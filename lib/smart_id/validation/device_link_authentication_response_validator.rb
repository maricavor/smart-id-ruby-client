# frozen_string_literal: true

require "base64"
require "openssl"

module SmartId
  module Validation
    # Validates device-link authentication session status response and maps it to
    # a typed authentication response model.
    class DeviceLinkAuthenticationResponseValidator
      BASE64_FORMAT_PATTERN = /\A[a-zA-Z0-9+\/]+={0,2}\z/.freeze
      USER_CHALLENGE_PATTERN = /\A[a-zA-Z0-9\-_]{43}\z/.freeze
      MINIMUM_SERVER_RANDOM_LENGTH = 24
      SUPPORTED_FLOW_TYPES = ["QR", "Web2App", "App2App", "Notification"].freeze
      SUPPORTED_SIGNATURE_ALGORITHM = "rsassa-pss"
      SUPPORTED_HASH_ALGORITHM_OCTET_LENGTH = {
        "SHA-256" => 32,
        "SHA-384" => 48,
        "SHA-512" => 64,
        "SHA3-256" => 32,
        "SHA3-384" => 48,
        "SHA3-512" => 64
      }.freeze
      SUPPORTED_MASK_GEN_ALGORITHM = "id-mgf1"
      SUPPORTED_TRAILER_FIELD = "0xbc"
      END_RESULT_MESSAGES = {
        "USER_REFUSED" => "User pressed cancel in app",
        "TIMEOUT" => "Session timed out without getting any response from user",
        "DOCUMENT_UNUSABLE" => "Document is unusable. User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason.",
        "WRONG_VC" => "User selected wrong verification code",
        "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP" => "User app version does not support any of the provided interactions.",
        "USER_REFUSED_CERT_CHOICE" => "User has multiple accounts and pressed Cancel on device choice screen on any device.",
        "PROTOCOL_FAILURE" => "A logical error occurred in the signing protocol.",
        "EXPECTED_LINKED_SESSION" => "The app received a different transaction while waiting for the linked session that follows the device-link based cert-choice session",
        "SERVER_ERROR" => "Process was terminated due to server-side technical error",
        "ACCOUNT_UNUSABLE" => "The account is currently unusable"
      }.freeze

      def initialize(signature_value_validator: SignatureValueValidator.new,
                     signature_payload_builder: SignaturePayloadBuilder.new,
                     certificate_validator: AuthenticationCertificateValidator.new)
        @signature_value_validator = signature_value_validator
        @signature_payload_builder = signature_payload_builder
        @certificate_validator = certificate_validator
      end

      # Validates a completed device-link authentication session status.
      #
      # @param session_status [SmartId::Models::SessionStatus, Hash]
      #   Session status received from Smart-ID RP API. Hash values are mapped to
      #   {SmartId::Models::SessionStatus} before validation.
      # @param authentication_session_request [Hash]
      #   Request payload used for initializing the device-link authentication
      #   session. Used to validate requested certificate level.
      # @param user_challenge_verifier [String, nil]
      #   Callback URL verifier value used in same-device flows. Required only
      #   when flow type is Web2App or App2App.
      # @param schema_name [String, nil]
      #   RP schema name used in device link generation. Must be provided.
      # @param _brokered_rp_name [String, nil]
      #   The brokered RP name, used in the device link.
      #
      # @return [SmartId::Models::AuthenticationResponse]
      #
      # @raise [SmartId::Errors::RequestSetupError]
      #   If required input parameters are missing.
      # @raise [SmartId::Errors::SessionNotCompleteError]
      #   If session status state is not COMPLETE.
      # @raise [SmartId::Errors::SessionEndResultError]
      #   If session end result is not OK.
      # @raise [SmartId::Errors::UnprocessableResponseError]
      #   If response contains invalid or unsupported values.
      def validate(session_status, authentication_session_request, user_challenge_verifier = nil, schema_name = nil, brokered_rp_name = nil)
        status = normalize_status(session_status)
        validate_inputs(status, authentication_session_request, schema_name)
        validate_complete_state(status)
        validate_result(status.result)
        validate_signature_protocol(status)
        validate_signature(status.signature)
        validate_user_challenge(user_challenge_verifier, status.signature)
        certificate = @certificate_validator.validate(
          cert: status.cert,
          requested_level: requested_certificate_level(authentication_session_request)
        )
        validate_signature_value(status, authentication_session_request, schema_name, brokered_rp_name, certificate)
        validate_interaction_type(status)

        SmartId::Models::AuthenticationResponse.new(
          end_result: status.result.end_result,
          document_number: status.result.document_number,
          signature_value: status.signature.value,
          server_random: status.signature.server_random,
          user_challenge: status.signature.user_challenge,
          flow_type: status.signature.flow_type,
          signature_algorithm: status.signature.signature_algorithm,
          certificate_value: status.cert.value,
          certificate_level: status.cert.certificate_level,
          interaction_type_used: status.interaction_type_used,
          device_ip_address: status.device_ip_address
        )
      end

      private

      def normalize_status(session_status)
        return session_status if session_status.is_a?(SmartId::Models::SessionStatus)
        return SmartId::Models::SessionStatus.from_h(session_status) if session_status.is_a?(Hash)

        nil
      end

      def validate_inputs(session_status, authentication_session_request, schema_name)
        if session_status.nil?
          raise SmartId::Errors::RequestSetupError, "Parameter 'sessionStatus' is not provided"
        end
        if authentication_session_request.nil?
          raise SmartId::Errors::RequestSetupError, "Parameter 'authenticationSessionRequest' is not provided"
        end
        if blank?(schema_name)
          raise SmartId::Errors::RequestSetupError, "Parameter 'schemaName' is not provided"
        end
      end

      def validate_complete_state(session_status)
        return if session_status.complete?

        raise SmartId::Errors::SessionNotCompleteError,
              "Authentication session is not complete. Current state: '#{session_status.state}'"
      end

      def validate_result(result)
        if result.nil?
          raise SmartId::Errors::UnprocessableResponseError, "Authentication session status field 'result' is empty"
        end
        if blank?(result.end_result)
          raise SmartId::Errors::UnprocessableResponseError, "Authentication session status field 'result.endResult' is empty"
        end
        if result.end_result != "OK"
          if result.end_result == "USER_REFUSED_INTERACTION"
            raise_user_refused_interaction_error(result)
          end

          raise SmartId::Errors::SessionEndResultError.new(
            result.end_result,
            END_RESULT_MESSAGES[result.end_result] || "Unexpected session result: #{result.end_result}"
          )
        end
        if blank?(result.document_number)
          raise SmartId::Errors::UnprocessableResponseError, "Authentication session status field 'result.documentNumber' is empty"
        end
      end

      def validate_signature_protocol(session_status)
        if blank?(session_status.signature_protocol)
          raise SmartId::Errors::UnprocessableResponseError, "Authentication session status field 'signatureProtocol' is empty"
        end
        return if session_status.signature_protocol == "ACSP_V2"

        raise SmartId::Errors::UnprocessableResponseError,
              "Authentication session status field 'signatureProtocol' has unsupported value"
      end

      def validate_signature(signature)
        if signature.nil?
          raise SmartId::Errors::UnprocessableResponseError, "Authentication session status field 'signature' is missing"
        end
        validate_base64_field(signature.value, "signature.value")
        validate_server_random(signature.server_random)
        validate_user_challenge_format(signature.user_challenge)
        validate_non_empty(signature.flow_type, "signature.flowType")
        unless SUPPORTED_FLOW_TYPES.include?(signature.flow_type)
          raise SmartId::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.flowType' has unsupported value"
        end
        validate_non_empty(signature.signature_algorithm, "signature.signatureAlgorithm")
        unless signature.signature_algorithm == SUPPORTED_SIGNATURE_ALGORITHM
          raise SmartId::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithm' has unsupported value"
        end
        validate_signature_algorithm_parameters(signature.signature_algorithm_parameters)
      end

      def validate_interaction_type(session_status)
        return unless blank?(session_status.interaction_type_used)

        raise SmartId::Errors::UnprocessableResponseError,
              "Authentication session status field 'interactionTypeUsed' is empty"
      end

      def validate_base64_field(value, field_name)
        validate_non_empty(value, field_name)
        return if BASE64_FORMAT_PATTERN.match?(value)

        raise SmartId::Errors::UnprocessableResponseError,
              "Authentication session status field '#{field_name}' does not have Base64-encoded value"
      end

      def validate_server_random(value)
        validate_non_empty(value, "signature.serverRandom")
        if value.length < MINIMUM_SERVER_RANDOM_LENGTH
          raise SmartId::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.serverRandom' value length is less than required"
        end
        validate_base64_field(value, "signature.serverRandom")
      end

      def validate_user_challenge_format(value)
        validate_non_empty(value, "signature.userChallenge")
        return if USER_CHALLENGE_PATTERN.match?(value)

        raise SmartId::Errors::UnprocessableResponseError,
              "Authentication session status field 'signature.userChallenge' value does not match required pattern"
      end

      def validate_user_challenge(user_challenge_verifier, signature)
        flow_type = signature.flow_type
        return unless flow_type == "Web2App" || flow_type == "App2App"

        if blank?(user_challenge_verifier)
          raise SmartId::Errors::RequestSetupError,
                "Parameter 'userChallengeVerifier' must be provided for 'flowType' - #{flow_type}"
        end
        url_user_challenge = Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(user_challenge_verifier), padding: false)
        return if signature.user_challenge == url_user_challenge

        raise SmartId::Errors::UnprocessableResponseError,
              "Device link authentication 'signature.userChallenge' does not validate with 'userChallengeVerifier'"
      end

      def validate_signature_algorithm_parameters(signature_algorithm_parameters)
        if signature_algorithm_parameters.nil?
          raise SmartId::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters' is missing"
        end

        hash_algorithm = signature_algorithm_parameters.hash_algorithm
        if blank?(hash_algorithm)
          raise SmartId::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.hashAlgorithm' is empty"
        end
        unless SUPPORTED_HASH_ALGORITHM_OCTET_LENGTH.key?(hash_algorithm)
          raise SmartId::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.hashAlgorithm' has unsupported value"
        end

        mask_gen_algorithm = signature_algorithm_parameters.mask_gen_algorithm
        if mask_gen_algorithm.nil?
          raise SmartId::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm' is missing"
        end
        mask_gen_algorithm_value = fetch_hash_value(mask_gen_algorithm, :algorithm)
        if blank?(mask_gen_algorithm_value)
          raise SmartId::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.algorithm' is empty"
        end
        unless mask_gen_algorithm_value == SUPPORTED_MASK_GEN_ALGORITHM
          raise SmartId::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm' has unsupported value"
        end

        mask_gen_parameters = fetch_hash_value(mask_gen_algorithm, :parameters)
        if mask_gen_parameters.nil?
          raise SmartId::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters' is missing"
        end
        mask_hash_algorithm = fetch_hash_value(mask_gen_parameters, :hashAlgorithm)
        if blank?(mask_hash_algorithm)
          raise SmartId::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' is empty"
        end
        unless SUPPORTED_HASH_ALGORITHM_OCTET_LENGTH.key?(mask_hash_algorithm)
          raise SmartId::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' has unsupported value"
        end
        unless hash_algorithm == mask_hash_algorithm
          raise SmartId::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.hashAlgorithm' value does not match 'signature.signatureAlgorithmParameters.hashAlgorithm' value"
        end

        salt_length = signature_algorithm_parameters.salt_length
        if salt_length.nil?
          raise SmartId::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.saltLength' is empty"
        end
        unless salt_length == SUPPORTED_HASH_ALGORITHM_OCTET_LENGTH[hash_algorithm]
          raise SmartId::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.saltLength' has invalid value"
        end

        trailer_field = signature_algorithm_parameters.trailer_field
        if blank?(trailer_field)
          raise SmartId::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.trailerField' is empty"
        end
        unless trailer_field == SUPPORTED_TRAILER_FIELD
          raise SmartId::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.trailerField' has unsupported value"
        end
      end

      def validate_signature_value(session_status, authentication_session_request, schema_name, brokered_rp_name, certificate)
        payload = @signature_payload_builder.build(
          session_status: session_status,
          authentication_session_request: authentication_session_request,
          schema_name: schema_name,
          brokered_rp_name: brokered_rp_name
        )
        @signature_value_validator.validate(
          signature_value: session_status.signature.value,
          payload: payload,
          certificate: certificate,
          signature_algorithm_parameters: session_status.signature.signature_algorithm_parameters
        )
      end

      def validate_non_empty(value, field_name)
        return unless blank?(value)

        raise SmartId::Errors::UnprocessableResponseError,
              "Authentication session status field '#{field_name}' is empty"
      end

      def requested_certificate_level(authentication_session_request)
        value = fetch_request_value(authentication_session_request, :certificateLevel)
        return "QUALIFIED" if blank?(value)

        value
      end

      def raise_user_refused_interaction_error(result)
        interaction = result.details&.interaction
        if blank?(interaction)
          raise SmartId::Errors::UnprocessableResponseError, "Details for refused interaction are missing"
        end

        case interaction
        when "displayTextAndPIN"
          raise SmartId::Errors::UserRefusedDisplayTextAndPinError
        when "confirmationMessage"
          raise SmartId::Errors::UserRefusedConfirmationMessageError
        when "confirmationMessageAndVerificationCodeChoice"
          raise SmartId::Errors::UserRefusedConfirmationMessageWithVerificationChoiceError
        else
          raise SmartId::Errors::UnprocessableResponseError, "Unexpected interaction type: #{interaction}"
        end
      end

      def fetch_request_value(payload, key)
        return nil unless payload.respond_to?(:[])

        payload[key] || payload[key.to_s]
      end

      def fetch_hash_value(payload, key)
        return nil unless payload.respond_to?(:[])

        payload[key] || payload[key.to_s]
      end

      def blank?(value)
        value.nil? || value.to_s.strip.empty?
      end
    end
  end
end
