# frozen_string_literal: true

require "base64"
require "openssl"

module SmartIdRuby
  module Validation
    # Validates device-link authentication session status response and maps it to
    # a typed authentication identity model.
    class DeviceLinkAuthenticationResponseValidator
      BASE64_FORMAT_PATTERN = /\A[a-zA-Z0-9+\/]+={0,2}\z/.freeze
      USER_CHALLENGE_PATTERN = /\A[a-zA-Z0-9\-_]{43}\z/.freeze
      MINIMUM_SERVER_RANDOM_LENGTH = 24
      SUPPORTED_FLOW_TYPES = %w[QR Web2App App2App Notification].freeze
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
      def initialize(signature_value_validator: SignatureValueValidator.new,
                     signature_payload_builder: SignaturePayloadBuilder.new,
                     certificate_validator: AuthenticationCertificateValidator.new,
                     authentication_identity_mapper: AuthenticationIdentityMapper.new)
        @signature_value_validator = signature_value_validator
        @signature_payload_builder = signature_payload_builder
        @certificate_validator = certificate_validator
        @authentication_identity_mapper = authentication_identity_mapper
      end

      # Validates a completed device-link authentication session status.
      #
      # @param session_status [SmartIdRuby::Models::SessionStatus, Hash]
      #   Session status received from Smart-ID RP API. Hash values are mapped to
      #   {SmartIdRuby::Models::SessionStatus} before validation.
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
      # @return [SmartIdRuby::Models::AuthenticationIdentity]
      #
      # @raise [SmartIdRuby::Errors::RequestSetupError]
      #   If required input parameters are missing.
      # @raise [SmartIdRuby::Errors::SessionNotCompleteError]
      #   If session status state is not COMPLETE.
      # @raise [SmartIdRuby::Errors::SessionEndResultError]
      #   If session end result is not OK.
      # @raise [SmartIdRuby::Errors::UnprocessableResponseError]
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

        @authentication_identity_mapper.from(certificate)
      end

      private

      def normalize_status(session_status)
        return session_status if session_status.is_a?(SmartIdRuby::Models::SessionStatus)
        return SmartIdRuby::Models::SessionStatus.from_h(session_status) if session_status.is_a?(Hash)

        nil
      end

      def validate_inputs(session_status, authentication_session_request, schema_name)
        raise SmartIdRuby::Errors::RequestSetupError, "Parameter 'sessionStatus' is not provided" if session_status.nil?

        if authentication_session_request.nil?
          raise SmartIdRuby::Errors::RequestSetupError, "Parameter 'authenticationSessionRequest' is not provided"
        end
        return unless blank?(schema_name)

        raise SmartIdRuby::Errors::RequestSetupError, "Parameter 'schemaName' is not provided"
      end

      def validate_complete_state(session_status)
        return if session_status.complete?

        raise SmartIdRuby::Errors::SessionNotCompleteError,
              "Authentication session is not complete. Current state: '#{session_status.state}'"
      end

      def validate_result(result)
        if result.nil?
          raise SmartIdRuby::Errors::UnprocessableResponseError, "Authentication session status field 'result' is empty"
        end
        if blank?(result.end_result)
          raise SmartIdRuby::Errors::UnprocessableResponseError, "Authentication session status field 'result.endResult' is empty"
        end

        ErrorResultHandler.handle(result) if result.end_result != "OK"
        return unless blank?(result.document_number)

        raise SmartIdRuby::Errors::UnprocessableResponseError, "Authentication session status field 'result.documentNumber' is empty"
      end

      def validate_signature_protocol(session_status)
        if blank?(session_status.signature_protocol)
          raise SmartIdRuby::Errors::UnprocessableResponseError, "Authentication session status field 'signatureProtocol' is empty"
        end
        return if session_status.signature_protocol == "ACSP_V2"

        raise SmartIdRuby::Errors::UnprocessableResponseError,
              "Authentication session status field 'signatureProtocol' has unsupported value"
      end

      def validate_signature(signature)
        if signature.nil?
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature' is missing"
        end
        validate_base64_field(signature.value, "signature.value")
        validate_server_random(signature.server_random)
        validate_user_challenge_format(signature.user_challenge)
        validate_non_empty(signature.flow_type, "signature.flowType")
        unless SUPPORTED_FLOW_TYPES.include?(signature.flow_type)
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.flowType' has unsupported value"
        end
        validate_non_empty(signature.signature_algorithm, "signature.signatureAlgorithm")
        unless signature.signature_algorithm == SUPPORTED_SIGNATURE_ALGORITHM
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithm' has unsupported value"
        end
        validate_signature_algorithm_parameters(signature.signature_algorithm_parameters)
      end

      def validate_interaction_type(session_status)
        return unless blank?(session_status.interaction_type_used)

        raise SmartIdRuby::Errors::UnprocessableResponseError,
              "Authentication session status field 'interactionTypeUsed' is empty"
      end

      def validate_base64_field(value, field_name)
        validate_non_empty(value, field_name)
        return if BASE64_FORMAT_PATTERN.match?(value)

        raise SmartIdRuby::Errors::UnprocessableResponseError,
              "Authentication session status field '#{field_name}' does not have Base64-encoded value"
      end

      def validate_server_random(value)
        validate_non_empty(value, "signature.serverRandom")
        if value.length < MINIMUM_SERVER_RANDOM_LENGTH
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.serverRandom' value length is less than required"
        end
        validate_base64_field(value, "signature.serverRandom")
      end

      def validate_user_challenge_format(value)
        validate_non_empty(value, "signature.userChallenge")
        return if USER_CHALLENGE_PATTERN.match?(value)

        raise SmartIdRuby::Errors::UnprocessableResponseError,
              "Authentication session status field 'signature.userChallenge' value does not match required pattern"
      end

      def validate_user_challenge(user_challenge_verifier, signature)
        flow_type = signature.flow_type
        return unless %w[Web2App App2App].include?(flow_type)

        if blank?(user_challenge_verifier)
          raise SmartIdRuby::Errors::RequestSetupError,
                "Parameter 'userChallengeVerifier' must be provided for 'flowType' - #{flow_type}"
        end
        url_user_challenge = Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(user_challenge_verifier), padding: false)
        return if signature.user_challenge == url_user_challenge

        raise SmartIdRuby::Errors::UnprocessableResponseError,
              "Device link authentication 'signature.userChallenge' does not validate with 'userChallengeVerifier'"
      end

      def validate_signature_algorithm_parameters(signature_algorithm_parameters)
        if signature_algorithm_parameters.nil?
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters' is missing"
        end

        hash_algorithm = signature_algorithm_parameters.hash_algorithm
        if blank?(hash_algorithm)
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.hashAlgorithm' is empty"
        end
        unless SUPPORTED_HASH_ALGORITHM_OCTET_LENGTH.key?(hash_algorithm)
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.hashAlgorithm' has unsupported value"
        end

        mask_gen_algorithm = signature_algorithm_parameters.mask_gen_algorithm
        if mask_gen_algorithm.nil?
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm' is missing"
        end
        mask_gen_algorithm_value = fetch_hash_value(mask_gen_algorithm, :algorithm)
        if blank?(mask_gen_algorithm_value)
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.algorithm' is empty"
        end
        unless mask_gen_algorithm_value == SUPPORTED_MASK_GEN_ALGORITHM
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm' has unsupported value"
        end

        mask_gen_parameters = fetch_hash_value(mask_gen_algorithm, :parameters)
        if mask_gen_parameters.nil?
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters' is missing"
        end
        mask_hash_algorithm = fetch_hash_value(mask_gen_parameters, :hashAlgorithm)
        if blank?(mask_hash_algorithm)
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' is empty"
        end
        unless SUPPORTED_HASH_ALGORITHM_OCTET_LENGTH.key?(mask_hash_algorithm)
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' has unsupported value"
        end
        unless hash_algorithm == mask_hash_algorithm
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.hashAlgorithm' value does not match 'signature.signatureAlgorithmParameters.hashAlgorithm' value"
        end

        salt_length = signature_algorithm_parameters.salt_length
        if salt_length.nil?
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.saltLength' is empty"
        end
        unless salt_length == SUPPORTED_HASH_ALGORITHM_OCTET_LENGTH[hash_algorithm]
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.saltLength' has invalid value"
        end

        trailer_field = signature_algorithm_parameters.trailer_field
        if blank?(trailer_field)
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Authentication session status field 'signature.signatureAlgorithmParameters.trailerField' is empty"
        end
        return if trailer_field == SUPPORTED_TRAILER_FIELD

        raise SmartIdRuby::Errors::UnprocessableResponseError,
              "Authentication session status field 'signature.signatureAlgorithmParameters.trailerField' has unsupported value"
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

        raise SmartIdRuby::Errors::UnprocessableResponseError,
              "Authentication session status field '#{field_name}' is empty"
      end

      def requested_certificate_level(authentication_session_request)
        value = fetch_request_value(authentication_session_request, :certificateLevel)
        return "QUALIFIED" if blank?(value)

        value
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
