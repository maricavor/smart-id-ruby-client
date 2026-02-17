# frozen_string_literal: true

module SmartId
  module Validation
    class DeviceLinkAuthenticationResponseValidator
      BASE64_FORMAT_PATTERN = /\A[a-zA-Z0-9+\/]+={0,2}\z/.freeze
      USER_CHALLENGE_PATTERN = /\A[a-zA-Z0-9\-_]{43}\z/.freeze
      MINIMUM_SERVER_RANDOM_LENGTH = 24
      CERTIFICATE_LEVEL_ORDER = {
        "ADVANCED" => 1,
        "QUALIFIED" => 2,
        "QSCD" => 3
      }.freeze
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

      def validate(session_status, authentication_session_request)
        status = normalize_status(session_status)
        validate_inputs(status, authentication_session_request)
        validate_complete_state(status)
        validate_result(status.result)
        validate_signature_protocol(status)
        validate_signature(status.signature)
        validate_certificate(status.cert, requested_certificate_level(authentication_session_request))
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

      def validate_inputs(session_status, authentication_session_request)
        if session_status.nil?
          raise SmartId::Errors::RequestSetupError, "Parameter 'sessionStatus' is not provided"
        end
        if authentication_session_request.nil?
          raise SmartId::Errors::RequestSetupError, "Parameter 'authenticationSessionRequest' is not provided"
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
            raise SmartId::Errors::SessionEndResultError.new(
              result.end_result,
              user_refused_interaction_message(result)
            )
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
        validate_user_challenge(signature.user_challenge)
        validate_non_empty(signature.flow_type, "signature.flowType")
        validate_non_empty(signature.signature_algorithm, "signature.signatureAlgorithm")
      end

      def validate_certificate(cert, requested_level)
        if cert.nil?
          raise SmartId::Errors::UnprocessableResponseError, "Authentication session status field 'cert' is missing"
        end
        validate_non_empty(cert.value, "cert.value")
        validate_non_empty(cert.certificate_level, "cert.certificateLevel")

        actual_level = cert.certificate_level.to_s.upcase
        required_level = requested_level.to_s.upcase
        unless CERTIFICATE_LEVEL_ORDER.key?(actual_level)
          raise SmartId::Errors::UnprocessableResponseError,
                "Authentication session status field 'cert.certificateLevel' has unsupported value"
        end
        return if CERTIFICATE_LEVEL_ORDER[actual_level] >= CERTIFICATE_LEVEL_ORDER.fetch(required_level, 2)

        raise SmartId::Errors::UnprocessableResponseError,
              "Authentication certificate level '#{actual_level}' is lower than requested level '#{required_level}'"
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

      def validate_user_challenge(value)
        validate_non_empty(value, "signature.userChallenge")
        return if USER_CHALLENGE_PATTERN.match?(value)

        raise SmartId::Errors::UnprocessableResponseError,
              "Authentication session status field 'signature.userChallenge' value does not match required pattern"
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

      def user_refused_interaction_message(result)
        interaction = result.details&.interaction
        if blank?(interaction)
          return "Details for refused interaction are missing"
        end

        case interaction
        when "displayTextAndPIN"
          "User pressed Cancel on PIN screen."
        when "confirmationMessage"
          "User cancelled on confirmationMessage screen"
        when "confirmationMessageAndVerificationCodeChoice"
          "User cancelled on confirmationMessageAndVerificationCodeChoice screen"
        else
          "Unexpected interaction type: #{interaction}"
        end
      end

      def fetch_request_value(payload, key)
        return nil unless payload.respond_to?(:[])

        payload[key] || payload[key.to_s]
      end

      def blank?(value)
        value.nil? || value.to_s.strip.empty?
      end
    end
  end
end
