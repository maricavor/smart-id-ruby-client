# frozen_string_literal: true

require "base64"
require "openssl"

module SmartIdRuby
  module Validation
    # Validates device-link authentication session status response and maps it to
    # a typed authentication identity model.
    class DeviceLinkAuthenticationResponseValidator < BaseAuthenticationResponseValidator
      def initialize(signature_value_validator: SignatureValueValidator.new,
                     signature_payload_builder: SignaturePayloadBuilder.new,
                     certificate_validator: AuthenticationCertificateValidator.new,
                     authentication_identity_mapper: AuthenticationIdentityMapper.new)
        @signature_payload_builder = signature_payload_builder
        super(
          signature_value_validator: signature_value_validator,
          certificate_validator: certificate_validator,
          authentication_identity_mapper: authentication_identity_mapper
        )
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
      private

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

      def build_signature_payload(session_status, authentication_session_request, schema_name, brokered_rp_name)
        @signature_payload_builder.build(
          session_status: session_status,
          authentication_session_request: authentication_session_request,
          schema_name: schema_name,
          brokered_rp_name: brokered_rp_name
        )
      end
    end
  end
end
