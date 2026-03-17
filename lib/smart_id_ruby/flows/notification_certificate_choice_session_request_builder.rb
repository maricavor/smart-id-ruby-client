# frozen_string_literal: true

module SmartIdRuby
  module Flows
    # Builds notification certificate choice session requests.
    class NotificationCertificateChoiceSessionRequestBuilder < BaseBuilder
      NONCE_MAX_LENGTH = 30

      def initialize(connector)
        super(connector)
        @certificate_level = nil
        @nonce = nil
        @capabilities = nil
        @share_md_client_ip_address = nil
        @semantics_identifier = nil
      end

      def with_certificate_level(certificate_level)
        @certificate_level = certificate_level
        self
      end

      def with_nonce(nonce)
        @nonce = nonce
        self
      end

      def with_capabilities(*capabilities)
        @capabilities = normalize_capabilities(capabilities)
        self
      end

      def with_share_md_client_ip_address(share_md_client_ip_address)
        @share_md_client_ip_address = share_md_client_ip_address
        self
      end

      def with_semantics_identifier(semantics_identifier)
        @semantics_identifier = semantics_identifier
        self
      end

      def init_certificate_choice
        validate_request_parameters
        request = create_certificate_choice_request
        response = init_certificate_choice_session(request)
        validate_response_parameters(response)
        response
      end

      private

      def init_certificate_choice_session(request)
        if @semantics_identifier.nil?
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'semanticIdentifier' must be set"
        end

        connector.init_notification_certificate_choice(request, @semantics_identifier)
      end

      def validate_request_parameters
        if blank?(relying_party_uuid)
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'relyingPartyUUID' cannot be empty"
        end
        if blank?(relying_party_name)
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'relyingPartyName' cannot be empty"
        end
        if !@nonce.nil? && (@nonce.empty? || @nonce.length > NONCE_MAX_LENGTH)
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'nonce' length must be between 1 and 30 characters"
        end
      end

      def create_certificate_choice_request
        {
          relyingPartyUUID: relying_party_uuid,
          relyingPartyName: relying_party_name,
          certificateLevel: @certificate_level&.to_s,
          nonce: @nonce,
          capabilities: @capabilities,
          requestProperties: request_properties
        }.compact
      end

      def request_properties
        request_properties_for_share_md(@share_md_client_ip_address)
      end

      def validate_response_parameters(response)
        return unless blank?(fetch_value(response, :sessionID))

        raise SmartIdRuby::Errors::UnprocessableResponseError,
              "Notification-based certificate choice response field 'sessionID' is missing or empty"
      end
    end
  end
end
