# frozen_string_literal: true

module SmartIdRuby
  module Flows
    # Builds device link certificate choice session requests.
    class DeviceLinkCertificateChoiceSessionRequestBuilder < BaseBuilder
      INITIAL_CALLBACK_URL_PATTERN = %r{\Ahttps://[^|]+\z}
      NONCE_MAX_LENGTH = 30

      def initialize(connector)
        super(connector)
        @certificate_level = nil
        @nonce = nil
        @capabilities = nil
        @share_md_client_ip_address = nil
        @initial_callback_url = nil
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

      def with_initial_callback_url(initial_callback_url)
        @initial_callback_url = initial_callback_url
        self
      end

      def init_certificate_choice
        validate_request_parameters
        request = create_certificate_request
        response = connector.init_device_link_certificate_choice(request)
        validate_response_parameters(response)
        SmartIdRuby::Models::DeviceLinkSessionResponse.from_h(response)
      end

      private

      def validate_request_parameters
        if blank?(relying_party_uuid)
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'relyingPartyUUID' cannot be empty"
        end
        if blank?(relying_party_name)
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'relyingPartyName' cannot be empty"
        end
        if !@nonce.nil? && (@nonce.empty? || @nonce.length > NONCE_MAX_LENGTH)
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'nonce' must have length between 1 and 30 characters"
        end

        validate_initial_callback_url
      end

      def create_certificate_request
        {
          relyingPartyUUID: relying_party_uuid,
          relyingPartyName: relying_party_name,
          certificateLevel: @certificate_level&.to_s,
          nonce: @nonce,
          capabilities: @capabilities,
          requestProperties: request_properties,
          initialCallbackUrl: @initial_callback_url
        }.compact
      end

      def request_properties
        request_properties_for_share_md(@share_md_client_ip_address)
      end

      def validate_initial_callback_url
        return if blank?(@initial_callback_url)
        return if INITIAL_CALLBACK_URL_PATTERN.match?(@initial_callback_url)

        raise SmartIdRuby::Errors::RequestSetupError,
              "Value for 'initialCallbackUrl' must match pattern ^https://[^|]+$ and must not contain unencoded vertical bars"
      end

      def validate_response_parameters(response)
        if blank?(fetch_value(response, :sessionID))
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Device link certificate choice session initialisation response field 'sessionID' is missing or empty"
        end
        if blank?(fetch_value(response, :sessionToken))
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Device link certificate choice session initialisation response field 'sessionToken' is missing or empty"
        end
        if blank?(fetch_value(response, :sessionSecret))
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Device link certificate choice session initialisation response field 'sessionSecret' is missing or empty"
        end
        if blank?(fetch_value(response, :deviceLinkBase))
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Device link certificate choice session initialisation response field 'deviceLinkBase' is missing or empty"
        end
      end
    end
  end
end
