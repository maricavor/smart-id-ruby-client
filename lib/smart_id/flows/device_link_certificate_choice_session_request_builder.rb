# frozen_string_literal: true

module SmartId
  module Flows
    class DeviceLinkCertificateChoiceSessionRequestBuilder < BaseBuilder
      INITIAL_CALLBACK_URL_PATTERN = %r{\Ahttps://[^|]+\z}.freeze
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
        @capabilities = capabilities.flatten.compact.map(&:to_s).map(&:strip).reject(&:empty?).uniq
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
        response
      end

      private

      def validate_request_parameters
        if blank?(relying_party_uuid)
          raise SmartId::Errors::RequestSetupError, "Value for 'relyingPartyUUID' cannot be empty"
        end
        if blank?(relying_party_name)
          raise SmartId::Errors::RequestSetupError, "Value for 'relyingPartyName' cannot be empty"
        end
        if !@nonce.nil? && (@nonce.empty? || @nonce.length > NONCE_MAX_LENGTH)
          raise SmartId::Errors::RequestSetupError, "Value for 'nonce' must have length between 1 and 30 characters"
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
        return nil if @share_md_client_ip_address.nil?

        { shareMdClientIpAddress: @share_md_client_ip_address }
      end

      def validate_initial_callback_url
        return if blank?(@initial_callback_url)
        return if INITIAL_CALLBACK_URL_PATTERN.match?(@initial_callback_url)

        raise SmartId::Errors::RequestSetupError,
              "Value for 'initialCallbackUrl' must match pattern ^https://[^|]+$ and must not contain unencoded vertical bars"
      end

      def validate_response_parameters(response)
        if blank?(fetch_value(response, :sessionID))
          raise SmartId::Errors::UnprocessableResponseError,
                "Device link certificate choice session initialisation response field 'sessionID' is missing or empty"
        end
        if blank?(fetch_value(response, :sessionToken))
          raise SmartId::Errors::UnprocessableResponseError,
                "Device link certificate choice session initialisation response field 'sessionToken' is missing or empty"
        end
        if blank?(fetch_value(response, :sessionSecret))
          raise SmartId::Errors::UnprocessableResponseError,
                "Device link certificate choice session initialisation response field 'sessionSecret' is missing or empty"
        end
        if blank?(fetch_value(response, :deviceLinkBase))
          raise SmartId::Errors::UnprocessableResponseError,
                "Device link certificate choice session initialisation response field 'deviceLinkBase' is missing or empty"
        end
      end

      def fetch_value(container, key)
        return nil if container.nil?

        key_str = key.to_s
        snake_key = underscore_key(key_str)
        candidates = [key, key_str, snake_key.to_sym, snake_key].uniq

        if container.respond_to?(:[])
          candidates.each do |candidate|
            value = container[candidate]
            return value unless value.nil?
          end
        end

        candidates.each do |candidate|
          method_name = candidate.is_a?(Symbol) ? candidate : candidate.to_s
          return container.public_send(method_name) if container.respond_to?(method_name)
        end

        nil
      end

      def underscore_key(value)
        value.to_s.gsub(/([A-Z])/, "_\\1").downcase.sub(/\A_/, "")
      end

      def blank?(value)
        value.nil? || value.to_s.strip.empty?
      end
    end
  end
end
