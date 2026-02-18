# frozen_string_literal: true

require "base64"

module SmartId
  module Flows
    class DeviceLinkAuthenticationSessionRequestBuilder < BaseBuilder
      INITIAL_CALLBACK_URL_PATTERN = %r{\Ahttps://[^|]+\z}.freeze
      RP_CHALLENGE_MIN_LENGTH = 44
      RP_CHALLENGE_MAX_LENGTH = 88

      attr_reader :authentication_session_request

      def initialize(connector)
        super(connector)
        @certificate_level = "QUALIFIED"
        @signature_algorithm = "rsassa-pss"
        @hash_algorithm = "SHA3-512"
        @interactions = nil
        @share_md_client_ip_address = nil
        @capabilities = nil
        @semantics_identifier = nil
        @document_number = nil
        @initial_callback_url = nil
        @rp_challenge = nil
      end

      def with_certificate_level(certificate_level)
        @certificate_level = certificate_level
        self
      end

      def with_rp_challenge(rp_challenge)
        @rp_challenge = rp_challenge
        self
      end

      def with_signature_algorithm(signature_algorithm)
        @signature_algorithm = signature_algorithm
        self
      end

      def with_hash_algorithm(hash_algorithm)
        @hash_algorithm = hash_algorithm
        self
      end

      def with_interactions(interactions)
        @interactions = interactions
        self
      end

      def with_share_md_client_ip_address(share_md_client_ip_address)
        @share_md_client_ip_address = share_md_client_ip_address
        self
      end

      def with_capabilities(*capabilities)
        @capabilities = normalize_capabilities(capabilities, strip: false, reject_empty: false)
        self
      end

      def with_semantics_identifier(semantics_identifier)
        @semantics_identifier = semantics_identifier
        self
      end

      def with_document_number(document_number)
        @document_number = document_number
        self
      end

      def with_initial_callback_url(initial_callback_url)
        @initial_callback_url = initial_callback_url
        self
      end

      def init_authentication_session
        validate_request_parameters
        request = create_authentication_request
        response = init_session(request)
        validate_response_parameters(response)
        @authentication_session_request = request
        response
      end

      def get_authentication_session_request
        if authentication_session_request.nil?
          raise SmartId::Errors::RequestSetupError, "Device link authentication session has not been initialized yet"
        end

        authentication_session_request
      end

      private

      def init_session(request)
        if @semantics_identifier && @document_number
          raise SmartId::Errors::RequestSetupError, "Only one of 'semanticsIdentifier' or 'documentNumber' may be set"
        end

        if @semantics_identifier
          connector.init_device_link_authentication(request, @semantics_identifier)
        elsif @document_number
          connector.init_device_link_authentication_with_document(request, @document_number)
        else
          connector.init_anonymous_device_link_authentication(request)
        end
      end

      def validate_request_parameters
        if blank?(relying_party_uuid)
          raise SmartId::Errors::RequestSetupError, "Value for 'relyingPartyUUID' cannot be empty"
        end
        if blank?(relying_party_name)
          raise SmartId::Errors::RequestSetupError, "Value for 'relyingPartyName' cannot be empty"
        end

        validate_signature_parameters
        validate_interactions
        validate_initial_callback_url
      end

      def validate_signature_parameters
        if blank?(@rp_challenge)
          raise SmartId::Errors::RequestSetupError, "Value for 'rpChallenge' cannot be empty"
        end
        begin
          Base64.strict_decode64(@rp_challenge)
        rescue ArgumentError
          raise SmartId::Errors::RequestSetupError, "Value for 'rpChallenge' must be Base64-encoded string"
        end

        unless @rp_challenge.length.between?(RP_CHALLENGE_MIN_LENGTH, RP_CHALLENGE_MAX_LENGTH)
          raise SmartId::Errors::RequestSetupError,
                "Value for 'rpChallenge' must have length between #{RP_CHALLENGE_MIN_LENGTH} and #{RP_CHALLENGE_MAX_LENGTH} characters"
        end
        if @signature_algorithm.nil?
          raise SmartId::Errors::RequestSetupError, "Value for 'signatureAlgorithm' must be set"
        end
        if @hash_algorithm.nil?
          raise SmartId::Errors::RequestSetupError, "Value for 'hashAlgorithm' must be set"
        end
      end

      def validate_interactions
        if @interactions.nil? || @interactions.empty?
          raise SmartId::Errors::RequestSetupError, "Value for 'interactions' cannot be empty"
        end

        interaction_types = @interactions.map { |interaction| interaction_type(interaction) }
        if interaction_types.any?(&:nil?)
          raise SmartId::Errors::RequestSetupError, "Each interaction must include a 'type' value"
        end
        if interaction_types.uniq.length != @interactions.length
          raise SmartId::Errors::RequestSetupError, "Value for 'interactions' cannot contain duplicate types"
        end
      end

      def validate_initial_callback_url
        return if blank?(@initial_callback_url)
        return if INITIAL_CALLBACK_URL_PATTERN.match?(@initial_callback_url)

        raise SmartId::Errors::RequestSetupError,
              "Value for 'initialCallbackUrl' must match pattern ^https://[^|]+$ and must not contain unencoded vertical bars"
      end

      def create_authentication_request
        {
          relyingPartyUUID: relying_party_uuid,
          relyingPartyName: relying_party_name,
          certificateLevel: @certificate_level&.to_s,
          signatureProtocol: "ACSP_V2",
          signatureProtocolParameters: {
            rpChallenge: @rp_challenge,
            signatureAlgorithm: @signature_algorithm.to_s,
            signatureAlgorithmParameters: {
              hashAlgorithm: @hash_algorithm.to_s
            }
          },
          interactions: encode_interactions(@interactions),
          requestProperties: request_properties,
          capabilities: @capabilities,
          initialCallbackUrl: @initial_callback_url
        }.compact
      end

      def request_properties
        request_properties_for_share_md(@share_md_client_ip_address)
      end

      def validate_response_parameters(response)
        if blank?(fetch_value(response, :sessionID))
          raise SmartId::Errors::UnprocessableResponseError,
                "Device link authentication session initialisation response field 'sessionID' is missing or empty"
        end
        if blank?(fetch_value(response, :sessionToken))
          raise SmartId::Errors::UnprocessableResponseError,
                "Device link authentication session initialisation response field 'sessionToken' is missing or empty"
        end
        if blank?(fetch_value(response, :sessionSecret))
          raise SmartId::Errors::UnprocessableResponseError,
                "Device link authentication session initialisation response field 'sessionSecret' is missing or empty"
        end
        if blank?(fetch_value(response, :deviceLinkBase))
          raise SmartId::Errors::UnprocessableResponseError,
                "Device link authentication session initialisation response field 'deviceLinkBase' is missing or empty"
        end
      end

      def interaction_type(interaction)
        normalize_interaction(interaction)[:type]
      end
    end
  end
end
