# frozen_string_literal: true

require "base64"

module SmartIdRuby
  module Flows
    # Builds notification authentication session requests.
    class NotificationAuthenticationSessionRequestBuilder < BaseBuilder
      RP_CHALLENGE_MIN_LENGTH = 44
      RP_CHALLENGE_MAX_LENGTH = 88

      attr_reader :notification_authentication_session_request

      def initialize(connector)
        super(connector)
        @certificate_level = nil
        @signature_algorithm = "rsassa-pss"
        @hash_algorithm = "SHA3-512"
        @interactions = nil
        @share_md_client_ip_address = nil
        @capabilities = nil
        @semantics_identifier = nil
        @document_number = nil
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
        @capabilities = normalize_capabilities(capabilities)
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

      def init_authentication_session
        validate_request_parameters
        request = create_authentication_request
        response = init_session(request)
        validate_response_parameters(response)
        @notification_authentication_session_request = request
        response
      end

      def authentication_session_request
        if notification_authentication_session_request.nil?
          raise SmartIdRuby::Errors::RequestSetupError, "Notification-based authentication session has not been initialized yet"
        end

        notification_authentication_session_request
      end

      private

      def init_session(request)
        if @semantics_identifier && @document_number
          raise SmartIdRuby::Errors::RequestSetupError, "Only one of 'semanticsIdentifier' or 'documentNumber' may be set"
        end

        if @semantics_identifier
          connector.init_notification_authentication(request, @semantics_identifier)
        elsif @document_number
          connector.init_notification_authentication_with_document(request, @document_number)
        else
          raise SmartIdRuby::Errors::RequestSetupError, "Either 'documentNumber' or 'semanticsIdentifier' must be set"
        end
      end

      def validate_request_parameters
        if blank?(relying_party_uuid)
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'relyingPartyUUID' cannot be empty"
        end
        if blank?(relying_party_name)
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'relyingPartyName' cannot be empty"
        end

        validate_signature_parameters
        validate_interactions
      end

      def validate_signature_parameters
        if blank?(@rp_challenge)
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'rpChallenge' cannot be empty"
        end

        begin
          Base64.strict_decode64(@rp_challenge)
        rescue ArgumentError
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'rpChallenge' must be Base64-encoded string"
        end

        unless @rp_challenge.length.between?(RP_CHALLENGE_MIN_LENGTH, RP_CHALLENGE_MAX_LENGTH)
          raise SmartIdRuby::Errors::RequestSetupError,
                "Value for 'rpChallenge' must have length between #{RP_CHALLENGE_MIN_LENGTH} and #{RP_CHALLENGE_MAX_LENGTH} characters"
        end
        if @signature_algorithm.nil?
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'signatureAlgorithm' must be set"
        end
        if @hash_algorithm.nil?
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'hashAlgorithm' must be set"
        end
      end

      def validate_interactions
        normalized_interactions = normalize_interactions(@interactions)
        if normalized_interactions.empty?
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'interactions' cannot be empty"
        end

        interaction_types = normalized_interactions.map { |interaction| interaction[:type] }
        if interaction_types.uniq.length != interaction_types.length
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'interactions' cannot contain duplicate types"
        end
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
          vcType: "numeric4"
        }.compact
      end

      def request_properties
        request_properties_for_share_md(@share_md_client_ip_address)
      end

      def validate_response_parameters(response)
        return unless blank?(fetch_value(response, :sessionID))

        raise SmartIdRuby::Errors::UnprocessableResponseError,
              "Notification-based authentication session initialisation response field 'sessionID' is missing or empty"
      end
    end
  end
end
