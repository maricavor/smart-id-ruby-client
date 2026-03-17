# frozen_string_literal: true

require "base64"
require "openssl"

module SmartIdRuby
  module Flows
    # Builds notification signature session requests.
    class NotificationSignatureSessionRequestBuilder < BaseBuilder
      VERIFICATION_CODE_PATTERN = /\A[0-9]{4}\z/
      NONCE_MAX_LENGTH = 30
      DEFAULT_HASH_ALGORITHM = "SHA-512"
      SUPPORTED_VC_TYPE = "numeric4"

      def initialize(connector)
        super(connector)
        @document_number = nil
        @semantics_identifier = nil
        @certificate_level = nil
        @nonce = nil
        @capabilities = nil
        @interactions = nil
        @share_md_client_ip_address = nil
        @signature_algorithm = "rsassa-pss"
        @digest_input = nil
      end

      def with_document_number(document_number)
        @document_number = document_number
        self
      end

      def with_semantics_identifier(semantics_identifier)
        @semantics_identifier = semantics_identifier
        self
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

      def with_interactions(interactions)
        @interactions = interactions
        self
      end

      def with_share_md_client_ip_address(share_md_client_ip_address)
        @share_md_client_ip_address = share_md_client_ip_address
        self
      end

      def with_signature_algorithm(signature_algorithm)
        @signature_algorithm = signature_algorithm
        self
      end

      def with_signable_data(signable_data)
        if digest_input_kind == :signable_hash
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'digestInput' has already been set with SignableHash"
        end

        @digest_input = build_signable_data_digest_input(signable_data)
        self
      end

      def with_signable_hash(signable_hash)
        if digest_input_kind == :signable_data
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'digestInput' has already been set with SignableData"
        end

        @digest_input = build_signable_hash_digest_input(signable_hash)
        self
      end

      def init_signature_session
        validate_request_parameters
        request = create_signature_session_request
        response = init_session(request)
        validate_response_parameters(response)
        response
      end

      private

      def init_session(request)
        if @semantics_identifier && @document_number
          raise SmartIdRuby::Errors::RequestSetupError, "Only one of 'semanticsIdentifier' or 'documentNumber' may be set"
        end

        if @document_number
          connector.init_notification_signature_with_document(request, @document_number)
        elsif @semantics_identifier
          connector.init_notification_signature(request, @semantics_identifier)
        else
          raise SmartIdRuby::Errors::RequestSetupError, "Either 'documentNumber' or 'semanticsIdentifier' must be set"
        end
      end

      def create_signature_session_request
        {
          relyingPartyUUID: relying_party_uuid,
          relyingPartyName: relying_party_name,
          certificateLevel: @certificate_level&.to_s,
          signatureProtocol: "RAW_DIGEST_SIGNATURE",
          signatureProtocolParameters: {
            digest: @digest_input[:digest],
            signatureAlgorithm: @signature_algorithm.to_s,
            signatureAlgorithmParameters: {
              hashAlgorithm: @digest_input[:hash_algorithm].to_s
            }
          },
          nonce: @nonce,
          capabilities: @capabilities,
          interactions: encode_interactions(@interactions),
          requestProperties: request_properties
        }.compact
      end

      def validate_request_parameters
        if blank?(relying_party_uuid)
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'relyingPartyUUID' cannot be empty"
        end
        if blank?(relying_party_name)
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'relyingPartyName' cannot be empty"
        end
        if @signature_algorithm.nil?
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'signatureAlgorithm' must be set"
        end
        if @digest_input.nil?
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'digestInput' must be set with either SignableData or SignableHash"
        end

        validate_interactions
        validate_nonce
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

      def validate_nonce
        return if @nonce.nil?
        return if @nonce.length.between?(1, NONCE_MAX_LENGTH)

        raise SmartIdRuby::Errors::RequestSetupError, "Value for 'nonce' length must be between 1 and 30 characters"
      end

      def validate_response_parameters(response)
        if blank?(fetch_value(response, :sessionID))
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Notification-based signature response field 'sessionID' is missing or empty"
        end

        verification_code = fetch_value(response, :vc)
        if verification_code.nil?
          raise SmartIdRuby::Errors::UnprocessableResponseError, "Notification-based signature response field 'vc' is missing"
        end

        vc_type = fetch_value(verification_code, :type)
        if blank?(vc_type)
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Notification-based signature response field 'vc.type' is missing or empty"
        end
        unless vc_type == SUPPORTED_VC_TYPE
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Notification-based signature response field 'vc.type' contains unsupported value"
        end

        vc_value = fetch_value(verification_code, :value)
        if blank?(vc_value)
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Notification-based signature response field 'vc.value' is missing or empty"
        end
        return if VERIFICATION_CODE_PATTERN.match?(vc_value.to_s)

        raise SmartIdRuby::Errors::UnprocessableResponseError,
              "Notification-based signature response field 'vc.value' does not match the required pattern"
      end

      def request_properties
        request_properties_for_share_md(@share_md_client_ip_address)
      end

      def build_signable_data_digest_input(signable_data)
        return nil if signable_data.nil?

        data_to_sign, hash_algorithm = extract_signable_data(signable_data)
        data = normalize_binary_input(data_to_sign)
        algorithm_name = normalize_hash_algorithm(hash_algorithm)

        digest = OpenSSL::Digest.new(openssl_algorithm_name(algorithm_name)).digest(data)
        { kind: :signable_data, digest: Base64.strict_encode64(digest), hash_algorithm: algorithm_name }
      end

      def build_signable_hash_digest_input(signable_hash)
        return nil if signable_hash.nil?

        hash_to_sign, hash_algorithm = extract_signable_hash(signable_hash)
        hash_bytes = normalize_binary_input(hash_to_sign)
        algorithm_name = normalize_hash_algorithm(hash_algorithm)

        { kind: :signable_hash, digest: Base64.strict_encode64(hash_bytes), hash_algorithm: algorithm_name }
      end

      def extract_signable_data(input)
        if input.respond_to?(:to_h)
          normalized = input.to_h.transform_keys(&:to_sym)
          [normalized[:data_to_sign] || normalized[:data], normalized[:hash_algorithm]]
        elsif input.respond_to?(:data_to_sign)
          [input.data_to_sign, input.respond_to?(:hash_algorithm) ? input.hash_algorithm : nil]
        else
          [input, nil]
        end
      end

      def extract_signable_hash(input)
        if input.respond_to?(:to_h)
          normalized = input.to_h.transform_keys(&:to_sym)
          [normalized[:hash_to_sign] || normalized[:hash] || normalized[:digest], normalized[:hash_algorithm]]
        elsif input.respond_to?(:hash_to_sign)
          [input.hash_to_sign, input.respond_to?(:hash_algorithm) ? input.hash_algorithm : nil]
        else
          [input, nil]
        end
      end

      def normalize_binary_input(input)
        data = input.is_a?(String) ? input.dup : input
        data = data.pack("C*") if data.is_a?(Array) && data.all? { |value| value.is_a?(Integer) && value.between?(0, 255) }
        if data.nil? || data.to_s.bytesize.zero?
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'digestInput' must be set with either SignableData or SignableHash"
        end

        data
      end

      def normalize_hash_algorithm(hash_algorithm)
        value = hash_algorithm&.to_s
        return DEFAULT_HASH_ALGORITHM if blank?(value)

        value
      end

      def openssl_algorithm_name(hash_algorithm)
        hash_algorithm.to_s.delete("-")
      end

      def digest_input_kind
        @digest_input && @digest_input[:kind]
      end
    end
  end
end
