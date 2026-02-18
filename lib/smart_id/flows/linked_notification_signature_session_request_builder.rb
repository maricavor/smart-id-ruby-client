# frozen_string_literal: true

require "base64"
require "openssl"

module SmartId
  module Flows
    class LinkedNotificationSignatureSessionRequestBuilder < BaseBuilder
      NONCE_MAX_LENGTH = 30
      DEFAULT_HASH_ALGORITHM = "SHA-512"

      def initialize(connector)
        super(connector)
        @document_number = nil
        @digest_input = nil
        @signature_algorithm = "rsassa-pss"
        @linked_session_id = nil
        @interactions = nil
        @certificate_level = nil
        @nonce = nil
        @share_md_client_ip_address = nil
        @capabilities = nil
      end

      def with_document_number(document_number)
        @document_number = document_number
        self
      end

      def with_certificate_level(certificate_level)
        @certificate_level = certificate_level
        self
      end

      def with_signable_data(signable_data)
        if digest_input_kind == :signable_hash
          raise SmartId::Errors::RequestSetupError, "Value for 'digestInput' has been already set with SignableHash"
        end

        @digest_input = build_signable_data_digest_input(signable_data)
        self
      end

      def with_signable_hash(signable_hash)
        if digest_input_kind == :signable_data
          raise SmartId::Errors::RequestSetupError, "Value for 'digestInput' has been already set with SignableData"
        end

        @digest_input = build_signable_hash_digest_input(signable_hash)
        self
      end

      def with_signature_algorithm(signature_algorithm)
        @signature_algorithm = signature_algorithm
        self
      end

      def with_linked_session_id(linked_session_id)
        @linked_session_id = linked_session_id
        self
      end

      def with_nonce(nonce)
        @nonce = nonce
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
        @capabilities = capabilities.flatten.compact.map(&:to_s).map(&:strip).reject(&:empty?).uniq
        self
      end

      def init_signature_session
        validate_request_parameters
        request = create_session_request
        response = connector.init_linked_notification_signature(request, @document_number)
        validate_response(response)
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
        if blank?(@document_number)
          raise SmartId::Errors::RequestSetupError, "Value for 'documentNumber' cannot be empty"
        end
        if @digest_input.nil?
          raise SmartId::Errors::RequestSetupError, "Value for 'digestInput' must be set with SignableData or with SignableHash"
        end
        if @signature_algorithm.nil?
          raise SmartId::Errors::RequestSetupError, "Value for 'signatureAlgorithm' must be set"
        end
        if blank?(@linked_session_id)
          raise SmartId::Errors::RequestSetupError, "Value for 'linkedSessionID' cannot be empty"
        end
        if !@nonce.nil? && (@nonce.empty? || @nonce.length > NONCE_MAX_LENGTH)
          raise SmartId::Errors::RequestSetupError, "Value for 'nonce' must be 1-30 characters long"
        end

        validate_interactions
      end

      def validate_interactions
        normalized_interactions = normalize_interactions(@interactions)
        if normalized_interactions.empty?
          raise SmartId::Errors::RequestSetupError, "Value for 'interactions' cannot be empty"
        end

        interaction_types = normalized_interactions.map { |interaction| interaction[:type] }
        if interaction_types.uniq.length != interaction_types.length
          raise SmartId::Errors::RequestSetupError, "Value for 'interactions' cannot contain duplicate types"
        end
      end

      def create_session_request
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
          linkedSessionID: @linked_session_id,
          nonce: @nonce,
          interactions: encode_interactions(@interactions),
          requestProperties: request_properties,
          capabilities: @capabilities
        }.compact
      end

      def request_properties
        return nil if @share_md_client_ip_address.nil?

        { shareMdClientIpAddress: @share_md_client_ip_address }
      end

      def validate_response(response)
        if blank?(fetch_value(response, :sessionID))
          raise SmartId::Errors::UnprocessableResponseError,
                "Linked notification-base signature session response field 'sessionID' is missing or empty"
        end
      end

      def encode_interactions(interactions)
        Base64.strict_encode64(JSON.generate(normalize_interactions(interactions)))
      end

      def normalize_interactions(interactions)
        Array(interactions).compact.map { |interaction| normalize_interaction(interaction) }
      end

      def normalize_interaction(interaction)
        if interaction.respond_to?(:to_h)
          interaction.to_h.transform_keys(&:to_sym)
        elsif interaction.is_a?(Hash)
          interaction.transform_keys(&:to_sym)
        else
          raise SmartId::Errors::RequestSetupError, "Unsupported interaction object type: #{interaction.class}"
        end
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
          raise SmartId::Errors::RequestSetupError, "Value for 'digestInput' must be set with SignableData or with SignableHash"
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
