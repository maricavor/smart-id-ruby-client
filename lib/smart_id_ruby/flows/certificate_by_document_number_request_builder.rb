# frozen_string_literal: true

require "base64"
require "openssl"

module SmartIdRuby
  module Flows
    # Builds certificate by document number requests.
    class CertificateByDocumentNumberRequestBuilder < BaseBuilder
      BASE64_PATTERN = /\A[A-Za-z0-9+\/]+={0,2}\z/
      SUPPORTED_STATES = %w[OK DOCUMENT_UNUSABLE].freeze
      CERTIFICATE_LEVEL_ORDER = {
        "ADVANCED" => 1,
        "QUALIFIED" => 2,
        "QSCD" => 2
      }.freeze
      DEFAULT_CERTIFICATE_LEVEL = "QUALIFIED"

      def initialize(connector)
        super(connector)
        @document_number = nil
        @certificate_level = DEFAULT_CERTIFICATE_LEVEL
      end

      def with_document_number(document_number)
        @document_number = document_number
        self
      end

      def with_certificate_level(certificate_level)
        @certificate_level = certificate_level
        self
      end

      def get_certificate_by_document_number
        validate_request_parameters
        request = create_request
        response = connector.get_certificate_by_document_number(@document_number, request)
        validate_response_parameters(response)

        cert = fetch_value(response, :cert)
        cert_level = fetch_value(cert, :certificateLevel).to_s
        cert_value = fetch_value(cert, :value).to_s
        {
          certificate_level: cert_level,
          certificate: OpenSSL::X509::Certificate.new(Base64.strict_decode64(cert_value))
        }
      end

      private

      def create_request
        {
          relyingPartyUUID: relying_party_uuid,
          relyingPartyName: relying_party_name,
          certificateLevel: @certificate_level&.to_s
        }.compact
      end

      def validate_request_parameters
        if blank?(@document_number)
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'documentNumber' cannot be empty"
        end
        if blank?(relying_party_uuid)
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'relyingPartyUUID' cannot be empty"
        end
        if blank?(relying_party_name)
          raise SmartIdRuby::Errors::RequestSetupError, "Value for 'relyingPartyName' cannot be empty"
        end
      end

      def validate_response_parameters(response)
        if response.nil?
          raise SmartIdRuby::Errors::UnprocessableResponseError, "Queried certificate response is not provided"
        end

        validate_state(response)
        cert = fetch_value(response, :cert)
        if cert.nil?
          raise SmartIdRuby::Errors::UnprocessableResponseError, "Queried certificate response field 'cert' is missing"
        end

        validate_certificate_level(cert)
        validate_certificate_value(cert)
      end

      def validate_state(response)
        state = fetch_value(response, :state)
        if blank?(state)
          raise SmartIdRuby::Errors::UnprocessableResponseError, "Queried certificate response field 'state' is missing"
        end
        unless SUPPORTED_STATES.include?(state)
          raise SmartIdRuby::Errors::UnprocessableResponseError, "Queried certificate response field 'state' has unsupported value"
        end
        if state == "DOCUMENT_UNUSABLE"
          raise SmartIdRuby::Errors::DocumentUnusableError
        end
      end

      def validate_certificate_level(cert)
        response_level = fetch_value(cert, :certificateLevel)
        if blank?(response_level)
          raise SmartIdRuby::Errors::UnprocessableResponseError, "Queried certificate response field 'cert.certificateLevel' is missing"
        end

        unless CERTIFICATE_LEVEL_ORDER.key?(response_level)
          raise SmartIdRuby::Errors::UnprocessableResponseError,
                "Queried certificate response field 'cert.certificateLevel' has unsupported value"
        end

        requested_level = @certificate_level.nil? ? DEFAULT_CERTIFICATE_LEVEL : @certificate_level.to_s
        if CERTIFICATE_LEVEL_ORDER[response_level] < CERTIFICATE_LEVEL_ORDER.fetch(requested_level, CERTIFICATE_LEVEL_ORDER[DEFAULT_CERTIFICATE_LEVEL])
          raise SmartIdRuby::Errors::UnprocessableResponseError, "Queried certificate has lower level than requested"
        end
      end

      def validate_certificate_value(cert)
        cert_value = fetch_value(cert, :value)
        if blank?(cert_value)
          raise SmartIdRuby::Errors::UnprocessableResponseError, "Queried certificate response field 'cert.value' is missing"
        end

        return if BASE64_PATTERN.match?(cert_value)

        raise SmartIdRuby::Errors::UnprocessableResponseError,
              "Queried certificate response field 'cert.value' does not have Base64-encoded value"
      end
    end
  end
end
