# frozen_string_literal: true

require "base64"
require "openssl"

module SmartId
  module Validation
    # Validates authentication certificate structure, level and purpose.
    class AuthenticationCertificateValidator
      QUALIFIED_CERTIFICATE_POLICY_OIDS = ["1.3.6.1.4.1.10015.17.2", "0.4.0.2042.1.2"].freeze
      CERTIFICATE_LEVEL_ORDER = {
        "ADVANCED" => 1,
        "QUALIFIED" => 2,
        "QSCD" => 3
      }.freeze

      def validate(cert:, requested_level:)
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
        unless CERTIFICATE_LEVEL_ORDER[actual_level] >= CERTIFICATE_LEVEL_ORDER.fetch(required_level, 2)
          raise SmartId::Errors::UnprocessableResponseError, "Signer's certificate is below requested certificate level"
        end

        certificate = parse_certificate(cert.value)
        validate_certificate_is_currently_valid(certificate)
        validate_certificate_purpose(certificate, actual_level)
        certificate
      end

      private

      def parse_certificate(value)
        der = Base64.decode64(value)
        OpenSSL::X509::Certificate.new(der)
      rescue OpenSSL::X509::CertificateError, ArgumentError
        raise SmartId::Errors::UnprocessableResponseError, "Certificate is invalid"
      end

      def validate_certificate_is_currently_valid(certificate)
        now = Time.now
        return if certificate.not_before <= now && now <= certificate.not_after

        raise SmartId::Errors::UnprocessableResponseError, "Certificate is invalid"
      end

      def validate_certificate_purpose(certificate, actual_level)
        return unless ["QUALIFIED", "QSCD"].include?(actual_level)

        certificate_policy_oids = extract_certificate_policy_oids(certificate)
        if certificate_policy_oids.empty?
          raise SmartId::Errors::UnprocessableResponseError,
                "Certificate does not have certificate policy OIDs and is not a qualified Smart-ID authentication certificate"
        end
        return if (QUALIFIED_CERTIFICATE_POLICY_OIDS - certificate_policy_oids).empty?

        raise SmartId::Errors::UnprocessableResponseError,
              "Certificate is not a qualified Smart-ID authentication certificate"
      end

      def extract_certificate_policy_oids(certificate)
        extension = certificate.extensions.find { |ext| ext.oid == "certificatePolicies" }
        return [] unless extension

        extension.value.scan(/\b\d+(?:\.\d+)+\b/)
      end

      def validate_non_empty(value, field_name)
        return unless blank?(value)

        raise SmartId::Errors::UnprocessableResponseError,
              "Authentication session status field '#{field_name}' is empty"
      end

      def blank?(value)
        value.nil? || value.to_s.strip.empty?
      end
    end
  end
end
