# frozen_string_literal: true

require "base64"
require "openssl"

module SmartId
  module Validation
    # Validates certificate choice response data.
    class CertificateChoiceResponseValidator
      CERTIFICATE_LEVEL_ORDER = { "ADVANCED" => 1, "QUALIFIED" => 2, "QSCD" => 2 }.freeze
      def initialize(certificate_validator: CertificateValidator.new)
        @certificate_validator = certificate_validator
      end

      def validate(session_status, requested_certificate_level = "QUALIFIED")
        status = normalize_status(session_status)
        if status.nil?
          raise SmartId::Errors::RequestSetupError, "Parameter 'sessionStatus' is not provided"
        end
        if requested_certificate_level.nil?
          raise SmartId::Errors::RequestSetupError, "Parameter 'requestedCertificateLevel' is not provided"
        end

        validate_result(status.result)
        certificate_level, certificate = validate_session_status_certificate(status.cert, requested_certificate_level)
        to_certificate_choice_response(status, certificate, certificate_level)
      end

      private

      def validate_result(session_result)
        if session_result.nil?
          raise SmartId::Errors::UnprocessableResponseError, "Certificate choice session status field 'result' is missing"
        end
        if blank?(session_result.end_result)
          raise SmartId::Errors::UnprocessableResponseError, "Certificate choice session status field 'result.endResult' is empty"
        end
        ErrorResultHandler.handle(session_result) unless session_result.end_result == "OK"
        if blank?(session_result.document_number)
          raise SmartId::Errors::UnprocessableResponseError, "Certificate choice session status field 'result.documentNumber' is empty"
        end
      end

      def validate_session_status_certificate(session_certificate, requested_certificate_level)
        if session_certificate.nil?
          raise SmartId::Errors::UnprocessableResponseError, "Certificate choice session status field 'cert' is missing"
        end
        if blank?(session_certificate.value)
          raise SmartId::Errors::UnprocessableResponseError, "Certificate choice session status field 'cert.value' has empty value"
        end
        if blank?(session_certificate.certificate_level)
          raise SmartId::Errors::UnprocessableResponseError, "Certificate choice session status field 'cert.certificateLevel' has empty value"
        end
        unless CERTIFICATE_LEVEL_ORDER.key?(session_certificate.certificate_level)
          raise SmartId::Errors::UnprocessableResponseError,
                "Certificate choice session status field 'cert.certificateLevel' has unsupported value"
        end

        response_level = session_certificate.certificate_level
        requested_level = requested_certificate_level.to_s
        requested_level = "QUALIFIED" if requested_level.strip.empty?
        if CERTIFICATE_LEVEL_ORDER[response_level] < CERTIFICATE_LEVEL_ORDER.fetch(requested_level, CERTIFICATE_LEVEL_ORDER["QUALIFIED"])
          raise SmartId::Errors::CertificateLevelMismatchError,
                "Certificate choice session status response certificate level is lower than requested"
        end

        certificate = parse_certificate(session_certificate.value)
        @certificate_validator.validate(certificate) if @certificate_validator
        [response_level, certificate]
      end

      def parse_certificate(cert_base64)
        decoded = Base64.decode64(cert_base64.to_s)
        OpenSSL::X509::Certificate.new(decoded)
      rescue OpenSSL::X509::CertificateError, ArgumentError
        raise SmartId::Errors::UnprocessableResponseError, "Certificate is invalid"
      end

      def to_certificate_choice_response(status, certificate, certificate_level)
        SmartId::Models::CertificateChoiceResponse.new(
          end_result: status.result.end_result,
          document_number: status.result.document_number,
          certificate: certificate,
          certificate_level: certificate_level,
          interaction_flow_used: status.interaction_type_used,
          device_ip_address: status.device_ip_address
        )
      end

      def normalize_status(session_status)
        return session_status if session_status.respond_to?(:result)
        return SmartId::Models::SessionStatus.from_h(session_status) if session_status.is_a?(Hash)

        nil
      end

      def blank?(value)
        value.nil? || value.to_s.strip.empty?
      end
    end
  end
end
