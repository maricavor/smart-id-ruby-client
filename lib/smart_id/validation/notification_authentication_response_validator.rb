# frozen_string_literal: true

require "base64"
require "openssl"

module SmartId
  module Validation
    # Validates notification authentication response data.
    class NotificationAuthenticationResponseValidator
      def initialize(
        device_link_authentication_response_validator: DeviceLinkAuthenticationResponseValidator.new,
        authentication_identity_mapper: AuthenticationIdentityMapper.new
      )
        @device_link_authentication_response_validator = device_link_authentication_response_validator
        @authentication_identity_mapper = authentication_identity_mapper
      end

      def validate(session_status, authentication_session_request, schema_name, brokered_rp_name = nil)
        response = @device_link_authentication_response_validator.validate(
          session_status,
          authentication_session_request,
          nil,
          schema_name,
          brokered_rp_name
        )
        certificate = parse_certificate(response.certificate_value)
        map_identity(certificate)
      end

      private

      def parse_certificate(cert_value)
        decoded = Base64.decode64(cert_value.to_s)
        OpenSSL::X509::Certificate.new(decoded)
      rescue OpenSSL::X509::CertificateError, ArgumentError
        raise SmartId::Errors::UnprocessableResponseError, "Certificate is invalid"
      end

      def map_identity(certificate)
        @authentication_identity_mapper.from(certificate)
      end
    end
  end
end
