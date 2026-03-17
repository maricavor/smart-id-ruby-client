# frozen_string_literal: true

require "base64"
require "openssl"

module SmartIdRuby
  module Validation
    # Validates notification authentication response data and returns authentication identity.
    class NotificationAuthenticationResponseValidator
      def initialize(
        device_link_authentication_response_validator: DeviceLinkAuthenticationResponseValidator.new,
        authentication_identity_mapper: AuthenticationIdentityMapper.new
      )
        @device_link_authentication_response_validator = device_link_authentication_response_validator
        @authentication_identity_mapper = authentication_identity_mapper
      end

      def validate(session_status, authentication_session_request, schema_name, brokered_rp_name = nil)
        @device_link_authentication_response_validator.validate(
          session_status,
          authentication_session_request,
          nil,
          schema_name,
          brokered_rp_name
        )
      end
    end
  end
end
