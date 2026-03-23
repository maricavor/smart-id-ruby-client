# frozen_string_literal: true

require "base64"
require "openssl"

module SmartIdRuby
  module Validation
    # Validates notification authentication response data and returns authentication identity.
    class NotificationAuthenticationResponseValidator < BaseAuthenticationResponseValidator

      def validate(session_status, authentication_session_request, schema_name, brokered_rp_name = nil)
        super(session_status, authentication_session_request, nil, schema_name, brokered_rp_name)
      end
    end
  end
end
