# frozen_string_literal: true

module SmartIdRuby
  module Models
    # Represents validated authentication response data.
    class AuthenticationResponse
      attr_reader :end_result, :document_number, :signature_value_base64, :server_random,
                  :user_challenge, :flow_type, :signature_algorithm, :certificate_value,
                  :certificate_level, :interaction_type_used, :device_ip_address

      def initialize(
        end_result:,
        document_number:,
        signature_value_base64:,
        server_random:,
        user_challenge:,
        flow_type:,
        signature_algorithm:,
        certificate_value:,
        certificate_level:,
        interaction_type_used:,
        device_ip_address:
      )
        @end_result = end_result
        @document_number = document_number
        @signature_value_base64 = signature_value_base64
        @server_random = server_random
        @user_challenge = user_challenge
        @flow_type = flow_type
        @signature_algorithm = signature_algorithm
        @certificate_value = certificate_value
        @certificate_level = certificate_level
        @interaction_type_used = interaction_type_used
        @device_ip_address = device_ip_address
      end
    end
  end
end
