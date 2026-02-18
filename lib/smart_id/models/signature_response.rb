# frozen_string_literal: true

module SmartId
  module Models
    class SignatureResponse
      attr_reader :end_result, :signature_value_in_base64, :algorithm_name, :flow_type, :certificate,
                  :requested_certificate_level, :certificate_level, :document_number, :interaction_flow_used,
                  :device_ip_address, :rsa_ssa_pss_parameters

      def initialize(
        end_result:,
        signature_value_in_base64:,
        algorithm_name:,
        flow_type:,
        certificate:,
        requested_certificate_level:,
        certificate_level:,
        document_number:,
        interaction_flow_used:,
        device_ip_address:,
        rsa_ssa_pss_parameters:
      )
        @end_result = end_result
        @signature_value_in_base64 = signature_value_in_base64
        @algorithm_name = algorithm_name
        @flow_type = flow_type
        @certificate = certificate
        @requested_certificate_level = requested_certificate_level
        @certificate_level = certificate_level
        @document_number = document_number
        @interaction_flow_used = interaction_flow_used
        @device_ip_address = device_ip_address
        @rsa_ssa_pss_parameters = rsa_ssa_pss_parameters
      end
    end
  end
end
