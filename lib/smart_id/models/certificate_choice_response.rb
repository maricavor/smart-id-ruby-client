# frozen_string_literal: true

module SmartId
  module Models
    class CertificateChoiceResponse
      attr_reader :end_result, :certificate, :certificate_level, :document_number, :interaction_flow_used, :device_ip_address

      def initialize(end_result:, certificate:, certificate_level:, document_number:, interaction_flow_used:, device_ip_address:)
        @end_result = end_result
        @certificate = certificate
        @certificate_level = certificate_level
        @document_number = document_number
        @interaction_flow_used = interaction_flow_used
        @device_ip_address = device_ip_address
      end
    end
  end
end
