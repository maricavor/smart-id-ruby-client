# frozen_string_literal: true

module SmartIdRuby
  module Validation
    # Container for trust anchors and CA certificates used in validation.
    class TrustedCaCertStore
      attr_reader :trust_anchors, :trusted_ca_certificates, :ocsp_enabled

      def initialize(trust_anchors:, trusted_ca_certificates:, ocsp_enabled: false)
        @trust_anchors = Array(trust_anchors).dup.freeze
        @trusted_ca_certificates = Array(trusted_ca_certificates).dup.freeze
        @ocsp_enabled = !!ocsp_enabled
      end

      def ocsp_enabled?
        ocsp_enabled
      end
    end
  end
end
