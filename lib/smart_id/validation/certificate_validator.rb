# frozen_string_literal: true

require "openssl"

module SmartId
  module Validation
    # Validates X.509 certificate validity period and trust chain.
    class CertificateValidator
      def initialize(trusted_ca_cert_store: nil, use_system_store: true)
        @trusted_ca_cert_store = trusted_ca_cert_store
        @use_system_store = use_system_store
      end

      def validate(certificate)
        validate_certificate_is_currently_valid(certificate)
        validate_certificate_chain(certificate)
      end

      private

      def validate_certificate_is_currently_valid(certificate)
        now = Time.now
        return if certificate.not_before <= now && now <= certificate.not_after

        raise SmartId::Errors::UnprocessableResponseError, "Certificate is invalid"
      rescue OpenSSL::X509::CertificateError, NoMethodError
        raise SmartId::Errors::UnprocessableResponseError, "Certificate is invalid"
      end

      def validate_certificate_chain(certificate)
        store = OpenSSL::X509::Store.new
        store.set_default_paths if @use_system_store

        trusted_chain = []
        if @trusted_ca_cert_store
          @trusted_ca_cert_store.trust_anchors.each { |cert| store.add_cert(cert) }
          @trusted_ca_cert_store.trusted_ca_certificates.each do |cert|
            store.add_cert(cert)
            trusted_chain << cert
          end
          # OCSP is not directly exposed by Ruby OpenSSL store API. Keep the flag
          # in the store model for parity and future extension.
          @trusted_ca_cert_store.ocsp_enabled?
        end

        return if store.verify(certificate, trusted_chain)

        raise SmartId::Errors::UnprocessableResponseError, "Certificate chain validation failed"
      rescue OpenSSL::X509::StoreError
        raise SmartId::Errors::UnprocessableResponseError, "Certificate chain validation failed"
      end
    end
  end
end
