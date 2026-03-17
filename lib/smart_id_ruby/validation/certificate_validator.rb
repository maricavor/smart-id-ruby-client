# frozen_string_literal: true

require "openssl"
require "net/http"
require "uri"

module SmartIdRuby
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

        raise SmartIdRuby::Errors::UnprocessableResponseError, "Certificate is invalid"
      rescue OpenSSL::X509::CertificateError, NoMethodError => e
        logger.error("Certificate is expired or not yet valid: #{certificate_subject(certificate)} (#{e.class}: #{e.message})")
        raise SmartIdRuby::Errors::UnprocessableResponseError, "Certificate is invalid"
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
        end

        store_context = OpenSSL::X509::StoreContext.new(store, certificate, trusted_chain)
        if store_context.verify
          log_validated_chain(store_context)
          validate_ocsp_revocation!(certificate, Array(store_context.chain), store)
          return
        end

        raise SmartIdRuby::Errors::UnprocessableResponseError, "Certificate chain validation failed"
      rescue OpenSSL::X509::StoreError
        raise SmartIdRuby::Errors::UnprocessableResponseError, "Certificate chain validation failed"
      end

      def log_validated_chain(store_context)
        return unless logger.respond_to?(:debug?) && logger.debug?

        chain = Array(store_context.chain)
        leaf = chain[0]
        intermediate = chain[1]
        trust_anchor = chain.last
        logger.debug(
          "Leaf: #{certificate_common_name(leaf)}, " \
          "Intermediate: #{certificate_common_name(intermediate)}, " \
          "Trust anchor: #{certificate_common_name(trust_anchor)}"
        )
      rescue StandardError
        # Keep certificate validation resilient even if debug chain details are unavailable.
      end

      def certificate_common_name(certificate)
        return "N/A" unless certificate.respond_to?(:subject) && certificate.subject

        entry = certificate.subject.to_a.find { |name, _value, _type| name == "CN" }
        entry ? entry[1] : certificate.subject.to_s
      end

      def certificate_subject(certificate)
        certificate&.subject&.to_s || "unknown"
      end

      def validate_ocsp_revocation!(certificate, chain, store)
        return unless @trusted_ca_cert_store&.ocsp_enabled?

        issuer = find_issuer_certificate(certificate, chain)
        ocsp_url = extract_ocsp_url(certificate)
        if issuer.nil? || ocsp_url.nil?
          raise SmartIdRuby::Errors::UnprocessableResponseError, "OCSP validation failed"
        end

        cert_id = OpenSSL::OCSP::CertificateId.new(certificate, issuer, OpenSSL::Digest::SHA1.new)
        request = OpenSSL::OCSP::Request.new
        request.add_certid(cert_id)
        request.add_nonce

        response = perform_ocsp_request(ocsp_url, request.to_der)
        unless response.status == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
          raise SmartIdRuby::Errors::UnprocessableResponseError, "OCSP responder returned non-success status"
        end

        basic_response = response.basic
        if basic_response.nil?
          raise SmartIdRuby::Errors::UnprocessableResponseError, "OCSP response does not contain basic response"
        end

        verify_ocsp_response_signature!(basic_response, store)

        status_entries = Array(basic_response.status)
        cert_status = status_entries.first&.[](1)
        case cert_status
        when OpenSSL::OCSP::V_CERTSTATUS_GOOD
          logger.debug("OCSP status for certificate is GOOD") if logger.respond_to?(:debug?) && logger.debug?
        when OpenSSL::OCSP::V_CERTSTATUS_REVOKED
          raise SmartIdRuby::Errors::UnprocessableResponseError, "Certificate is revoked according to OCSP response"
        else
          raise SmartIdRuby::Errors::UnprocessableResponseError, "Certificate OCSP status is unknown"
        end
      rescue OpenSSL::OCSP::OCSPError, OpenSSL::X509::StoreError, SocketError, SystemCallError, Timeout::Error => e
        raise SmartIdRuby::Errors::UnprocessableResponseError, "OCSP validation failed: #{e.message}"
      end

      def find_issuer_certificate(certificate, chain)
        issuer_subject = certificate&.issuer
        Array(chain).find { |cert| cert != certificate && cert.subject == issuer_subject }
      end

      def extract_ocsp_url(certificate)
        aia_ext = certificate.extensions.find { |ext| ext.oid == "authorityInfoAccess" }
        return nil if aia_ext.nil?

        match = aia_ext.value.to_s.match(/OCSP\s*-\s*URI:([^\s,]+)/i)
        match && match[1]
      rescue OpenSSL::X509::ExtensionError, NoMethodError
        nil
      end

      def perform_ocsp_request(url, body)
        uri = URI.parse(url)
        request = Net::HTTP::Post.new(uri.request_uri)
        request["Content-Type"] = "application/ocsp-request"
        request["Accept"] = "application/ocsp-response"
        request.body = body

        response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https", read_timeout: 10, open_timeout: 10) do |http|
          http.request(request)
        end
        unless response.code.to_i == 200
          raise SmartIdRuby::Errors::UnprocessableResponseError, "OCSP responder returned HTTP #{response.code}"
        end

        OpenSSL::OCSP::Response.new(response.body)
      end

      def verify_ocsp_response_signature!(basic_response, store)
        responder_chain = Array(basic_response.certs)
        verified = basic_response.verify(responder_chain, store)
        return if verified

        raise SmartIdRuby::Errors::UnprocessableResponseError, "OCSP response signature is not valid"
      end

      def logger
        SmartIdRuby.logger
      end
    end
  end
end
