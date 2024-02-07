module SmartId::Utils
  class CertificateValidator
    def self.validate!(hash_data, signature, certificate)
      obj = new(hash_data, signature, certificate)
      obj.validate_certificate!
      obj.validate_signature!
    end

    def initialize(hash_data, signature, certificate)
      @hash_data = hash_data
      @signature = signature
      @certificate = certificate&.cert
      @trusted_ca_certificates = CertificateLoader.load_pkcs12_certificates(SmartId.truststore_path, SmartId.truststore_password)
    end

    def validate_certificate!
      raise SmartId::UnprocessableResponseError, "Certificate is not present in the authentication response" unless @certificate

      verify_certificate_expiry
      verify_certificate_trusted
    end

    def validate_signature!
      raise SmartId::UnprocessableResponseError, "Signature is not present in the authentication response" unless @certificate

      public_key = @certificate.public_key

      return if public_key.verify(OpenSSL::Digest.new('SHA256'), Base64.decode64(@signature), @hash_data)

      raise SmartId::InvalidResponseSignature, "Signature verification failed"
    end

    private

    def verify_certificate_expiry
      return if @certificate.not_before <= Time.now && @certificate.not_after >= Time.now

      raise SmartId::UnprocessableResponseError, "Signer's certificate has expired"
    end

    def verify_certificate_trusted
      store = build_cert_store(@trusted_ca_certificates)

      context = OpenSSL::X509::StoreContext.new(store, @certificate)

      return if context.verify

      raise SmartId::InvalidResponseCertificate, "Certificate #{@certificate.subject} is not trusted -> #{context.error_string}"
    end

    def build_cert_store(certificates)
      OpenSSL::X509::Store.new.tap do |store|
        store.set_default_paths
        certificates.each do |cert|
          store.add_cert(cert)
        end
      end
    rescue OpenSSL::X509::StoreError => e
      raise SmartId::UnprocessableResponseError, "Error building certificate store: #{e.message}"
    end
  end
end
