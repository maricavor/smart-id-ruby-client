module SmartId::Utils
  class CertificateLevelValidator
    def self.validate!(certificate_level, requested_certificate_level)
      obj = new(certificate_level, requested_certificate_level)
      obj.validate_level!
    end

    def initialize(certificate_level, requested_certificate_level)
      @certificate_level = certificate_level
      @requested_certificate_level = requested_certificate_level
    end

    def validate_level!
      cert_level = CertificateLevel.new(@certificate_level)
      return if @requested_certificate_level.to_s.empty? || cert_level.equal_or_above?(@requested_certificate_level)

      raise SmartId::CertificateLevelMismatchError, "Signer's certificate is below requested certificate level"
    end
  end
end
