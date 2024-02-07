module SmartId::Utils
  class CertificateLevel
    CERTIFICATE_LEVELS = {
      'ADVANCED' => 1,
      'QUALIFIED' => 2
    }.freeze

    def initialize(certificate_level)
      raise ArgumentError, 'certificateLevel cannot be null' if certificate_level.nil?

      @certificate_level = certificate_level.upcase
    end

    def equal_or_above?(requested_certificate_level)
      certificate_level = certificate_level.upcase

      return true if @certificate_level == certificate_level

      # Check based on the predefined levels
      current_level = CERTIFICATE_LEVELS[@certificate_level]
      requested_level = CERTIFICATE_LEVELS[requested_certificate_level]

      # Ensure both levels are defined and compare
      !current_level.nil? && !requested_level.nil? && requested_level <= current_level
    end
  end
end
