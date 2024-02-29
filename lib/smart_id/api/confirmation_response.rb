module SmartId::Api
  class ConfirmationResponse
    RUNNING_STATE = "RUNNING".freeze

    attr_reader :body, :requested_certificate_level

    def initialize(response_body, hashed_data, requested_certificate_level)
      @body = response_body
      @requested_certificate_level = requested_certificate_level
      validate!(hashed_data)
    end

    def confirmation_running?
      state == RUNNING_STATE
    end

    def result
      @body["result"]
    end

    def state
      @body["state"]
    end

    def end_result
      @body.dig("result", "endResult")
    end

    def document_number
      @body.dig("result", "documentNumber")
    end

    def certificate_level
      @body.dig("cert", "certificateLevel")
    end

    def certificate
      @certificate ||= SmartId::AuthenticationCertificate::Certificate.new(@body.dig("cert", "value"))
    end

    def signature_algorithm
      @body.dig("signature", "algorithm")
    end

    def signature
      @body.dig("signature", "value")
    end

    def ignored_properties
      @body["ignoredProperties"]
    end

    private

    def validate!(hashed_data)
      SmartId::Utils::SessionResultValidator.validate!(result)
      SmartId::Utils::CertificateValidator.validate!(hashed_data, signature, certificate)
      SmartId::Utils::CertificateLevelValidator.validate!(certificate_level, requested_certificate_level)
    end
  end
end
