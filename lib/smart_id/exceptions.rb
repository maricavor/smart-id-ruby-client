module SmartId
  class Exception < StandardError; end
  class InvalidParamsError < Exception; end
  class SSLCertificateNotVerified < Exception; end
  class InvalidResponseCertificate < Exception; end
  class InvalidResponseSignature < Exception; end
  class UserNotFoundError < Exception; end
  class OutdatedApiError < Exception; end
  class SystemUnderMaintenanceError < Exception; end
  class InvalidPermissionsError < Exception; end
  class ConnectionError < Exception; end
  class UserRefusedError < Exception; end
  class SessionTimeoutError < Exception; end
  class DocumentUnusableError < Exception; end
  class WrongVerificationCodeSelectedError < Exception; end
  class RequiredInteractionNotSupportedError < Exception; end
  class CertChoiceRefusedError < Exception; end
  class DisplayTextAndPinRefusedError < Exception; end
  class VerificationChoiceRefusedError < Exception; end
  class ConfirmationMessageRefusedError < Exception; end
  class ConfirmationMessageWithVerificationChoiceRefusedError < Exception; end
  class UnprocessableResponseError < Exception; end
  class CerificateLevelMismatchError < Exception; end

  class IncorrectAccountLevelError < Exception
    def message
      "User exists, but has lower level account than required by request"
    end
  end
end
