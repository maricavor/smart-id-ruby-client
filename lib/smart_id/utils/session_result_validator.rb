module SmartId::Utils
  class SessionResultValidator
    def self.validate!(result)
      obj = new(result)
      obj.validate_end_result!
    end

    def initialize(result)
      @result = result
    end

    def validate_end_result!
      raise SmartId::UnprocessableResponseError, "Result is missing in the session status response" unless @result

      end_result = @result["endResult"]
      case end_result
      when "OK"
        return
      when "USER_REFUSED"
        raise SmartId::UserRefusedError, "User pressed cancel in app"
      when "TIMEOUT"
        raise SmartId::SessionTimeoutError, "Session timed out without getting any response from user"
      when "DOCUMENT_UNUSABLE"
        raise SmartId::DocumentUnusableError, "DOCUMENT_UNUSABLE. User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason"
      when "WRONG_VC"
        raise SmartId::WrongVerificationCodeSelectedError, "User selected wrong verification code"
      when "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP"
        raise SmartId::RequiredInteractionNotSupportedError, "User app version does not support any of the allowedInteractionsOrder interactions"
      when "USER_REFUSED_CERT_CHOICE"
        raise SmartId::CertChoiceRefusedError, "User has multiple accounts and pressed Cancel on device choice screen on any device"
      when "USER_REFUSED_DISPLAYTEXTANDPIN"
        raise SmartId::DisplayTextAndPinRefusedError, "User pressed Cancel on PIN screen"
      when "USER_REFUSED_VC_CHOICE"
        raise SmartId::VerificationChoiceRefusedError, "User cancelled verificationCodeChoice screen"
      when "USER_REFUSED_CONFIRMATIONMESSAGE"
        raise SmartId::ConfirmationMessageRefusedError, "User cancelled on confirmationMessage screen"
      when "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE"
        raise SmartId::ConfirmationMessageWithVerificationChoiceRefusedError, "User cancelled on confirmationMessageAndVerificationCodeChoice screen"
      else
        raise SmartId::UnprocessableResponseError, "Session status end result is '#{end_result}'"
      end
    end
  end
end
