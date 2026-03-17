# frozen_string_literal: true

module SmartIdRuby
  module Validation
    # Handles non-OK session end results and raises mapped exceptions.
    class ErrorResultHandler
      def self.handle(result)
        raise SmartIdRuby::Errors::RequestSetupError, "Parameter 'sessionResult' is not provided" if result.nil?

        end_result = fetch_value(result, :end_result, :endResult)
        if blank?(end_result)
          raise SmartIdRuby::Errors::UnprocessableResponseError, "Session result field 'endResult' is empty"
        end

        case end_result
        when "USER_REFUSED"
          raise SmartIdRuby::Errors::UserRefusedError
        when "TIMEOUT"
          raise SmartIdRuby::Errors::SessionTimeoutError
        when "DOCUMENT_UNUSABLE"
          raise SmartIdRuby::Errors::DocumentUnusableError
        when "WRONG_VC"
          raise SmartIdRuby::Errors::UserSelectedWrongVerificationCodeError
        when "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP"
          raise SmartIdRuby::Errors::RequiredInteractionNotSupportedByAppError
        when "USER_REFUSED_CERT_CHOICE"
          raise SmartIdRuby::Errors::UserRefusedCertChoiceError
        when "USER_REFUSED_INTERACTION"
          raise_user_refused_interaction_error(result)
        when "PROTOCOL_FAILURE"
          raise SmartIdRuby::Errors::ProtocolFailureError
        when "EXPECTED_LINKED_SESSION"
          raise SmartIdRuby::Errors::ExpectedLinkedSessionError
        when "SERVER_ERROR"
          raise SmartIdRuby::Errors::SmartIdServerError
        when "ACCOUNT_UNUSABLE"
          raise SmartIdRuby::Errors::UserAccountUnusableError
        else
          raise SmartIdRuby::Errors::UnprocessableResponseError, "Unexpected session result: #{end_result}"
        end
      end

      def self.raise_user_refused_interaction_error(result)
        details = fetch_value(result, :details)
        interaction = fetch_value(details, :interaction)
        if blank?(interaction)
          raise SmartIdRuby::Errors::UnprocessableResponseError, "Details for refused interaction are missing"
        end

        case interaction
        when "displayTextAndPIN"
          raise SmartIdRuby::Errors::UserRefusedDisplayTextAndPinError
        when "confirmationMessage"
          raise SmartIdRuby::Errors::UserRefusedConfirmationMessageError
        when "confirmationMessageAndVerificationCodeChoice"
          raise SmartIdRuby::Errors::UserRefusedConfirmationMessageWithVerificationChoiceError
        else
          raise SmartIdRuby::Errors::UnprocessableResponseError, "Unexpected interaction type: #{interaction}"
        end
      end

      def self.fetch_value(container, *keys)
        return nil if container.nil?

        keys.each do |key|
          if container.respond_to?(:[])
            value = container[key]
            return value unless value.nil?

            value = container[key.to_s]
            return value unless value.nil?
          end

          method_name = key.to_s
          return container.public_send(method_name) if container.respond_to?(method_name)
        end

        nil
      end
      private_class_method :fetch_value

      def self.blank?(value)
        value.nil? || value.to_s.strip.empty?
      end
      private_class_method :blank?
    end
  end
end
