# frozen_string_literal: true

module SmartId
  module Validation
    # Handles non-OK session end results and raises mapped exceptions.
    class ErrorResultHandler
      END_RESULT_MESSAGES = {
        "USER_REFUSED" => "User pressed cancel in app",
        "TIMEOUT" => "Session timed out without getting any response from user",
        "DOCUMENT_UNUSABLE" => "Document is unusable. User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason.",
        "WRONG_VC" => "User selected wrong verification code",
        "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP" => "User app version does not support any of the provided interactions.",
        "USER_REFUSED_CERT_CHOICE" => "User has multiple accounts and pressed Cancel on device choice screen on any device.",
        "USER_REFUSED_INTERACTION" => "User refused interaction",
        "PROTOCOL_FAILURE" => "A logical error occurred in the signing protocol.",
        "EXPECTED_LINKED_SESSION" => "The app received a different transaction while waiting for the linked session that follows the device-link based cert-choice session",
        "SERVER_ERROR" => "Process was terminated due to server-side technical error",
        "ACCOUNT_UNUSABLE" => "The account is currently unusable"
      }.freeze

      def self.handle(result)
        if result.nil?
          raise SmartId::Errors::RequestSetupError, "Parameter 'sessionResult' is not provided"
        end

        end_result = fetch_value(result, :end_result, :endResult)
        if blank?(end_result)
          raise SmartId::Errors::UnprocessableResponseError, "Session result field 'endResult' is empty"
        end

        if end_result == "USER_REFUSED_INTERACTION"
          raise_user_refused_interaction_error(result)
        end
        if end_result == "DOCUMENT_UNUSABLE"
          raise SmartId::Errors::DocumentUnusableError
        end

        raise SmartId::Errors::SessionEndResultError.new(
          end_result,
          END_RESULT_MESSAGES[end_result] || "Unexpected session result: #{end_result}"
        )
      end

      def self.raise_user_refused_interaction_error(result)
        details = fetch_value(result, :details)
        interaction = fetch_value(details, :interaction)
        if blank?(interaction)
          raise SmartId::Errors::UnprocessableResponseError, "Details for refused interaction are missing"
        end

        case interaction
        when "displayTextAndPIN"
          raise SmartId::Errors::UserRefusedDisplayTextAndPinError
        when "confirmationMessage"
          raise SmartId::Errors::UserRefusedConfirmationMessageError
        when "confirmationMessageAndVerificationCodeChoice"
          raise SmartId::Errors::UserRefusedConfirmationMessageWithVerificationChoiceError
        else
          raise SmartId::Errors::UnprocessableResponseError, "Unexpected interaction type: #{interaction}"
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
