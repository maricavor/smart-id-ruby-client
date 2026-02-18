# frozen_string_literal: true

module SmartId
  module Errors
    class UserRefusedConfirmationMessageWithVerificationChoiceError < SessionEndResultError
      def initialize
        super("USER_REFUSED_INTERACTION", "User cancelled on confirmationMessageAndVerificationCodeChoice screen")
      end
    end
  end
end
