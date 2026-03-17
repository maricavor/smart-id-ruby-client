# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Represents user refused confirmation message with verification choice error condition.
    class UserRefusedConfirmationMessageWithVerificationChoiceError < SessionEndResultError
      def initialize
        super("USER_REFUSED_INTERACTION", "User cancelled on confirmationMessageAndVerificationCodeChoice screen")
      end
    end
  end
end
