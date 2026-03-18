# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Thrown when session status end result is USER_REFUSED_INTERACTION.
    # This happens when user presses Cancel on confirmation and verification code choice screen.
    class UserRefusedConfirmationMessageWithVerificationChoiceError < SessionEndResultError
      def initialize
        super("USER_REFUSED_INTERACTION", "User cancelled on confirmationMessageAndVerificationCodeChoice screen")
      end
    end
  end
end
