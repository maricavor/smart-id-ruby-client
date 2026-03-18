# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Thrown when session status end result is WRONG_VC.
    # This happens when user selects wrong verification code in the app.
    class UserSelectedWrongVerificationCodeError < SessionEndResultError
      def initialize
        super("WRONG_VC", "User selected wrong verification code")
      end
    end
  end
end
