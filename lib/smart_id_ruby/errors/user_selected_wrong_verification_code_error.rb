# frozen_string_literal: true

module SmartIdRuby
  module Errors
    class UserSelectedWrongVerificationCodeError < SessionEndResultError
      def initialize
        super("WRONG_VC", "User selected wrong verification code")
      end
    end
  end
end
