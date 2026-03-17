# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Represents user refused confirmation message error condition.
    class UserRefusedConfirmationMessageError < SessionEndResultError
      def initialize
        super("USER_REFUSED_INTERACTION", "User cancelled on confirmationMessage screen")
      end
    end
  end
end
