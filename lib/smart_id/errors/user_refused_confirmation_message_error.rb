# frozen_string_literal: true

module SmartId
  module Errors
    class UserRefusedConfirmationMessageError < SessionEndResultError
      def initialize
        super("USER_REFUSED_INTERACTION", "User cancelled on confirmationMessage screen")
      end
    end
  end
end
