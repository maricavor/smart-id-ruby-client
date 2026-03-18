# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Thrown when session status end result is USER_REFUSED_INTERACTION.
    # This happens when user presses Cancel on display text and PIN screen.
    class UserRefusedDisplayTextAndPinError < SessionEndResultError
      def initialize
        super("USER_REFUSED_INTERACTION", "User pressed Cancel on PIN screen.")
      end
    end
  end
end
