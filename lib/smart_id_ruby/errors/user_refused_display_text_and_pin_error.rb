# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Represents user refused display text and pin error condition.
    class UserRefusedDisplayTextAndPinError < SessionEndResultError
      def initialize
        super("USER_REFUSED_INTERACTION", "User pressed Cancel on PIN screen.")
      end
    end
  end
end
