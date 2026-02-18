# frozen_string_literal: true

module SmartId
  module Errors
    class UserRefusedDisplayTextAndPinError < SessionEndResultError
      def initialize
        super("USER_REFUSED_INTERACTION", "User pressed Cancel on PIN screen.")
      end
    end
  end
end
