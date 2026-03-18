# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Thrown when session status end result is USER_REFUSED.
    class UserRefusedError < SessionEndResultError
      def initialize
        super("USER_REFUSED", "User pressed cancel in app")
      end
    end
  end
end
