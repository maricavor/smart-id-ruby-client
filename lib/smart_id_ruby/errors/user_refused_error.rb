# frozen_string_literal: true

module SmartIdRuby
  module Errors
    class UserRefusedError < SessionEndResultError
      def initialize
        super("USER_REFUSED", "User pressed cancel in app")
      end
    end
  end
end
