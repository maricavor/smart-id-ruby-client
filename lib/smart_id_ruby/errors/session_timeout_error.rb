# frozen_string_literal: true

module SmartIdRuby
  module Errors
    class SessionTimeoutError < SessionEndResultError
      def initialize
        super("TIMEOUT", "Session timed out without getting any response from user")
      end
    end
  end
end
