# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Thrown when session status end result is SERVER_ERROR, indicating a server-side technical error.
    class SmartIdServerError < SessionEndResultError
      def initialize
        super("SERVER_ERROR", "Process was terminated due to server-side technical error")
      end
    end
  end
end
