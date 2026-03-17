# frozen_string_literal: true

module SmartIdRuby
  module Errors
    class SmartIdServerError < SessionEndResultError
      def initialize
        super("SERVER_ERROR", "Process was terminated due to server-side technical error")
      end
    end
  end
end
