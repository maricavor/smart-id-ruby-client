# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Represents session end result error condition.
    class SessionEndResultError < Error
      attr_reader :end_result

      def initialize(end_result, message = nil)
        @end_result = end_result
        super(message || "Session ended with result '#{end_result}'")
      end
    end
  end
end
