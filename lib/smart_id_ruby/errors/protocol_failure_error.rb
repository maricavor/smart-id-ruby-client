# frozen_string_literal: true

module SmartIdRuby
  module Errors
    class ProtocolFailureError < SessionEndResultError
      def initialize
        super("PROTOCOL_FAILURE", "A logical error occurred in the signing protocol.")
      end
    end
  end
end
