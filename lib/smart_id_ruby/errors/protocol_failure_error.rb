# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Exception thrown when the session status end result is PROTOCOL_FAILURE, indicating logical error in the signing protocol.
    # F.e. Constructed device link that user can interact with contains invalid schema.
    class ProtocolFailureError < SessionEndResultError
      def initialize
        super("PROTOCOL_FAILURE", "A logical error occurred in the signing protocol.")
      end
    end
  end
end
