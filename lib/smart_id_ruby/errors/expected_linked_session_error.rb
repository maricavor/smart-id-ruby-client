# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Linked signature flow consists of two sessions - device link-based certificate choice session followed by the linked signature session.
    # Exception will be thrown when linked signature session is not received after the device link-based certificate choice session,
    # but some other session with the same document number is received instead.
    class ExpectedLinkedSessionError < SessionEndResultError
      def initialize
        super("EXPECTED_LINKED_SESSION",
              "The app received a different transaction while waiting for the linked session that follows the device-link based cert-choice session")
      end
    end
  end
end
