# frozen_string_literal: true

module SmartIdRuby
  module Errors
    class ExpectedLinkedSessionError < SessionEndResultError
      def initialize
        super("EXPECTED_LINKED_SESSION",
              "The app received a different transaction while waiting for the linked session that follows the device-link based cert-choice session")
      end
    end
  end
end
