# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Thrown when session status end result is DOCUMENT_UNUSABLE.
    class DocumentUnusableError < Error
      def initialize(message = "Document is unusable. User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason.")
        super
      end
    end
  end
end
