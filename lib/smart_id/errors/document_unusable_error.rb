# frozen_string_literal: true

module SmartId
  module Errors
    # Represents document unusable error condition.
    class DocumentUnusableError < Error
      def initialize(message = "Document is unusable")
        super
      end
    end
  end
end
