# frozen_string_literal: true

module SmartId
  module Errors
    class DocumentUnusableError < Error
      def initialize(message = "Document is unusable")
        super
      end
    end
  end
end
