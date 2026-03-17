# frozen_string_literal: true

module SmartIdRuby
  module Errors
    class RequiredInteractionNotSupportedByAppError < SessionEndResultError
      def initialize
        super("REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP",
              "User app version does not support any of the provided interactions.")
      end
    end
  end
end
