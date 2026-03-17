# frozen_string_literal: true

module SmartIdRuby
  module Errors
    class UserAccountUnusableError < SessionEndResultError
      def initialize
        super("ACCOUNT_UNUSABLE", "The account is currently unusable")
      end
    end
  end
end
