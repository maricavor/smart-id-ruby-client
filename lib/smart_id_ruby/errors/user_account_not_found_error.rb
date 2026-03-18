# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Thrown when user account does not exist with the given identifier or document number.
    class UserAccountNotFoundError < Error; end
  end
end
