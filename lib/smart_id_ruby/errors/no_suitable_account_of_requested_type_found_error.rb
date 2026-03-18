# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Thrown when user does not have a suitable account for the requested operation.
    # F.e. user has non-qualified account with ADVANCED certificate level,
    # but QUALIFIED certificate level is required for the operation.
    class NoSuitableAccountOfRequestedTypeFoundError < Error; end
  end
end
