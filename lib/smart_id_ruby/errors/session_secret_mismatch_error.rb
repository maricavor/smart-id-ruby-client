# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Thrown when the session secret digest from the callback does not match the calculated digest.
    class SessionSecretMismatchError < Error; end
  end
end
