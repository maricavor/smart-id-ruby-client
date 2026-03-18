# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Thrown when session with the given session ID could not be found.
    class SessionNotFoundError < Error; end
  end
end
