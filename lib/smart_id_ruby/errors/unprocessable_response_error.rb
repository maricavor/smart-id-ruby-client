# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Thrown when validation of any Smart-ID API responses fail.
    # This includes responses for session initialization requests and session status responses.
    class UnprocessableResponseError < Error; end
  end
end
