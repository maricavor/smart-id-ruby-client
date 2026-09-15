# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Raised when a request to the Smart-ID API times out at the transport level.
    #
    # Distinct from SessionTimeoutError, which means the *user* did not respond in time and
    # is reported by the API as a TIMEOUT end result. This one says nothing about the
    # session — a long-poll session status request that times out is expected, and the
    # caller should poll again.
    class NetworkTimeoutError < Error
      def initialize(message = "Request to Smart-ID API timed out")
        super
      end
    end
  end
end
