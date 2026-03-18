# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Exception thrown when there is an issue setting up a Smart-ID request.
    # This could be due to invalid parameters, configuration issues, or other
    # problems that prevent from successfully preparing the request.
    class RequestSetupError < Error; end
  end
end
