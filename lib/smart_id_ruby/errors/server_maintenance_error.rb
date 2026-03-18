# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Thrown when request cannot be process because the Smart-ID API server is under maintenance.
    class ServerMaintenanceError < Error; end
  end
end
