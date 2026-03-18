# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Thrown when returned certificate level is lower than the requested certificate level.
    class CertificateLevelMismatchError < Error; end
  end
end
