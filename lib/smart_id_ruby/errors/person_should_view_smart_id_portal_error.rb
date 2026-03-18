# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Thrown when Smart-ID API indicates that there is an issue with user document and user should check its state.
    class PersonShouldViewSmartIdPortalError < Error; end
  end
end
