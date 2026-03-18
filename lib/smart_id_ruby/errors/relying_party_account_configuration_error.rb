# frozen_string_literal: true

module SmartIdRuby
  module Errors
    # Exception will be thrown when there are problems with relying party account and access configuration
    # or when relying party does not have access to the requested service.
    # F.e. Request is made with relying party UUID and incorrect relying party name.
    class RelyingPartyAccountConfigurationError < Error; end
  end
end
