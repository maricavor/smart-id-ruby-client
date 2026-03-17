# frozen_string_literal: true

module SmartIdRuby
  module Errors
    class UserRefusedCertChoiceError < SessionEndResultError
      def initialize
        super("USER_REFUSED_CERT_CHOICE",
              "User has multiple accounts and pressed Cancel on device choice screen on any device.")
      end
    end
  end
end
