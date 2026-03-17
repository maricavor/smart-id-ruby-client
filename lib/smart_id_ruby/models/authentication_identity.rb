# frozen_string_literal: true

module SmartIdRuby
  module Models
    # Represents mapped identity details from authentication certificate.
    class AuthenticationIdentity
      attr_reader :given_name, :surname, :identity_number, :country, :auth_certificate, :date_of_birth

      def initialize(given_name: nil, surname: nil, identity_number: nil, country: nil, auth_certificate: nil, date_of_birth: nil)
        @given_name = given_name
        @surname = surname
        @identity_number = identity_number
        @country = country
        @auth_certificate = auth_certificate
        @date_of_birth = date_of_birth
      end
    end
  end
end
