require "smart_id/api/authentication/base"

module SmartId::Api
  module Authentication
    class IdentityNumber < Base
      BASE_URI = "authentication/etsi".freeze

      # @param country: 2 character ISO 3166-1 alpha-2 format(for example EE, LT, LV, KZ)
      # @param identity_number: national identity number of the individuals
      def initialize(**opts)
        @country = opts[:country].upcase
        @identity_number = opts[:identity_number]
        @semantics_identifier = opts[:semantics_identifier]

        unless @country && @identity_number && @semantics_identifier
          raise SmartId::InvalidParamsError
        end

        super(**opts)
      end

      private

      def api_uri
        "#{BASE_URI}/#{@semantics_identifier.identifier}"
      end
    end
  end
end
