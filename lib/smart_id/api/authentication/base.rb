require "rest-client"
require "smart_id/exceptions"
require "smart_id/utils/authentication_hash"
require "json"

module SmartId::Api
  module Authentication
    class Base
      attr_reader :authentication_hash, :certificate_level

      def self.authenticate(**opts)
        new(**opts).call
      end

      def initialize(**opts)
        @authentication_hash = opts[:authentication_hash]
        @certificate_level = opts[:certificate_level]
        @allowed_interactions_order = opts[:allowed_interactions_order]
      end

      def call
        response = SmartId::Api::Request.execute(method: :post, uri: api_uri, params: request_params)
        SmartId::Api::Response.new(JSON.parse(response.body), authentication_hash, certificate_level)
      end

      private

      def request_params
        params = {
          relyingPartyUUID: SmartId.relying_party_uuid,
          relyingPartyName: SmartId.relying_party_name,
          certificateLevel: @certificate_level || SmartId.default_certificate_level,
          hash: authentication_hash.calculate_base64_digest,
          hashType: "SHA256"
        }

        if @allowed_interactions_order
          params.merge!(allowedInteractionsOrder: @allowed_interactions_order.map(&:serialize))
        end

        params
      end

      def api_uri
        raise NotImplementedError
      end
    end
  end
end
