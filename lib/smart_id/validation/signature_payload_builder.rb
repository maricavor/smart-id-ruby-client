# frozen_string_literal: true

require "base64"
require "openssl"

module SmartId
  module Validation
    # Builds ACSP_V2 signature payload used for authentication signature verification.
    class SignaturePayloadBuilder
      def build(session_status:, authentication_session_request:, schema_name:, brokered_rp_name: nil)
        signature_protocol_parameters = fetch_request_value(authentication_session_request, :signatureProtocolParameters)
        rp_challenge = fetch_hash_value(signature_protocol_parameters, :rpChallenge)
        relying_party_name = fetch_request_value(authentication_session_request, :relyingPartyName)
        interactions = fetch_request_value(authentication_session_request, :interactions)
        initial_callback_url = fetch_request_value(authentication_session_request, :initialCallbackUrl)
        flow_type = session_status.signature.flow_type

        payload_values = [
          schema_name,
          "ACSP_V2",
          session_status.signature.server_random,
          rp_challenge,
          session_status.signature.user_challenge || "",
          to_base64_utf8(relying_party_name),
          blank?(brokered_rp_name) ? "" : to_base64_utf8(brokered_rp_name),
          calculate_interactions_digest(interactions),
          session_status.interaction_type_used,
          flow_type == "QR" ? "" : initial_callback_url,
          flow_type
        ]
        payload_values.join("|")
      end

      private

      def calculate_interactions_digest(interactions)
        digest = OpenSSL::Digest::SHA256.digest(interactions.to_s)
        Base64.strict_encode64(digest)
      end

      def to_base64_utf8(input)
        Base64.strict_encode64(input.to_s.encode("UTF-8"))
      end

      def fetch_request_value(payload, key)
        return nil unless payload.respond_to?(:[])

        payload[key] || payload[key.to_s]
      end

      def fetch_hash_value(payload, key)
        return nil unless payload.respond_to?(:[])

        payload[key] || payload[key.to_s]
      end

      def blank?(value)
        value.nil? || value.to_s.strip.empty?
      end
    end
  end
end
