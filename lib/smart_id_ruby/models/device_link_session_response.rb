# frozen_string_literal: true

module SmartIdRuby
  module Models
    # Represents device-link session initialization response.
    class DeviceLinkSessionResponse
      attr_reader :session_id, :session_token, :session_secret, :device_link_base, :received_at

      def initialize(session_id:, session_token:, session_secret:, device_link_base:, received_at: Time.now)
        @session_id = session_id
        @session_token = session_token
        @session_secret = session_secret
        @device_link_base = device_link_base
        @received_at = received_at
      end

      def self.from_h(payload)
        return payload if payload.is_a?(self)
        return new(session_id: nil, session_token: nil, session_secret: nil, device_link_base: nil) unless payload.is_a?(Hash)

        new(
          session_id: fetch(payload, :sessionID),
          session_token: fetch(payload, :sessionToken),
          session_secret: fetch(payload, :sessionSecret),
          device_link_base: fetch(payload, :deviceLinkBase)
        )
      end

      def self.fetch(payload, key)
        payload[key] || payload[key.to_s]
      end
    end
  end
end
