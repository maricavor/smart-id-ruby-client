# frozen_string_literal: true

module SmartIdRuby
  module Models
    # Represents notification-based signature session initialization response.
    class NotificationSignatureSessionResponse
      attr_reader :session_id, :vc

      def initialize(session_id:, vc:)
        @session_id = session_id
        @vc = vc
      end

      def self.from_h(payload)
        return payload if payload.is_a?(self)
        return new(session_id: nil, vc: nil) unless payload.is_a?(Hash)

        new(
          session_id: fetch(payload, :sessionID),
          vc: fetch(payload, :vc)
        )
      end

      def self.fetch(payload, key)
        payload[key] || payload[key.to_s]
      end
    end
  end
end
