# frozen_string_literal: true

module SmartIdRuby
  module Models
    # Represents notification-based certificate choice session initialization response.
    class NotificationCertificateChoiceSessionResponse
      attr_reader :session_id

      def initialize(session_id:)
        @session_id = session_id
      end

      def self.from_h(payload)
        return payload if payload.is_a?(self)
        return new(session_id: nil) unless payload.is_a?(Hash)

        new(session_id: fetch(payload, :sessionID))
      end

      def self.fetch(payload, key)
        payload[key] || payload[key.to_s]
      end
    end
  end
end
