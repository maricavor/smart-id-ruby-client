module SmartId::Api
  module Authentication
    class ConfirmationPoller
      BASE_URI = "session/".freeze
      RUNNING_STATE = "RUNNING".freeze

      def self.confirm(session_id:, authentication_hash:, certificate_level:, poll: true)
        new(session_id, authentication_hash, certificate_level, poll).call
      end

      def initialize(session_id, authentication_hash, certificate_level, poll)
        @session_id = session_id
        @authentication_hash = authentication_hash
        @certificate_level = certificate_level
        @poll = poll
      end

      def call
        params = { timeoutMs: SmartId.poller_timeout_seconds * 1000 }
        uri = BASE_URI + @session_id

        raw_response = SmartId::Api::Request.execute(method: :get, uri: uri, params: params)
        response = JSON.parse(raw_response.body)

        # repeat request if confirmation is still running
        if response["state"] == RUNNING_STATE && @poll
          call
        else
          SmartId::Api::ConfirmationResponse.new(
            response,
            @authentication_hash.hash_data,
            @certificate_level
          )
        end
      end
    end
  end
end
