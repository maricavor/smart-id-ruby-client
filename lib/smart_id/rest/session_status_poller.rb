# frozen_string_literal: true

module SmartId
  module Rest
    # Provides methods for querying session status and polling session status.
    class SessionStatusPoller
      def initialize(connector)
        @connector = connector
        @polling_sleep_time_unit = :seconds
        @polling_sleep_timeout = 1
      end

      def set_polling_sleep_time(unit, timeout)
        @polling_sleep_time_unit = unit
        @polling_sleep_timeout = timeout
      end

      def polling_sleep_time
        { unit: @polling_sleep_time_unit, timeout: @polling_sleep_timeout }
      end

      # TODO: implement real polling when session status endpoint handling is added.
      def fetch_final_session_status(_session_id)
        raise NotImplementedError, "session status polling is not implemented yet"
      end

      # TODO: implement real session status request handling.
      def get_session_status(_session_id)
        raise NotImplementedError, "session status query is not implemented yet"
      end
    end
  end
end
