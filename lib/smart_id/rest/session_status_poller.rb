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
        logger.debug("Setting polling sleep time to #{timeout} #{unit}")
        @polling_sleep_time_unit = unit
        @polling_sleep_timeout = timeout
      end

      def polling_sleep_time
        { unit: @polling_sleep_time_unit, timeout: @polling_sleep_timeout }
      end

      # Loops session status query until state is COMPLETE.
      def fetch_final_session_status(session_id)
        logger.debug("Starting to poll session status for session #{session_id}")
        poll_for_final_session_status(session_id)
      rescue Interrupt => e
        logger.error("Failed to poll session status: #{e.message}")
        raise SmartId::Error, "Failed to poll session status"
      end

      # Query session status once.
      def get_session_status(session_id)
        logger.debug("Querying session status")
        @connector.get_session_status(session_id)
      end

      private

      def poll_for_final_session_status(session_id)
        session_status = nil
        while session_status.nil? || running?(session_status)
          session_status = get_session_status(session_id)
          break if complete?(session_status)

          logger.debug("Sleeping for #{@polling_sleep_timeout} #{@polling_sleep_time_unit}")
          sleep_for_poll_interval
        end
        logger.debug("Got final session status response")
        session_status
      end

      def running?(session_status)
        session_state(session_status)&.casecmp("RUNNING")&.zero?
      end

      def complete?(session_status)
        session_state(session_status)&.casecmp("COMPLETE")&.zero?
      end

      def session_state(session_status)
        if session_status.respond_to?(:[])
          session_status[:state] || session_status["state"]
        elsif session_status.respond_to?(:state)
          session_status.state
        end
      end

      def sleep_for_poll_interval
        seconds = poll_interval_in_seconds
        return if seconds <= 0

        sleep(seconds)
      end

      def poll_interval_in_seconds
        timeout = @polling_sleep_timeout.to_f
        return 0 if timeout <= 0

        case @polling_sleep_time_unit&.to_sym
        when :milliseconds
          timeout / 1000.0
        when :seconds
          timeout
        when :minutes
          timeout * 60
        when :hours
          timeout * 3600
        else
          timeout
        end
      end

      def logger
        SmartId.logger
      end
    end
  end
end
