# frozen_string_literal: true

require "faraday"

module SmartId
  module Rest
    # Minimal HTTP connector wrapper for Smart-ID RP API.
    class Connector
      attr_reader :host_url, :configured_connection, :network_connection_config, :ssl_context

      def initialize(host_url:, configured_connection: nil, network_connection_config: nil, ssl_context: nil)
        @host_url = host_url
        @configured_connection = configured_connection
        @network_connection_config = network_connection_config
        @ssl_context = ssl_context
        @session_status_response_socket_open_time = nil
      end

      def set_session_status_response_socket_open_time(unit, value)
        @session_status_response_socket_open_time = { unit: unit, value: value }
      end

      def session_status_response_socket_open_time
        @session_status_response_socket_open_time
      end
    end
  end
end
