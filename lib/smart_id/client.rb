# frozen_string_literal: true

module SmartId
  # Main entry point for using Smart-ID services.
  # Mirrors the Java SmartIdClient surface so v3 flows can be added incrementally.
  class Client
    attr_accessor :relying_party_uuid, :relying_party_name, :host_url,
                  :network_connection_config, :configured_connection

    def initialize
      @polling_sleep_timeout = 1
      @polling_sleep_time_unit = :seconds
      @session_status_response_socket_open_time = nil
      @connector = nil
      @session_status_poller = nil
      @ssl_context = nil
    end

    def create_device_link_certificate_request
      Flows::DeviceLinkCertificateChoiceSessionRequestBuilder.new(smart_id_connector)
        .with_relying_party_uuid(relying_party_uuid)
        .with_relying_party_name(relying_party_name)
    end

    def create_linked_notification_signature
      Flows::LinkedNotificationSignatureSessionRequestBuilder.new(smart_id_connector)
        .with_relying_party_uuid(relying_party_uuid)
        .with_relying_party_name(relying_party_name)
    end

    def create_notification_certificate_choice
      Flows::NotificationCertificateChoiceSessionRequestBuilder.new(smart_id_connector)
        .with_relying_party_uuid(relying_party_uuid)
        .with_relying_party_name(relying_party_name)
    end

    def create_device_link_authentication
      Flows::DeviceLinkAuthenticationSessionRequestBuilder.new(smart_id_connector)
        .with_relying_party_uuid(relying_party_uuid)
        .with_relying_party_name(relying_party_name)
    end

    def create_notification_authentication
      Flows::NotificationAuthenticationSessionRequestBuilder.new(smart_id_connector)
        .with_relying_party_uuid(relying_party_uuid)
        .with_relying_party_name(relying_party_name)
    end

    def create_device_link_signature
      Flows::DeviceLinkSignatureSessionRequestBuilder.new(smart_id_connector)
        .with_relying_party_uuid(relying_party_uuid)
        .with_relying_party_name(relying_party_name)
    end

    def create_certificate_by_document_number
      Flows::CertificateByDocumentNumberRequestBuilder.new(smart_id_connector)
        .with_relying_party_uuid(relying_party_uuid)
        .with_relying_party_name(relying_party_name)
    end

    def create_notification_signature
      Flows::NotificationSignatureSessionRequestBuilder.new(smart_id_connector)
        .with_relying_party_uuid(relying_party_uuid)
        .with_relying_party_name(relying_party_name)
    end

    def session_status_poller
      @session_status_poller ||= begin
        poller = Rest::SessionStatusPoller.new(smart_id_connector)
        poller.set_polling_sleep_time(@polling_sleep_time_unit, @polling_sleep_timeout)
        poller
      end
    end

    def create_dynamic_content
      DeviceLinkBuilder.new.with_relying_party_name(relying_party_name)
    end

    def set_polling_sleep_timeout(unit, timeout)
      @polling_sleep_time_unit = unit
      @polling_sleep_timeout = timeout
      return unless @session_status_poller

      @session_status_poller.set_polling_sleep_time(unit, timeout)
    end

    def set_session_status_response_socket_open_time(unit, value)
      @session_status_response_socket_open_time = { unit: unit, value: value }
      return unless @connector

      @connector.set_session_status_response_socket_open_time(unit, value)
    end

    def trust_ssl_context=(ssl_context)
      @ssl_context = ssl_context
      @connector = nil
    end

    def smart_id_connector
      @connector ||= begin
        connector = Rest::Connector.new(
          host_url: host_url,
          configured_connection: configured_connection,
          network_connection_config: network_connection_config,
          ssl_context: @ssl_context
        )

        if @session_status_response_socket_open_time
          connector.set_session_status_response_socket_open_time(
            @session_status_response_socket_open_time[:unit],
            @session_status_response_socket_open_time[:value]
          )
        end

        connector
      end
    end
  end
end
