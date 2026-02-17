# frozen_string_literal: true

require "json"
require "openssl"

require_relative "smart_id/version"
require_relative "smart_id/client"
require_relative "smart_id/device_link_builder"
require_relative "smart_id/rest/connector"
require_relative "smart_id/rest/session_status_poller"
require_relative "smart_id/flows/base_builder"
require_relative "smart_id/flows/device_link_authentication_session_request_builder"
require_relative "smart_id/flows/notification_authentication_session_request_builder"
require_relative "smart_id/flows/device_link_signature_session_request_builder"
require_relative "smart_id/flows/notification_signature_session_request_builder"
require_relative "smart_id/flows/device_link_certificate_choice_session_request_builder"
require_relative "smart_id/flows/notification_certificate_choice_session_request_builder"
require_relative "smart_id/flows/linked_notification_signature_session_request_builder"
require_relative "smart_id/flows/certificate_by_document_number_request_builder"

module SmartId
  class Error < StandardError; end
end
