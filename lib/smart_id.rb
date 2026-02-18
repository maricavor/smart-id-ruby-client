# frozen_string_literal: true

require "json"
require "logger"
require "openssl"

module SmartId
  class Error < StandardError; end

  class << self
    attr_writer :logger

    def logger
      @logger ||= Logger.new($stdout).tap do |instance|
        instance.progname = "smart_id"
        instance.level = Logger::WARN
      end
    end
  end
end

require_relative "smart_id/version"
require_relative "smart_id/errors"
require_relative "smart_id/client"
require_relative "smart_id/device_link_builder"
require_relative "smart_id/rest/connector"
require_relative "smart_id/rest/session_status_poller"
require_relative "smart_id/models/authentication_response"
require_relative "smart_id/models/session_status"
require_relative "smart_id/flows/base_builder"
require_relative "smart_id/flows/device_link_authentication_session_request_builder"
require_relative "smart_id/flows/notification_authentication_session_request_builder"
require_relative "smart_id/flows/device_link_signature_session_request_builder"
require_relative "smart_id/flows/notification_signature_session_request_builder"
require_relative "smart_id/flows/device_link_certificate_choice_session_request_builder"
require_relative "smart_id/flows/notification_certificate_choice_session_request_builder"
require_relative "smart_id/flows/linked_notification_signature_session_request_builder"
require_relative "smart_id/flows/certificate_by_document_number_request_builder"
require_relative "smart_id/validation/signature_value_validator"
require_relative "smart_id/validation/signature_payload_builder"
require_relative "smart_id/validation/authentication_certificate_validator"
require_relative "smart_id/validation/device_link_authentication_response_validator"