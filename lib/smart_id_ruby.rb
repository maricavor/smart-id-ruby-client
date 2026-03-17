# frozen_string_literal: true

require "json"
require "logger"
require "openssl"
require_relative "smart_id_ruby/configuration"

#
# Top-level namespace for the Smart-ID Ruby client library.
# Provides configuration, logging, and access to Smart-ID API flows and models.
module SmartIdRuby
  class Error < StandardError; end

  extend Configuration

  class << self
    attr_writer :logger

    def logger
      @logger ||= if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
                    Rails.logger
                  else
                    Logger.new($stdout).tap do |instance|
                      instance.progname = "smart_id"
                      instance.level = Logger::WARN
                    end
                  end
    end
  end
end

require_relative "smart_id_ruby/version"
require_relative "smart_id_ruby/errors"
require_relative "smart_id_ruby/client"
require_relative "smart_id_ruby/rp_challenge"
require_relative "smart_id_ruby/rp_challenge_generator"
require_relative "smart_id_ruby/callback_url"
require_relative "smart_id_ruby/callback_url_util"
require_relative "smart_id_ruby/device_link_builder"
require_relative "smart_id_ruby/qr_code_generator"
require_relative "smart_id_ruby/device_link_interaction"
require_relative "smart_id_ruby/notification_interaction"
require_relative "smart_id_ruby/rest/connector"
require_relative "smart_id_ruby/rest/session_status_poller"
require_relative "smart_id_ruby/models/authentication_response"
require_relative "smart_id_ruby/models/authentication_identity"
require_relative "smart_id_ruby/models/device_link_session_response"
require_relative "smart_id_ruby/models/signature_response"
require_relative "smart_id_ruby/models/certificate_choice_response"
require_relative "smart_id_ruby/models/session_status"
require_relative "smart_id_ruby/flows/base_builder"
require_relative "smart_id_ruby/flows/device_link_authentication_session_request_builder"
require_relative "smart_id_ruby/flows/notification_authentication_session_request_builder"
require_relative "smart_id_ruby/flows/device_link_signature_session_request_builder"
require_relative "smart_id_ruby/flows/notification_signature_session_request_builder"
require_relative "smart_id_ruby/flows/device_link_certificate_choice_session_request_builder"
require_relative "smart_id_ruby/flows/notification_certificate_choice_session_request_builder"
require_relative "smart_id_ruby/flows/linked_notification_signature_session_request_builder"
require_relative "smart_id_ruby/flows/certificate_by_document_number_request_builder"
require_relative "smart_id_ruby/validation/signature_value_validator"
require_relative "smart_id_ruby/validation/signature_payload_builder"
require_relative "smart_id_ruby/validation/trusted_ca_cert_store"
require_relative "smart_id_ruby/validation/certificate_validator"
require_relative "smart_id_ruby/validation/authentication_certificate_validator"
require_relative "smart_id_ruby/validation/authentication_identity_mapper"
require_relative "smart_id_ruby/validation/error_result_handler"
require_relative "smart_id_ruby/validation/device_link_authentication_response_validator"
require_relative "smart_id_ruby/validation/notification_authentication_response_validator"
require_relative "smart_id_ruby/validation/signature_response_validator"
require_relative "smart_id_ruby/validation/certificate_choice_response_validator"
