# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require "uri"

module SmartIdRuby
  module DeviceLinkType
    QR_CODE = "QR"
    WEB_2_APP = "Web2App"
    APP_2_APP = "App2App"
  end

  module SessionType
    AUTHENTICATION = "auth"
    SIGNATURE = "sign"
    CERTIFICATE_CHOICE = "cert"
  end

  # Builder for creating Smart-ID device-link URIs and auth codes.
  class DeviceLinkBuilder
    ALLOWED_VERSION = "1.0"
    DEFAULT_SCHEME_NAME = "smart-id"
    DEFAULT_LANGUAGE = "eng"
    SUPPORTED_DEVICE_LINK_TYPES = [
      DeviceLinkType::QR_CODE,
      DeviceLinkType::WEB_2_APP,
      DeviceLinkType::APP_2_APP
    ].freeze
    SUPPORTED_SESSION_TYPES = [
      SessionType::AUTHENTICATION,
      SessionType::SIGNATURE,
      SessionType::CERTIFICATE_CHOICE
    ].freeze

    def initialize
      @scheme_name = DEFAULT_SCHEME_NAME
      @version = ALLOWED_VERSION
      @lang = DEFAULT_LANGUAGE
      @device_link_base = nil
      @device_link_type = nil
      @session_type = nil
      @session_token = nil
      @elapsed_seconds = nil
      @digest = nil
      @relying_party_name_base64 = nil
      @brokered_rp_name_base64 = nil
      @interactions = nil
      @initial_callback_url = nil
    end

    def with_scheme_name(value)
      @scheme_name = value
      self
    end

    def with_device_link_base(value)
      @device_link_base = value
      self
    end

    def with_version(value)
      @version = value
      self
    end

    def with_device_link_type(value)
      @device_link_type = normalize_device_link_type(value)
      self
    end

    def with_session_type(value)
      @session_type = normalize_session_type(value)
      self
    end

    def with_session_token(value)
      @session_token = value
      self
    end

    def with_elapsed_seconds(value)
      @elapsed_seconds = value
      self
    end

    def with_lang(value)
      @lang = value
      self
    end

    def with_digest(value)
      @digest = value
      self
    end

    def with_relying_party_name(value)
      @relying_party_name_base64 = Base64.strict_encode64(value.to_s.dup.force_encoding("UTF-8"))
      self
    end

    def with_brokered_rp_name(value)
      @brokered_rp_name_base64 = Base64.strict_encode64(value.to_s.dup.force_encoding("UTF-8"))
      self
    end

    def with_interactions(value)
      @interactions = encode_interactions(value)
      self
    end

    def with_initial_callback_url(value)
      @initial_callback_url = value
      self
    end

    def create_unprotected_uri
      validate_input_parameters!

      query_params = [
        ["deviceLinkType", @device_link_type],
        ["sessionToken", @session_token],
        ["sessionType", @session_type],
        ["version", @version],
        ["lang", @lang]
      ]
      query_params << ["elapsedSeconds", @elapsed_seconds.to_s] unless @elapsed_seconds.nil?

      uri = append_query_params(@device_link_base, query_params)
      logger.debug("Created unprotected device link URI=#{sanitize_uri(uri)}")
      uri
    end

    def build_device_link(session_secret)
      unprotected_uri = create_unprotected_uri
      logger.debug("Building protected device link with scheme=#{@scheme_name}, session_type=#{@session_type}, device_link_type=#{@device_link_type}")
      auth_code = generate_auth_code(unprotected_uri.to_s, session_secret)
      uri = append_query_params(unprotected_uri.to_s, [["authCode", auth_code]])
      logger.debug("Built protected device link URI=#{sanitize_uri(uri)}")
      uri
    end

    private

    def validate_input_parameters!
      raise_request_setup_error("Parameter 'deviceLinkBase' cannot be empty") if blank?(@device_link_base)
      raise_request_setup_error("Parameter 'version' cannot be empty") if blank?(@version)
      raise_request_setup_error("Only version 1.0 is allowed") unless @version == ALLOWED_VERSION
      raise_request_setup_error("Parameter 'deviceLinkType' must be set") if blank?(@device_link_type)
      raise_request_setup_error("Parameter 'sessionType' must be set") if blank?(@session_type)
      raise_request_setup_error("Parameter 'sessionToken' cannot be empty") if blank?(@session_token)
      raise_request_setup_error("Parameter 'lang' must be set") if blank?(@lang)

      if @device_link_type == DeviceLinkType::QR_CODE && @elapsed_seconds.nil?
        raise_request_setup_error("Parameter 'elapsedSeconds' must be set when 'deviceLinkType' is QR_CODE")
      end
      if @device_link_type != DeviceLinkType::QR_CODE && !@elapsed_seconds.nil?
        raise_request_setup_error("Parameter 'elapsedSeconds' should only be used when 'deviceLinkType' is QR_CODE")
      end
    end

    def validate_auth_code_params!
      raise_request_setup_error("Parameter 'schemeName' cannot be empty") if blank?(@scheme_name)
      raise_request_setup_error("Parameter 'relyingPartyName' cannot be empty") if blank?(@relying_party_name_base64)

      has_callback = !blank?(@initial_callback_url)
      if @device_link_type == DeviceLinkType::QR_CODE && has_callback
        raise_request_setup_error("Parameter 'initialCallbackUrl' must be empty when 'deviceLinkType' is QR_CODE")
      end
      if [DeviceLinkType::APP_2_APP, DeviceLinkType::WEB_2_APP].include?(@device_link_type) && !has_callback
        raise_request_setup_error("Parameter 'initialCallbackUrl' must be provided when 'deviceLinkType' is APP_2_APP or WEB_2_APP")
      end

      if [SessionType::AUTHENTICATION, SessionType::SIGNATURE].include?(@session_type)
        raise_request_setup_error("Parameter 'digest' must be set when 'sessionType' is AUTHENTICATION or SIGNATURE") if blank?(@digest)
        raise_request_setup_error("Parameter 'interactions' must be set when 'sessionType' is AUTHENTICATION or SIGNATURE") if blank?(@interactions)
      end

      if @session_type == SessionType::CERTIFICATE_CHOICE
        raise_request_setup_error("Parameter 'digest' must be empty when 'sessionType' is CERTIFICATE_CHOICE") unless blank?(@digest)
        raise_request_setup_error("Parameter 'interactions' must be empty when 'sessionType' is CERTIFICATE_CHOICE") unless blank?(@interactions)
      end
    end

    def generate_auth_code(unprotected_link, session_secret_base64)
      raise_request_setup_error("Parameter 'sessionSecret' cannot be empty") if blank?(session_secret_base64)

      validate_auth_code_params!

      payload = [
        @scheme_name,
        signature_protocol_for_session,
        or_empty(@digest),
        @relying_party_name_base64,
        or_empty(@brokered_rp_name_base64),
        or_empty(@interactions),
        or_empty(@initial_callback_url),
        unprotected_link
      ].join("|")
      logger.debug("Generating authCode payload metadata scheme=#{@scheme_name},
        protocol=#{signature_protocol_for_session}, has_digest=#{!blank?(@digest)},
        has_interactions=#{!blank?(@interactions)}, has_callback=#{!blank?(@initial_callback_url)}")

      session_secret = Base64.decode64(session_secret_base64)
      hmac = OpenSSL::HMAC.digest(
        "SHA256", session_secret, payload
      )
      Base64.urlsafe_encode64(hmac).sub(/=*$/, '')
    rescue OpenSSL::HMACError, ArgumentError => e
      raise SmartIdRuby::Errors::RequestSetupError, "Failed to calculate authCode: #{e.message}"
    end

    def signature_protocol_for_session
      case @session_type
      when SessionType::AUTHENTICATION then "ACSP_V2"
      when SessionType::SIGNATURE then "RAW_DIGEST_SIGNATURE"
      when SessionType::CERTIFICATE_CHOICE then ""
      else ""
      end
    end

    def append_query_params(base_url, new_params)
      uri = URI.parse(base_url.to_s)
      params = URI.decode_www_form(uri.query.to_s)
      params.concat(new_params)
      uri.query = URI.encode_www_form(params)
      uri
    end

    def encode_interactions(value)
      return nil if value.nil?
      return value if value.is_a?(String)

      interactions = Array(value).compact.map do |interaction|
        if interaction.respond_to?(:to_h)
          interaction.to_h
        elsif interaction.is_a?(Hash)
          interaction
        else
          raise_request_setup_error("Unsupported interaction object type: #{interaction.class}")
        end
      end

      Base64.strict_encode64(JSON.generate(interactions))
    end

    def normalize_device_link_type(value)
      return value if value.nil?

      normalized = value.to_s
      return normalized if SUPPORTED_DEVICE_LINK_TYPES.include?(normalized)

      raise_request_setup_error("Unsupported device link type: #{value}")
    end

    def normalize_session_type(value)
      return value if value.nil?

      normalized = value.to_s
      return normalized if SUPPORTED_SESSION_TYPES.include?(normalized)

      raise_request_setup_error("Unsupported session type: #{value}")
    end

    def or_empty(value)
      value.nil? ? "" : value
    end

    def blank?(value)
      value.nil? || value.to_s.strip.empty?
    end

    def raise_request_setup_error(message)
      raise SmartIdRuby::Errors::RequestSetupError, message
    end

    def logger
      SmartIdRuby.logger
    end

    def sanitize_uri(uri)
      parsed = URI.parse(uri.to_s)
      query = URI.decode_www_form(parsed.query.to_s).map do |key, value|
        [key, sensitive_param?(key) ? "[FILTERED]" : value]
      end
      parsed.query = URI.encode_www_form(query)
      parsed.to_s
    rescue StandardError
      uri.to_s
    end

    def sensitive_param?(name)
      %w[sessionToken authCode].include?(name.to_s)
    end
  end
end
