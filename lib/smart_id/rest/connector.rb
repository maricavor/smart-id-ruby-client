# frozen_string_literal: true

require "cgi"
require "faraday"
require "uri"

module SmartId
  module Rest
    # Smart-ID REST connector implementation for RP API v3.1.
    class Connector
      SESSION_STATUS_PATH = "session/%<session_id>s"

      DEVICE_LINK_CERTIFICATE_CHOICE_DEVICE_LINK_PATH = "signature/certificate-choice/device-link/anonymous"
      LINKED_NOTIFICATION_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH = "signature/notification/linked/%<document_number>s"
      NOTIFICATION_CERTIFICATE_CHOICE_WITH_SEMANTIC_IDENTIFIER_PATH = "signature/certificate-choice/notification/etsi/%<semantics_identifier>s"
      CERTIFICATE_BY_DOCUMENT_NUMBER_PATH = "signature/certificate/%<document_number>s"
      DEVICE_LINK_SIGNATURE_WITH_SEMANTIC_IDENTIFIER_PATH = "signature/device-link/etsi/%<semantics_identifier>s"
      DEVICE_LINK_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH = "signature/device-link/document/%<document_number>s"
      NOTIFICATION_SIGNATURE_WITH_SEMANTIC_IDENTIFIER_PATH = "signature/notification/etsi/%<semantics_identifier>s"
      NOTIFICATION_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH = "signature/notification/document/%<document_number>s"
      ANONYMOUS_DEVICE_LINK_AUTHENTICATION_PATH = "authentication/device-link/anonymous"
      DEVICE_LINK_AUTHENTICATION_WITH_SEMANTIC_IDENTIFIER_PATH = "authentication/device-link/etsi/%<semantics_identifier>s"
      DEVICE_LINK_AUTHENTICATION_WITH_DOCUMENT_NUMBER_PATH = "authentication/device-link/document/%<document_number>s"
      NOTIFICATION_AUTHENTICATION_WITH_SEMANTIC_IDENTIFIER_PATH = "authentication/notification/etsi/%<semantics_identifier>s"
      NOTIFICATION_AUTHENTICATION_WITH_DOCUMENT_NUMBER_PATH = "authentication/notification/document/%<document_number>s"

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

      def set_ssl_context(ssl_context)
        @ssl_context = ssl_context
        @connection = nil
      end

      def get_session_status(session_id)
        logger.debug("Getting session status for sessionId: #{session_id}")
        query = {}
        if @session_status_response_socket_open_time && @session_status_response_socket_open_time[:value].to_i.positive?
          query["timeoutMs"] = to_milliseconds(
            @session_status_response_socket_open_time[:unit],
            @session_status_response_socket_open_time[:value]
          )
        end

        path = format(SESSION_STATUS_PATH, session_id: encode_path_segment(session_id))
        response = get(path, query: query, not_found_error: SmartId::Errors::SessionNotFoundError)
        SmartId::Models::SessionStatus.from_h(response)
      end

      def init_device_link_authentication(authentication_request, semantics_identifier)
        logger.debug("Starting device link authentication session with semantics identifier")
        path = format(
          DEVICE_LINK_AUTHENTICATION_WITH_SEMANTIC_IDENTIFIER_PATH,
          semantics_identifier: encode_path_segment(extract_identifier(semantics_identifier))
        )
        post(path, body: authentication_request)
      end

      def init_device_link_authentication_with_document(authentication_request, document_number)
        logger.debug("Starting device link authentication session with document number")
        path = format(
          DEVICE_LINK_AUTHENTICATION_WITH_DOCUMENT_NUMBER_PATH,
          document_number: encode_path_segment(document_number)
        )
        post(path, body: authentication_request)
      end

      def init_anonymous_device_link_authentication(authentication_request)
        logger.debug("Starting anonymous device link authentication session")
        post(ANONYMOUS_DEVICE_LINK_AUTHENTICATION_PATH, body: authentication_request)
      end

      def init_notification_authentication(authentication_request, semantics_identifier)
        logger.debug("Starting notification authentication session with semantics identifier")
        path = format(
          NOTIFICATION_AUTHENTICATION_WITH_SEMANTIC_IDENTIFIER_PATH,
          semantics_identifier: encode_path_segment(extract_identifier(semantics_identifier))
        )
        post(path, body: authentication_request)
      end

      def init_notification_authentication_with_document(authentication_request, document_number)
        logger.debug("Starting notification authentication session with document number")
        path = format(
          NOTIFICATION_AUTHENTICATION_WITH_DOCUMENT_NUMBER_PATH,
          document_number: encode_path_segment(document_number)
        )
        post(path, body: authentication_request)
      end

      def init_device_link_certificate_choice(request)
        logger.debug("Initiating device link based certificate choice request")
        post(DEVICE_LINK_CERTIFICATE_CHOICE_DEVICE_LINK_PATH, body: request)
      end

      def init_linked_notification_signature(request, document_number)
        logger.debug("Starting linked notification-based signature session")
        path = format(
          LINKED_NOTIFICATION_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH,
          document_number: encode_path_segment(document_number)
        )
        post(path, body: request)
      end

      def init_notification_certificate_choice(request, semantics_identifier)
        logger.debug("Starting notification-based certificate choice session")
        path = format(
          NOTIFICATION_CERTIFICATE_CHOICE_WITH_SEMANTIC_IDENTIFIER_PATH,
          semantics_identifier: encode_path_segment(extract_identifier(semantics_identifier))
        )
        post(path, body: request)
      end

      def get_certificate_by_document_number(document_number, request)
        logger.debug("Querying certificate by document number")
        path = format(CERTIFICATE_BY_DOCUMENT_NUMBER_PATH, document_number: encode_path_segment(document_number))
        post(path, body: request)
      end

      def init_device_link_signature(request, semantics_identifier)
        logger.debug("Starting device link signature session with semantics identifier")
        path = format(
          DEVICE_LINK_SIGNATURE_WITH_SEMANTIC_IDENTIFIER_PATH,
          semantics_identifier: encode_path_segment(extract_identifier(semantics_identifier))
        )
        post(path, body: request)
      end

      def init_device_link_signature_with_document(request, document_number)
        logger.debug("Starting device link signature session with document number")
        path = format(
          DEVICE_LINK_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH,
          document_number: encode_path_segment(document_number)
        )
        post(path, body: request)
      end

      def init_notification_signature(request, semantics_identifier)
        logger.debug("Starting notification signature session with semantics identifier")
        path = format(
          NOTIFICATION_SIGNATURE_WITH_SEMANTIC_IDENTIFIER_PATH,
          semantics_identifier: encode_path_segment(extract_identifier(semantics_identifier))
        )
        post(path, body: request)
      end

      def init_notification_signature_with_document(request, document_number)
        logger.debug("Starting notification signature session with document number")
        path = format(
          NOTIFICATION_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH,
          document_number: encode_path_segment(document_number)
        )
        post(path, body: request)
      end

      private

      def connection
        @connection ||= begin
          if configured_connection
            configured_connection
          else
            Faraday.new(url: host_url, ssl: ssl_options) do |faraday|
              apply_connection_config(faraday)
              faraday.adapter Faraday.default_adapter
            end
          end
        end
      end

      def ssl_options
        options = { verify: true }
        return options unless ssl_context.respond_to?(:cert_store)

        cert_store = ssl_context.cert_store
        options[:cert_store] = cert_store if cert_store
        options
      end

      def apply_connection_config(faraday)
        return unless network_connection_config.is_a?(Hash)

        headers = network_connection_config[:headers]
        faraday.headers.update(headers) if headers.is_a?(Hash)

        request_opts = network_connection_config[:request]
        configure_request_options(faraday.options, request_opts) if request_opts.is_a?(Hash)

        configure_request_options(faraday.options, network_connection_config)
      end

      def configure_request_options(options, config)
        timeout = config[:timeout]
        open_timeout = config[:open_timeout]
        write_timeout = config[:write_timeout]

        options.timeout = timeout if timeout
        options.open_timeout = open_timeout if open_timeout
        options.write_timeout = write_timeout if write_timeout && options.respond_to?(:write_timeout=)
      end

      def get(path, query:, not_found_error: nil)
        response = perform_request(:get, path, query: query)
        parse_response(response)
      rescue Faraday::ResourceNotFound
        logger.warn("Session or resource not found for path #{path}")
        raise(not_found_error || SmartId::Errors::UserAccountNotFoundError)
      rescue Faraday::UnauthorizedError, Faraday::ForbiddenError => e
        logger.warn("Request is unauthorized for path #{path}: #{e.message}")
        raise SmartId::Errors::RelyingPartyAccountConfigurationError, e.message
      rescue Faraday::ClientError => e
        handle_client_error(e)
      rescue Faraday::ServerError => e
        handle_server_error(e)
      end

      def post(path, body:)
        response = perform_request(:post, path, body: body)
        parse_response(response)
      rescue Faraday::ResourceNotFound
        logger.warn("User account not found for path #{path}")
        raise SmartId::Errors::UserAccountNotFoundError
      rescue Faraday::UnauthorizedError, Faraday::ForbiddenError => e
        logger.warn("No permission to issue request for path #{path}: #{e.message}")
        raise SmartId::Errors::RelyingPartyAccountConfigurationError, e.message
      rescue Faraday::BadRequestError => e
        logger.warn("Request is invalid for path #{path}: #{e.message}")
        raise SmartId::Errors::RequestValidationError, e.message
      rescue Faraday::ClientError => e
        handle_client_error(e)
      rescue Faraday::ServerError => e
        handle_server_error(e)
      end

      def perform_request(method, path, query: nil, body: nil)
        url = build_url(path)
        headers = default_headers
        logger.debug("#{method.to_s.upcase} #{url}")

        response = if method == :get
                     connection.get(url, query, headers)
        else
                     connection.post(url, JSON.generate(body), headers)
                   end
        logger.debug("Response status: #{response.status}")
        response
      end

      def build_url(path)
        normalized_path = path.to_s.sub(%r{\A/+}, "")
        URI.join(host_url, normalized_path).to_s
      end

      def default_headers
        {
          "Accept" => "application/json",
          "Content-Type" => "application/json",
          "User-Agent" => "smart_id/#{SmartId::VERSION} (Ruby/#{RUBY_VERSION})"
        }
      end

      def parse_response(response)
        return {} if response.body.nil? || response.body.to_s.strip.empty?
        return response.body if response.body.is_a?(Hash)

        JSON.parse(response.body)
      rescue JSON::ParserError => e
        raise SmartId::Errors::ResponseError, "Failed to parse Smart-ID response body: #{e.message}"
      end

      def handle_client_error(error)
        status = error.response[:status].to_i
        case status
        when 471
          logger.warn("No suitable account of requested type found, but user has some other accounts")
          raise SmartId::Errors::NoSuitableAccountOfRequestedTypeFoundError
        when 472
          logger.warn("Person should view Smart-ID app or Smart-ID self-service portal now")
          raise SmartId::Errors::PersonShouldViewSmartIdPortalError
        when 480
          logger.warn("Client-side API is too old and not supported anymore")
          raise SmartId::Errors::UnsupportedClientApiVersionError
        else
          logger.warn("Server refused the request: #{error.message}")
          raise SmartId::Errors::RequestValidationError, error.message
        end
      end

      def handle_server_error(error)
        status = error.response[:status].to_i
        if status == 580
          logger.warn("Server is under maintenance, retry later")
          raise SmartId::Errors::ServerMaintenanceError
        end

        logger.warn("Unexpected server error: #{error.message}")
        raise SmartId::Errors::ResponseError, error.message
      end

      def extract_identifier(semantics_identifier)
        return semantics_identifier.identifier if semantics_identifier.respond_to?(:identifier)

        semantics_identifier
      end

      def encode_path_segment(value)
        CGI.escape(value.to_s).gsub("+", "%20")
      end

      def to_milliseconds(unit, value)
        numeric = value.to_i
        return numeric if numeric <= 0

        case unit.to_sym
        when :milliseconds
          numeric
        when :seconds
          numeric * 1000
        when :minutes
          numeric * 60_000
        when :hours
          numeric * 3_600_000
        else
          numeric
        end
      end

      def logger
        SmartId.logger
      end
    end
  end
end
