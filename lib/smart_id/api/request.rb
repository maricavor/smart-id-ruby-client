require 'logger'
require 'date'
module SmartId::Api
  class Request
    def initialize(method, uri, params)
      @method = method
      @url = "#{SmartId.host_url}#{uri}"
      @params = params
      @logger = Logger.new($stdout)
    end

    def self.execute(method:, uri:, params:)
      api_request = new(method, uri, params)
      api_request.execute
    rescue RestClient::RequestFailed => e
      case e.http_code
      when 471
        raise SmartId::IncorrectAccountLevelError, 'No suitable account of requested type found, but user has some other accounts'
      when 403
        raise SmartId::InvalidPermissionsError, 'No permission to issue the request'
      when 404
        raise SmartId::UserNotFoundError, "User account not found for URI #{uri}"
      when 480
        raise SmartId::OutdatedApiError, 'Client-side API is too old and not supported anymore'
      when 580
        raise SmartId::SystemUnderMaintenanceError, 'Server is under maintenance, retry later'
      else
        raise SmartId::ConnectionError, e.message
      end
    rescue RestClient::SSLCertificateNotVerified
      raise SmartId::SSLCertificateNotVerified
    end

    def execute
      attrs = if @method.to_sym == :post
                post_request_attrs
              else
                get_request_attrs
              end

      RestClient::Request.execute(**attrs)
    end

    private

    def default_attrs
      attrs = {
        method: @method,
        url: @url,
        headers: { content_type: :json, accept: :json },
        timeout: SmartId.poller_timeout_seconds + 1
      }
      attrs.merge!(ssl_config) if SmartId.tls_config

      attrs
    end

    def get_request_attrs
      default_attrs.merge(
        headers: {
          **default_attrs[:headers],
          params: @params
        }
      )
    end

    def post_request_attrs
      default_attrs.merge(payload: JSON.generate(@params))
    end

    def ssl_config
      config = {
        ssl_version: SmartId.tls_config[:default_protocol],
        verify_ssl: OpenSSL::SSL::VERIFY_PEER,
        ssl_ciphers: SmartId.tls_config[:enabled_cipher_suites]
      }
      config.merge!(ssl_ca_file: SmartId.tls_config[:ca_file]) if SmartId.tls_config[:ca_file]

      config
    end
  end
end
