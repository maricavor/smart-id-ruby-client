# frozen_string_literal: true

require "ostruct"

module SmartIdRuby
  # Mixin that provides global configuration for the Smart-ID Ruby client
  # (e.g. relying party UUID/name, host URL, and network options).
  module Configuration
    DEFAULT_CONFIG = {
      relying_party_uuid: nil,
      relying_party_name: nil,
      host_url: nil,
      default_certificate_level: "ADVANCED",
      poller_timeout_seconds: 10,
      truststore_path: nil,
      truststore_type: nil,
      truststore_password: nil,
      tls_config: nil,
      network_connection_config: nil,
      configured_connection: nil
    }.freeze

    def configuration
      @configuration ||= OpenStruct.new(DEFAULT_CONFIG)
    end

    def configure
      yield(configuration)
      reload_config
    end

    def client
      @client ||= build_client(configuration)
    end

    def reset_client!
      @client = nil
    end

    def reload_config
      reset_client!
      true
    end

    private

    def build_client(config)
      client = SmartIdRuby::Client.new
      client.relying_party_uuid = config.relying_party_uuid
      client.relying_party_name = config.relying_party_name
      client.host_url = config.host_url
      client.network_connection_config = config.network_connection_config
      client.configured_connection = config.configured_connection

      if config.poller_timeout_seconds
        client.set_session_status_response_socket_open_time(:seconds, config.poller_timeout_seconds.to_i)
      end

      ssl_context = build_ssl_context(config)
      client.trust_ssl_context = ssl_context if ssl_context

      client
    end

    def build_ssl_context(config)
      path = config.truststore_path
      return nil if path.nil? || path.to_s.strip.empty?

      truststore_type = normalize_truststore_type(config.truststore_type, path)
      cert_store = OpenSSL::X509::Store.new
      cert_store.set_default_paths

      if truststore_type == :pkcs12
        add_pkcs12_certificates(cert_store, path, config.truststore_password)
      else
        cert_store.add_file(path)
      end

      ssl_context = OpenSSL::SSL::SSLContext.new
      ssl_context.cert_store = cert_store
      ssl_context
    rescue Errno::ENOENT, OpenSSL::X509::StoreError, OpenSSL::PKCS12::PKCS12Error => e
      raise SmartIdRuby::Error, "Failed to load #{truststore_type || 'truststore'} from '#{path}': #{e.message}"
    end

    def normalize_truststore_type(value, path)
      normalized = value.to_s.strip.upcase
      if normalized.empty?
        return path.to_s.downcase.end_with?(".p12", ".pfx") ? :pkcs12 : :pem
      end

      return :pem if normalized == "PEM"
      return :pkcs12 if %w[PKCS12 P12].include?(normalized)

      raise SmartIdRuby::Error, "Unsupported truststore_type '#{value}'. Supported types: PEM, PKCS12, P12"
    end

    def add_pkcs12_certificates(cert_store, path, password)
      pkcs12 = OpenSSL::PKCS12.new(File.binread(path), password)
      certificates = [pkcs12.certificate, *Array(pkcs12.ca_certs)].compact
      raise SmartIdRuby::Error, "PKCS12 truststore does not contain any certificates" if certificates.empty?

      certificates.each { |certificate| cert_store.add_cert(certificate) }
    end
  end
end
