# frozen_string_literal: true

require "base64"
require "openssl"
require "securerandom"
require "uri"

module SmartIdRuby
  # Utility helpers for creating and validating Smart-ID callback URLs and their tokens.
  class CallbackUrlUtil
    class << self
      def create_callback_url(base_url)
        raise SmartIdRuby::Errors::RequestSetupError, "Parameter for 'baseUrl' cannot be empty" if blank?(base_url)

        url_token = SecureRandom.urlsafe_base64(32, false)
        uri = URI.parse(base_url.to_s)
        query = URI.decode_www_form(uri.query.to_s)
        query << ["value", url_token]
        uri.query = URI.encode_www_form(query)
        SmartIdRuby::CallbackUrl.new(url: uri.to_s, token: url_token)
      end

      def validate_session_secret_digest(session_secret_digest, session_secret)
        if blank?(session_secret_digest)
          raise SmartIdRuby::Errors::RequestSetupError, "Parameter for 'sessionSecretDigest' cannot be empty"
        end
        if blank?(session_secret)
          raise SmartIdRuby::Errors::RequestSetupError, "Parameter for 'sessionSecret' cannot be empty"
        end

        calculated_session_secret_digest = calculate_digest(session_secret)
        return if session_secret_digest.to_s == calculated_session_secret_digest

        raise SmartIdRuby::Errors::SessionSecretMismatchError,
              "Session secret digest from callback does not match calculated session secret digest"
      end

      private

      def calculate_digest(session_secret)
        decoded_session_secret = Base64.strict_decode64(session_secret)
        digest = OpenSSL::Digest::SHA256.digest(decoded_session_secret)
        Base64.urlsafe_encode64(digest, padding: false)
      rescue ArgumentError => e
        raise SmartIdRuby::Errors::RequestSetupError,
              "Parameter 'sessionSecret' is not Base64-encoded value: #{e.message}"
      end

      def blank?(value)
        value.nil? || value.to_s.strip.empty?
      end
    end
  end
end
