# frozen_string_literal: true

require "base64"
require "openssl"

module SmartId
  module Validation
    # Validates RSASSA-PSS signature value in authentication/signature responses.
    class SignatureValueValidator
      def validate(signature_value:, payload:, certificate:, signature_algorithm_parameters:)
        validate_inputs(signature_value, payload, certificate, signature_algorithm_parameters)

        decoded_signature_value = decode_signature_value(signature_value)
        digest = openssl_digest(signature_algorithm_parameters.hash_algorithm)
        mgf_hash_algorithm = fetch_hash_value(signature_algorithm_parameters.mask_gen_algorithm, :parameters)
        mgf_hash_algorithm = fetch_hash_value(mgf_hash_algorithm, :hashAlgorithm)
        mgf_digest = openssl_digest(mgf_hash_algorithm)

        valid = certificate.public_key.verify_pss(
          digest,
          decoded_signature_value,
          payload,
          salt_length: signature_algorithm_parameters.salt_length,
          mgf1_hash: mgf_digest
        )
        return if valid

        raise SmartId::Errors::UnprocessableResponseError,
              "Provided signature value does not match the calculated signature value"
      rescue OpenSSL::PKey::PKeyError, ArgumentError
        raise SmartId::Errors::UnprocessableResponseError, "Invalid signature algorithm parameters were provided"
      rescue SmartId::Errors::UnprocessableResponseError
        raise
      rescue StandardError
        raise SmartId::Errors::UnprocessableResponseError, "Signature value validation failed"
      end

      private

      def validate_inputs(signature_value, payload, certificate, signature_algorithm_parameters)
        raise SmartId::Errors::RequestSetupError, "Parameter 'signatureValue' is not provided" if signature_value.nil?
        raise SmartId::Errors::RequestSetupError, "Parameter 'payload' is not provided" if payload.nil?
        raise SmartId::Errors::RequestSetupError, "Parameter 'certificate' is not provided" if certificate.nil?
        return unless signature_algorithm_parameters.nil?

        raise SmartId::Errors::RequestSetupError, "Parameter 'rsaSsaPssParameters' is not provided"
      end

      def decode_signature_value(signature_value_in_base64)
        Base64.decode64(signature_value_in_base64)
      rescue ArgumentError
        raise SmartId::Errors::UnprocessableResponseError,
              "Failed to parse signature value in base64. Incorrectly encoded base64 string: '#{signature_value_in_base64}'"
      end

      def openssl_digest(hash_algorithm)
        case hash_algorithm
        when "SHA-256" then OpenSSL::Digest::SHA256.new
        when "SHA-384" then OpenSSL::Digest::SHA384.new
        when "SHA-512" then OpenSSL::Digest::SHA512.new
        when "SHA3-256" then OpenSSL::Digest.new("SHA3-256")
        when "SHA3-384" then OpenSSL::Digest.new("SHA3-384")
        when "SHA3-512" then OpenSSL::Digest.new("SHA3-512")
        else
          raise SmartId::Errors::UnprocessableResponseError, "Invalid signature algorithm parameters were provided"
        end
      end

      def fetch_hash_value(payload, key)
        return nil unless payload.respond_to?(:[])

        payload[key] || payload[key.to_s]
      end
    end
  end
end
