# frozen_string_literal: true

require "openssl"

module SmartIdRuby
  # Utility class for calculating verification code from a hash input.
  class VerificationCodeCalculator
    class << self
      # The Verification Code (VC) is computed as:
      # integer(SHA256(data)[-2..-1]) mod 10000
      # where SHA256 rightmost 2 bytes are interpreted as unsigned big-endian.
      def calculate(data)
        validate_data!(data)

        digest = OpenSSL::Digest::SHA256.digest(data.b)
        rightmost_two_bytes = digest[-2, 2]
        unsigned_value = rightmost_two_bytes.unpack1("n")

        format("%04d", unsigned_value % 10_000)
      end

      private

      def validate_data!(data)
        return if data.is_a?(String) && !data.empty?

        raise SmartIdRuby::Errors::RequestValidationError, "Parameter 'data' cannot be empty"
      end
    end
  end
end
