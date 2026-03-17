# frozen_string_literal: true

require "securerandom"

module SmartIdRuby
  # Utility class for generating RP challenges.
  class RpChallengeGenerator
    MAX_LENGTH = 64
    MIN_LENGTH = 32

    class << self
      # Generates an RP challenge with default length (64 bytes).
      def generate(length = MAX_LENGTH)
        validate_length!(length)
        RpChallenge.new(SecureRandom.random_bytes(length))
      end

      private

      def validate_length!(length)
        return if length.is_a?(Integer) && length.between?(MIN_LENGTH, MAX_LENGTH)

        raise SmartIdRuby::Errors::RequestValidationError,
              "Length must be between #{MIN_LENGTH} and #{MAX_LENGTH}"
      end
    end
  end
end
