# frozen_string_literal: true

require "base64"

module SmartIdRuby
  # Represents RP challenge bytes and helper encodings.
  class RpChallenge
    def initialize(value)
      @value = normalize_value(value).freeze
    end

    # Returns a copy of the challenge bytes.
    def value
      @value.dup
    end

    # Returns challenge as a Base64-encoded string.
    def to_base64_encoded_value
      Base64.strict_encode64(@value)
    end

    private

    # Accepts Ruby-friendly inputs and normalizes them into binary bytes.
    def normalize_value(input)
      case input
      when String
        input.dup.force_encoding(Encoding::BINARY)
      when Array
        input.pack("C*")
      else
        raise SmartIdRuby::Errors::RequestValidationError,
              "Value for 'value' must be a binary String or an Array of bytes"
      end
    end
  end
end
