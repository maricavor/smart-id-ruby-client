# frozen_string_literal: true

module SmartId
  # Represents interaction payload used in notification-based flows.
  class NotificationInteraction
    DISPLAY_TEXT_AND_PIN = "displayTextAndPIN"
    CONFIRMATION_MESSAGE = "confirmationMessage"
    CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE = "confirmationMessageAndVerificationCodeChoice"

    DISPLAY_TEXT_60_MAX_LENGTH = 60
    DISPLAY_TEXT_200_MAX_LENGTH = 200

    attr_reader :type, :display_text60, :display_text200

    def initialize(type:, display_text60: nil, display_text200: nil)
      @type = type&.to_s
      @display_text60 = display_text60
      @display_text200 = display_text200

      validate!
    end

    def to_h
      {
        type: type,
        displayText60: display_text60,
        displayText200: display_text200
      }.compact
    end

    def self.display_text_and_pin(display_text60)
      new(type: DISPLAY_TEXT_AND_PIN, display_text60: display_text60)
    end

    def self.confirmation_message(display_text200)
      new(type: CONFIRMATION_MESSAGE, display_text200: display_text200)
    end

    def self.confirmation_message_and_verification_code_choice(display_text200)
      new(type: CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE, display_text200: display_text200)
    end

    # Java-style factory aliases for easier migration from Java examples.
    def self.displayTextAndPin(display_text60)
      display_text_and_pin(display_text60)
    end

    def self.confirmationMessage(display_text200)
      confirmation_message(display_text200)
    end

    def self.confirmationMessageAndVerificationCodeChoice(display_text200)
      confirmation_message_and_verification_code_choice(display_text200)
    end

    private

    def validate!
      if blank?(type)
        raise SmartId::Errors::RequestSetupError, "Value for 'type' must be set"
      end

      case type
      when DISPLAY_TEXT_AND_PIN
        validate_display_text!(display_text60, "displayText60", DISPLAY_TEXT_60_MAX_LENGTH)
      when CONFIRMATION_MESSAGE, CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE
        validate_display_text!(display_text200, "displayText200", DISPLAY_TEXT_200_MAX_LENGTH)
      else
        raise SmartId::Errors::RequestSetupError, "Unsupported interaction type: #{type}"
      end
    end

    def validate_display_text!(value, field_name, max_length)
      if blank?(value)
        raise SmartId::Errors::RequestSetupError, "Value for '#{field_name}' cannot be empty"
      end
      return if value.to_s.length <= max_length

      raise SmartId::Errors::RequestSetupError,
            "Value for '#{field_name}' cannot be longer than #{max_length} characters"
    end

    def blank?(value)
      value.nil? || value.to_s.strip.empty?
    end
  end
end
