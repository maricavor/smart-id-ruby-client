# frozen_string_literal: true

require "smart_id/exceptions"
require "smart_id/utils/serializer"

module SmartId
  module Utils
    class Interaction
      include Serializer

      DISPLAY_TEXT_AND_PIN = "displayTextAndPIN"
      CONFIRMATION_MESSAGE = "confirmationMessage"
      VERIFICATION_CODE_CHOICE = "verificationCodeChoice"
      CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE = "confirmationMessageAndVerificationCodeChoice"

      attr_accessor :type, :display_text60, :display_text200

      def initialize(type)
        @type = type
      end

      def self.display_text_and_pin(display_text60)
        interaction = new(DISPLAY_TEXT_AND_PIN)
        interaction.display_text60 = display_text60
        interaction
      end

      def self.verification_code_choice(display_text60)
        interaction = new(VERIFICATION_CODE_CHOICE)
        interaction.display_text60 = display_text60
        interaction
      end

      def self.confirmation_message(display_text200)
        interaction = new(CONFIRMATION_MESSAGE)
        interaction.display_text200 = display_text200
        interaction
      end

      def self.confirmation_message_and_verification_code_choice(display_text200)
        interaction = new(CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE)
        interaction.display_text200 = display_text200
        interaction
      end

      def validate
        validate_display_text60
        validate_display_text200
      end

      private

      def validate_display_text60
        return unless [VERIFICATION_CODE_CHOICE, DISPLAY_TEXT_AND_PIN].include?(@type)

        raise InvalidParamsError, "displayText60 cannot be null for #{@type}" if @display_text60.nil?
        raise InvalidParamsError, "displayText60 must not be longer than 60 characters" if @display_text60.length > 60
        raise InvalidParamsError, "displayText200 must be null for #{@type}" unless @display_text200.nil?
      end

      def validate_display_text200
        return unless [CONFIRMATION_MESSAGE, CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE].include?(@type)

        raise InvalidParamsError, "displayText200 cannot be null for #{@type}" if @display_text200.nil?
        raise InvalidParamsError, "displayText200 must not be longer than 200 characters" if @display_text200.length > 200
        raise InvalidParamsError, "displayText60 must be null for #{@type}" unless @display_text60.nil?
      end
    end
  end
end
