# frozen_string_literal: true

RSpec.describe SmartIdRuby::NotificationInteraction do
  describe ".display_text_and_pin" do
    it "builds interaction payload with displayText60" do
      interaction = described_class.display_text_and_pin("Log in")

      expect(interaction.to_h).to eq(
        type: "displayTextAndPIN",
        displayText60: "Log in"
      )
    end
  end

  describe ".confirmation_message" do
    it "builds interaction payload with displayText200" do
      interaction = described_class.confirmation_message("Please confirm")

      expect(interaction.to_h).to eq(
        type: "confirmationMessage",
        displayText200: "Please confirm"
      )
    end
  end

  describe ".confirmation_message_and_verification_code_choice" do
    it "builds interaction payload with displayText200" do
      interaction = described_class.confirmation_message_and_verification_code_choice("Please confirm")

      expect(interaction.to_h).to eq(
        type: "confirmationMessageAndVerificationCodeChoice",
        displayText200: "Please confirm"
      )
    end
  end

  it "raises when displayText60 is too long" do
    expect { described_class.display_text_and_pin("a" * 61) }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /displayText60/
    )
  end

  it "raises when displayText200 is too long" do
    expect { described_class.confirmation_message("a" * 201) }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /displayText200/
    )
  end
end
