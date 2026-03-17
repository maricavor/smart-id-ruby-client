# frozen_string_literal: true

RSpec.describe SmartIdRuby::Validation::ErrorResultHandler do
  describe ".handle" do
    it "raises document unusable error for DOCUMENT_UNUSABLE" do
      result = SmartIdRuby::Models::SessionResult.new(end_result: "DOCUMENT_UNUSABLE")

      expect { described_class.handle(result) }.to raise_error(SmartIdRuby::Errors::DocumentUnusableError)
    end

    it "raises mapped user-refused interaction errors" do
      result = SmartIdRuby::Models::SessionResult.new(
        end_result: "USER_REFUSED_INTERACTION",
        details: SmartIdRuby::Models::SessionResultDetails.new(interaction: "displayTextAndPIN")
      )

      expect { described_class.handle(result) }.to raise_error(SmartIdRuby::Errors::UserRefusedDisplayTextAndPinError)
    end

    it "raises unprocessable error when refused interaction details are missing" do
      result = SmartIdRuby::Models::SessionResult.new(end_result: "USER_REFUSED_INTERACTION", details: nil)

      expect { described_class.handle(result) }.to raise_error(
        SmartIdRuby::Errors::UnprocessableResponseError,
        /Details for refused interaction are missing/
      )
    end

    it "raises dedicated error for known non-special end results" do
      result = SmartIdRuby::Models::SessionResult.new(end_result: "TIMEOUT")

      expect { described_class.handle(result) }.to raise_error(SmartIdRuby::Errors::SessionTimeoutError)
    end

    it "raises unprocessable error for unexpected end results" do
      result = SmartIdRuby::Models::SessionResult.new(end_result: "UNKNOWN_ERROR")

      expect { described_class.handle(result) }.to raise_error(
        SmartIdRuby::Errors::UnprocessableResponseError,
        /Unexpected session result: UNKNOWN_ERROR/
      )
    end
  end
end
