# frozen_string_literal: true

RSpec.describe SmartId::Validation::ErrorResultHandler do
  describe ".handle" do
    it "raises document unusable error for DOCUMENT_UNUSABLE" do
      result = SmartId::Models::SessionResult.new(end_result: "DOCUMENT_UNUSABLE")

      expect { described_class.handle(result) }.to raise_error(SmartId::Errors::DocumentUnusableError)
    end

    it "raises mapped user-refused interaction errors" do
      result = SmartId::Models::SessionResult.new(
        end_result: "USER_REFUSED_INTERACTION",
        details: SmartId::Models::SessionResultDetails.new(interaction: "displayTextAndPIN")
      )

      expect { described_class.handle(result) }.to raise_error(SmartId::Errors::UserRefusedDisplayTextAndPinError)
    end

    it "raises unprocessable error when refused interaction details are missing" do
      result = SmartId::Models::SessionResult.new(end_result: "USER_REFUSED_INTERACTION", details: nil)

      expect { described_class.handle(result) }.to raise_error(
        SmartId::Errors::UnprocessableResponseError,
        /Details for refused interaction are missing/
      )
    end

    it "raises session end result error for known non-special errors" do
      result = SmartId::Models::SessionResult.new(end_result: "TIMEOUT")

      expect { described_class.handle(result) }.to raise_error(SmartId::Errors::SessionEndResultError)
    end

    it "raises session end result error for unexpected errors with fallback message" do
      result = SmartId::Models::SessionResult.new(end_result: "UNKNOWN_ERROR")

      expect { described_class.handle(result) }.to raise_error(
        SmartId::Errors::SessionEndResultError,
        /Unexpected session result: UNKNOWN_ERROR/
      )
    end
  end
end
