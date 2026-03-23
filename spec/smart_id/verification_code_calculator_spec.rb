# frozen_string_literal: true

RSpec.describe SmartIdRuby::VerificationCodeCalculator do
  describe ".calculate" do
    it "calculates verification code from input bytes" do
      expect(described_class.calculate("test")).to eq("2568")
    end

    it "returns a zero-padded 4 digit code" do
      data = [0x00].pack("C*")
      expect(described_class.calculate(data)).to eq("0989")
    end

    it "raises when data is nil" do
      expect { described_class.calculate(nil) }.to raise_error(
        SmartIdRuby::Errors::RequestValidationError,
        /Parameter 'data' cannot be empty/
      )
    end

    it "raises when data is empty" do
      expect { described_class.calculate("") }.to raise_error(
        SmartIdRuby::Errors::RequestValidationError,
        /Parameter 'data' cannot be empty/
      )
    end
  end
end
