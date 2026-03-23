# frozen_string_literal: true

RSpec.describe SmartIdRuby::SemanticsIdentifier do
  describe "#initialize" do
    it "creates identifier from identity type, country code and identity number" do
      value = described_class.new("PNO", "EE", "30303039914")

      expect(value.identifier).to eq("PNOEE-30303039914")
    end

    it "accepts full semantics identifier value" do
      value = described_class.new("PNOEE-30303039914")

      expect(value.identifier).to eq("PNOEE-30303039914")
    end

    it "raises when only one of country code or identity number is missing" do
      expect { described_class.new("PNO", "EE") }.to raise_error(
        SmartIdRuby::Errors::RequestValidationError,
        /Provide either full identifier or identityType \+ countryCode \+ identityNumber/
      )
    end
  end

  describe "constants" do
    it "defines supported identity type constants" do
      expect(described_class::IdentityType::PAS).to eq("PAS")
      expect(described_class::IdentityType::IDC).to eq("IDC")
      expect(described_class::IdentityType::PNO).to eq("PNO")
    end

    it "defines supported country code constants" do
      expect(described_class::CountryCode::EE).to eq("EE")
      expect(described_class::CountryCode::LT).to eq("LT")
      expect(described_class::CountryCode::LV).to eq("LV")
    end
  end
end
