# frozen_string_literal: true

RSpec.describe SmartIdRuby::QrCodeGenerator do
  let(:uri) { "https://smart-id.com/device-link/?sessionToken=token123" }

  describe ".generate_data_uri" do
    it "generates PNG data URI" do
      data_uri = described_class.generate_data_uri(uri)

      expect(data_uri).to start_with("data:image/png;base64,")
      expect(Base64.decode64(data_uri.split(",", 2).last).bytesize).to be > 0
    end
  end

  describe ".generate_image" do
    it "generates image with default dimensions" do
      image = described_class.generate_image(uri)

      expect(image.width).to eq(610)
      expect(image.height).to eq(610)
    end

    it "generates image with custom dimensions" do
      image = described_class.generate_image(uri, 100, 100, 2)

      expect(image.width).to eq(100)
      expect(image.height).to eq(100)
    end

    it "raises when data is empty" do
      expect { described_class.generate_image(nil) }.to raise_error(
        SmartIdRuby::Errors::RequestSetupError,
        /Provided data cannot be empty/
      )
    end
  end

  describe ".convert_to_data_uri" do
    it "converts generated image to data URI" do
      image = described_class.generate_image(uri)
      data_uri = described_class.convert_to_data_uri(image, "png")

      expect(data_uri).to start_with("data:image/png;base64,")
      expect(Base64.decode64(data_uri.split(",", 2).last).bytesize).to be > 0
    end
  end
end
