# frozen_string_literal: true

RSpec.describe SmartIdRuby do
  before do
    described_class.instance_variable_set(:@configuration, nil)
    described_class.reset_client!
  end

  describe ".configure" do
    it "stores configuration values and builds client from them" do
      described_class.configure do |config|
        config.relying_party_uuid = "00000000-0000-4000-8000-000000000000"
        config.relying_party_name = "DEMO"
        config.host_url = "https://sid.demo.sk.ee/smart-id-rp/v3/"
        config.poller_timeout_seconds = 15
      end

      client = described_class.client
      expect(client.relying_party_uuid).to eq("00000000-0000-4000-8000-000000000000")
      expect(client.relying_party_name).to eq("DEMO")
      expect(client.host_url).to eq("https://sid.demo.sk.ee/smart-id-rp/v3/")
    end

    it "resets memoized client after reconfiguration" do
      described_class.configure { |config| config.relying_party_name = "ONE" }
      first_client = described_class.client

      described_class.configure { |config| config.relying_party_name = "TWO" }
      second_client = described_class.client

      expect(first_client).not_to equal(second_client)
      expect(second_client.relying_party_name).to eq("TWO")
    end
  end

  describe ".configuration" do
    it "provides defaults for compatibility with legacy initializer shape" do
      config = described_class.configuration

      expect(config.default_certificate_level).to eq("ADVANCED")
      expect(config.poller_timeout_seconds).to eq(10)
    end
  end
end
