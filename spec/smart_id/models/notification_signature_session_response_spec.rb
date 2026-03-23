# frozen_string_literal: true

RSpec.describe SmartIdRuby::Models::NotificationSignatureSessionResponse do
  describe ".from_h" do
    it "maps sessionID and vc fields" do
      model = described_class.from_h(
        {
          "sessionID" => "sid-123",
          "vc" => { "type" => "numeric4", "value" => "4927" }
        }
      )

      expect(model).to be_a(described_class)
      expect(model.session_id).to eq("sid-123")
      expect(model.vc).to eq({ "type" => "numeric4", "value" => "4927" })
    end

    it "returns same instance when payload is already model" do
      model = described_class.new(session_id: "sid-abc", vc: { "type" => "numeric4", "value" => "0001" })

      expect(described_class.from_h(model)).to equal(model)
    end

    it "returns empty model when payload is not hash" do
      model = described_class.from_h(nil)

      expect(model).to be_a(described_class)
      expect(model.session_id).to be_nil
      expect(model.vc).to be_nil
    end
  end
end
