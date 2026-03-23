# frozen_string_literal: true

RSpec.describe SmartIdRuby::Models::NotificationCertificateChoiceSessionResponse do
  describe ".from_h" do
    it "maps sessionID to session_id" do
      model = described_class.from_h({ "sessionID" => "sid-123" })

      expect(model).to be_a(described_class)
      expect(model.session_id).to eq("sid-123")
    end

    it "returns same instance when payload is already model" do
      model = described_class.new(session_id: "sid-abc")

      expect(described_class.from_h(model)).to equal(model)
    end

    it "returns empty model when payload is not hash" do
      model = described_class.from_h(nil)

      expect(model).to be_a(described_class)
      expect(model.session_id).to be_nil
    end
  end
end
