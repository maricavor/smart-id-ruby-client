# frozen_string_literal: true

RSpec.describe SmartIdRuby::Models::SessionStatus do
  it "maps nested session status payload to typed models" do
    payload = {
      "state" => "COMPLETE",
      "result" => {
        "endResult" => "OK",
        "documentNumber" => "PNOLT-40504040001-MOCK-Q",
        "details" => {
          "interaction" => "displayTextAndPIN"
        }
      },
      "signatureProtocol" => "ACSP_V2",
      "signature" => {
        "value" => "base64-signature",
        "serverRandom" => "base64-random",
        "userChallenge" => "base64-user-challenge",
        "flowType" => "QR",
        "signatureAlgorithm" => "rsassa-pss",
        "signatureAlgorithmParameters" => {
          "hashAlgorithm" => "SHA-256",
          "maskGenAlgorithm" => { "algorithm" => "MGF1", "parameters" => { "hashAlgorithm" => "SHA-256" } },
          "saltLength" => 32,
          "trailerField" => "0xbc"
        }
      },
      "cert" => {
        "value" => "base64-cert",
        "certificateLevel" => "QUALIFIED"
      },
      "ignoredProperties" => ["unsupportedField"],
      "interactionTypeUsed" => "displayTextAndPIN",
      "deviceIpAddress" => "10.10.10.10"
    }

    model = described_class.from_h(payload)

    expect(model).to be_complete
    expect(model.state).to eq("COMPLETE")
    expect(model.result).to be_a(SmartIdRuby::Models::SessionResult)
    expect(model.result.end_result).to eq("OK")
    expect(model.result.document_number).to eq("PNOLT-40504040001-MOCK-Q")
    expect(model.result.details.interaction).to eq("displayTextAndPIN")
    expect(model.signature).to be_a(SmartIdRuby::Models::SessionSignature)
    expect(model.signature.signature_algorithm_parameters.hash_algorithm).to eq("SHA-256")
    expect(model.cert).to be_a(SmartIdRuby::Models::SessionCertificate)
    expect(model.cert.certificate_level).to eq("QUALIFIED")
    expect(model.ignored_properties).to eq(["unsupportedField"])
    expect(model.interaction_type_used).to eq("displayTextAndPIN")
    expect(model.device_ip_address).to eq("10.10.10.10")
  end

  it "handles empty or non-hash payloads safely" do
    expect(described_class.from_h(nil)).to be_a(described_class)
    expect(described_class.from_h("invalid").state).to be_nil
  end
end
