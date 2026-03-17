# frozen_string_literal: true

RSpec.describe SmartIdRuby::Flows::NotificationSignatureSessionRequestBuilder do
  NotificationSignableDataInput = Struct.new(:data_to_sign, :hash_algorithm)
  NotificationSignableHashInput = Struct.new(:hash_to_sign, :hash_algorithm)

  class NotificationSignatureTestConnector
    attr_reader :called_method, :called_request, :called_argument

    def init_notification_signature(request, semantics_identifier)
      @called_method = :semantics
      @called_request = request
      @called_argument = semantics_identifier
      { "sessionID" => "sid-1", "vc" => { "type" => "numeric4", "value" => "4927" } }
    end

    def init_notification_signature_with_document(request, document_number)
      @called_method = :document
      @called_request = request
      @called_argument = document_number
      { "sessionID" => "sid-1", "vc" => { "type" => "numeric4", "value" => "4927" } }
    end
  end

  let(:connector) { NotificationSignatureTestConnector.new }
  let(:builder) { described_class.new(connector) }

  before do
    builder.with_relying_party_uuid("00000000-0000-4000-8000-000000000000")
    builder.with_relying_party_name("DEMO")
    builder.with_interactions([{ type: "displayTextAndPIN", displayText60: "Sign?" }])
    builder.with_signable_data("Test data")
  end

  it "creates mapped payload and routes to semantics init" do
    builder.with_semantics_identifier("PNOEE-30303039914")
    builder.init_signature_session

    expect(connector.called_method).to eq(:semantics)
    expect(connector.called_argument).to eq("PNOEE-30303039914")
    expect(connector.called_request[:signatureProtocol]).to eq("RAW_DIGEST_SIGNATURE")
    expect(connector.called_request[:signatureProtocolParameters][:signatureAlgorithm]).to eq("rsassa-pss")
    expect(connector.called_request[:signatureProtocolParameters][:signatureAlgorithmParameters][:hashAlgorithm]).to eq("SHA-512")
    expect(connector.called_request[:interactions]).to be_a(String)
  end

  it "uses SHA-512 by default for signable data digest input" do
    builder.with_semantics_identifier("PNOEE-30303039914")
    builder.init_signature_session

    digest = connector.called_request[:signatureProtocolParameters][:digest]
    hash_algorithm = connector.called_request[:signatureProtocolParameters][:signatureAlgorithmParameters][:hashAlgorithm]
    expected = Base64.strict_encode64(OpenSSL::Digest::SHA512.digest("Test data"))

    expect(hash_algorithm).to eq("SHA-512")
    expect(digest).to eq(expected)
  end

  it "allows overriding hash algorithm for signable data input object" do
    builder.with_signable_data(NotificationSignableDataInput.new("Test data", "SHA-256"))
    builder.with_semantics_identifier("PNOEE-30303039914")
    builder.init_signature_session

    digest = connector.called_request[:signatureProtocolParameters][:digest]
    hash_algorithm = connector.called_request[:signatureProtocolParameters][:signatureAlgorithmParameters][:hashAlgorithm]
    expected = Base64.strict_encode64(OpenSSL::Digest::SHA256.digest("Test data"))

    expect(hash_algorithm).to eq("SHA-256")
    expect(digest).to eq(expected)
  end

  it "uses SHA-512 by default for signable hash digest input" do
    builder.with_signable_data(nil)
    builder.with_signable_hash("raw hash bytes")
    builder.with_semantics_identifier("PNOEE-30303039914")
    builder.init_signature_session

    digest = connector.called_request[:signatureProtocolParameters][:digest]
    hash_algorithm = connector.called_request[:signatureProtocolParameters][:signatureAlgorithmParameters][:hashAlgorithm]
    expected = Base64.strict_encode64("raw hash bytes")

    expect(hash_algorithm).to eq("SHA-512")
    expect(digest).to eq(expected)
  end

  it "allows overriding hash algorithm for signable hash input object" do
    builder.with_signable_data(nil)
    builder.with_signable_hash(NotificationSignableHashInput.new("raw hash bytes", "SHA-384"))
    builder.with_semantics_identifier("PNOEE-30303039914")
    builder.init_signature_session

    digest = connector.called_request[:signatureProtocolParameters][:digest]
    hash_algorithm = connector.called_request[:signatureProtocolParameters][:signatureAlgorithmParameters][:hashAlgorithm]
    expected = Base64.strict_encode64("raw hash bytes")

    expect(hash_algorithm).to eq("SHA-384")
    expect(digest).to eq(expected)
  end

  it "routes to document-number connector method when document number is provided" do
    builder.with_document_number("PNOLT-40504040001-MOCK-Q")
    builder.init_signature_session

    expect(connector.called_method).to eq(:document)
    expect(connector.called_argument).to eq("PNOLT-40504040001-MOCK-Q")
  end

  it "raises when both semantics identifier and document number are set" do
    builder.with_document_number("PNOLT-40504040001-MOCK-Q")
    builder.with_semantics_identifier("PNOEE-30303039914")

    expect { builder.init_signature_session }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /Only one of 'semanticsIdentifier' or 'documentNumber'/
    )
  end

  it "raises when no document number or semantics identifier is set" do
    expect { builder.init_signature_session }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /Either 'documentNumber' or 'semanticsIdentifier' must be set/
    )
  end

  it "raises when nonce is empty" do
    builder.with_semantics_identifier("PNOEE-30303039914")
    builder.with_nonce("")

    expect { builder.init_signature_session }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /Value for 'nonce' length must be between 1 and 30 characters/
    )
  end

  it "raises when signable data and signable hash are both set" do
    builder.with_signable_data("abc")

    expect do
      builder.with_signable_hash("hash")
    end.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /Value for 'digestInput' has already been set with SignableData/
    )
  end

  it "raises when digest input is not set" do
    builder.with_signable_data(nil)
    builder.with_signable_hash(nil)
    builder.with_semantics_identifier("PNOEE-30303039914")

    expect { builder.init_signature_session }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /Value for 'digestInput' must be set with either SignableData or SignableHash/
    )
  end

  it "raises when signature algorithm is set to nil" do
    builder.with_signature_algorithm(nil)
    builder.with_semantics_identifier("PNOEE-30303039914")

    expect { builder.init_signature_session }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /Value for 'signatureAlgorithm' must be set/
    )
  end

  it "raises when response vc is missing" do
    broken_connector = NotificationSignatureTestConnector.new
    allow(broken_connector).to receive(:init_notification_signature)
      .and_return({ "sessionID" => "sid-1", "vc" => nil })
    local_builder = described_class.new(broken_connector)
      .with_relying_party_uuid("00000000-0000-4000-8000-000000000000")
      .with_relying_party_name("DEMO")
      .with_interactions([{ type: "displayTextAndPIN", displayText60: "Sign?" }])
      .with_signable_data("Test data")
      .with_semantics_identifier("PNOEE-30303039914")

    expect { local_builder.init_signature_session }.to raise_error(
      SmartIdRuby::Errors::UnprocessableResponseError,
      /response field 'vc' is missing/
    )
  end

  it "raises when response vc.type is missing" do
    broken_connector = NotificationSignatureTestConnector.new
    allow(broken_connector).to receive(:init_notification_signature)
      .and_return({ "sessionID" => "sid-1", "vc" => { "type" => "", "value" => "4927" } })
    local_builder = described_class.new(broken_connector)
      .with_relying_party_uuid("00000000-0000-4000-8000-000000000000")
      .with_relying_party_name("DEMO")
      .with_interactions([{ type: "displayTextAndPIN", displayText60: "Sign?" }])
      .with_signable_data("Test data")
      .with_semantics_identifier("PNOEE-30303039914")

    expect { local_builder.init_signature_session }.to raise_error(
      SmartIdRuby::Errors::UnprocessableResponseError,
      /response field 'vc.type' is missing or empty/
    )
  end

  it "raises when response vc.value is missing" do
    broken_connector = NotificationSignatureTestConnector.new
    allow(broken_connector).to receive(:init_notification_signature)
      .and_return({ "sessionID" => "sid-1", "vc" => { "type" => "numeric4", "value" => "" } })
    local_builder = described_class.new(broken_connector)
      .with_relying_party_uuid("00000000-0000-4000-8000-000000000000")
      .with_relying_party_name("DEMO")
      .with_interactions([{ type: "displayTextAndPIN", displayText60: "Sign?" }])
      .with_signable_data("Test data")
      .with_semantics_identifier("PNOEE-30303039914")

    expect { local_builder.init_signature_session }.to raise_error(
      SmartIdRuby::Errors::UnprocessableResponseError,
      /response field 'vc.value' is missing or empty/
    )
  end

  it "raises when response vc.value does not match required pattern" do
    broken_connector = NotificationSignatureTestConnector.new
    allow(broken_connector).to receive(:init_notification_signature)
      .and_return({ "sessionID" => "sid-1", "vc" => { "type" => "numeric4", "value" => "abcd" } })
    local_builder = described_class.new(broken_connector)
      .with_relying_party_uuid("00000000-0000-4000-8000-000000000000")
      .with_relying_party_name("DEMO")
      .with_interactions([{ type: "displayTextAndPIN", displayText60: "Sign?" }])
      .with_signable_data("Test data")
      .with_semantics_identifier("PNOEE-30303039914")

    expect { local_builder.init_signature_session }.to raise_error(
      SmartIdRuby::Errors::UnprocessableResponseError,
      /response field 'vc.value' does not match the required pattern/
    )
  end

  it "raises when response vc.type is unsupported" do
    broken_connector = NotificationSignatureTestConnector.new
    allow(broken_connector).to receive(:init_notification_signature)
      .and_return({ "sessionID" => "sid-1", "vc" => { "type" => "numeric6", "value" => "4927" } })
    local_builder = described_class.new(broken_connector)
      .with_relying_party_uuid("00000000-0000-4000-8000-000000000000")
      .with_relying_party_name("DEMO")
      .with_interactions([{ type: "displayTextAndPIN", displayText60: "Sign?" }])
      .with_signable_data("Test data")
      .with_semantics_identifier("PNOEE-30303039914")

    expect { local_builder.init_signature_session }.to raise_error(
      SmartIdRuby::Errors::UnprocessableResponseError,
      /vc.type' contains unsupported value/
    )
  end
end
