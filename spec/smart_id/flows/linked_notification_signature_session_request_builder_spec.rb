# frozen_string_literal: true

RSpec.describe SmartId::Flows::LinkedNotificationSignatureSessionRequestBuilder do
  LinkedSignableDataInput = Struct.new(:data_to_sign, :hash_algorithm)
  LinkedSignableHashInput = Struct.new(:hash_to_sign, :hash_algorithm)

  class LinkedNotificationSignatureTestConnector
    attr_reader :called_request, :called_document_number
    attr_accessor :response

    def initialize
      @response = { "sessionID" => "20000000-0000-0000-0000-000000000000" }
    end

    def init_linked_notification_signature(request, document_number)
      @called_request = request
      @called_document_number = document_number
      response
    end
  end

  let(:connector) { LinkedNotificationSignatureTestConnector.new }
  let(:builder) { described_class.new(connector) }

  before do
    builder.with_relying_party_uuid("00000000-0000-0000-0000-000000000000")
    builder.with_relying_party_name("DEMO")
    builder.with_document_number("PNOEE-12345678901-MOCK-Q")
    builder.with_signable_data("Test data")
    builder.with_linked_session_id("10000000-0000-0000-0000-000000000000")
    builder.with_interactions([{ type: "displayTextAndPIN", displayText200: "Sign?" }])
  end

  it "inits linked notification signature session and maps payload" do
    response = builder.init_signature_session

    expect(response["sessionID"]).to eq("20000000-0000-0000-0000-000000000000")
    expect(connector.called_document_number).to eq("PNOEE-12345678901-MOCK-Q")
    expect(connector.called_request[:signatureProtocol]).to eq("RAW_DIGEST_SIGNATURE")
    expect(connector.called_request[:linkedSessionID]).to eq("10000000-0000-0000-0000-000000000000")
  end

  it "supports certificate level and capabilities mapping" do
    builder.with_certificate_level("QUALIFIED")
    builder.with_capabilities("A", " ", nil, "B", "A")
    builder.init_signature_session

    expect(connector.called_request[:certificateLevel]).to eq("QUALIFIED")
    expect(connector.called_request[:capabilities]).to eq(%w[A B])
  end

  it "supports requestProperties mapping when share_md_client_ip_address is set" do
    builder.with_share_md_client_ip_address(true)
    builder.init_signature_session

    expect(connector.called_request[:requestProperties]).to eq({ shareMdClientIpAddress: true })
  end

  it "supports signable hash with explicit hash algorithm" do
    builder.with_signable_data(nil)
    builder.with_signable_hash(LinkedSignableHashInput.new("raw hash bytes", "SHA-384"))
    builder.init_signature_session

    expect(connector.called_request[:signatureProtocolParameters][:signatureAlgorithmParameters][:hashAlgorithm]).to eq("SHA-384")
    expect(connector.called_request[:signatureProtocolParameters][:digest]).to eq(Base64.strict_encode64("raw hash bytes"))
  end

  it "raises when digest input is missing" do
    builder.with_signable_data(nil)
    builder.with_signable_hash(nil)

    expect { builder.init_signature_session }.to raise_error(
      SmartId::Errors::RequestSetupError,
      /Value for 'digestInput' must be set with SignableData or with SignableHash/
    )
  end

  it "raises when signable hash is set after signable data" do
    expect do
      builder.with_signable_data(LinkedSignableDataInput.new("Test data", "SHA-512"))
             .with_signable_hash("hash")
    end.to raise_error(
      SmartId::Errors::RequestSetupError,
      /Value for 'digestInput' has been already set with SignableData/
    )
  end

  it "raises when linkedSessionID is missing" do
    builder.with_linked_session_id(nil)

    expect { builder.init_signature_session }.to raise_error(
      SmartId::Errors::RequestSetupError,
      /Value for 'linkedSessionID' cannot be empty/
    )
  end

  it "raises when nonce has invalid length" do
    builder.with_nonce("")

    expect { builder.init_signature_session }.to raise_error(
      SmartId::Errors::RequestSetupError,
      /Value for 'nonce' must be 1-30 characters long/
    )
  end

  it "raises when interactions contain duplicate types" do
    builder.with_interactions([{ type: "displayTextAndPIN" }, { type: "displayTextAndPIN" }])

    expect { builder.init_signature_session }.to raise_error(
      SmartId::Errors::RequestSetupError,
      /Value for 'interactions' cannot contain duplicate types/
    )
  end

  it "raises when sessionID is missing in response" do
    connector.response = { "sessionID" => "" }

    expect { builder.init_signature_session }.to raise_error(
      SmartId::Errors::UnprocessableResponseError,
      /Linked notification-base signature session response field 'sessionID' is missing or empty/
    )
  end
end
