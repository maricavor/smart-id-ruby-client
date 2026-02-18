# frozen_string_literal: true

RSpec.describe SmartId::Flows::NotificationAuthenticationSessionRequestBuilder do
  class TestConnector
    attr_reader :called_method, :called_request, :called_argument

    def init_notification_authentication(request, semantics_identifier)
      @called_method = :semantics
      @called_request = request
      @called_argument = semantics_identifier
      { "sessionID" => "sid-1" }
    end

    def init_notification_authentication_with_document(request, document_number)
      @called_method = :document
      @called_request = request
      @called_argument = document_number
      { "sessionID" => "sid-1" }
    end
  end

  let(:connector) { TestConnector.new }
  let(:builder) { described_class.new(connector) }
  let(:rp_challenge) { Base64.strict_encode64("x" * 32) }

  before do
    builder.with_relying_party_uuid("00000000-0000-4000-8000-000000000000")
    builder.with_relying_party_name("DEMO")
    builder.with_rp_challenge(rp_challenge)
    builder.with_interactions([{ type: "displayTextAndPIN", displayText60: "Log in" }])
  end

  it "creates mapped payload and routes to document-number init by default setup" do
    builder.with_document_number("PNOLT-40504040001-MOCK-Q")
    builder.init_authentication_session

    expect(connector.called_method).to eq(:document)
    expect(connector.called_request[:signatureProtocol]).to eq("ACSP_V2")
    expect(connector.called_request[:signatureProtocolParameters][:signatureAlgorithm]).to eq("rsassa-pss")
    expect(connector.called_request[:signatureProtocolParameters][:signatureAlgorithmParameters][:hashAlgorithm]).to eq("SHA3-512")
    expect(connector.called_request[:interactions]).to be_a(String)
    expect(connector.called_request[:vcType]).to eq("numeric4")
    expect(builder.get_authentication_session_request).to eq(connector.called_request)
  end

  it "routes to semantics-identifier connector method when provided" do
    builder.with_semantics_identifier("PNOEE-30303039914")
    builder.init_authentication_session

    expect(connector.called_method).to eq(:semantics)
    expect(connector.called_argument).to eq("PNOEE-30303039914")
  end

  it "raises when both semantics identifier and document number are set" do
    builder.with_document_number("PNOLT-40504040001-MOCK-Q")
    builder.with_semantics_identifier("PNOEE-30303039914")

    expect { builder.init_authentication_session }.to raise_error(
      SmartId::Errors::RequestSetupError,
      /Only one of 'semanticsIdentifier' or 'documentNumber'/
    )
  end

  it "raises when no document number or semantics identifier is set" do
    expect { builder.init_authentication_session }.to raise_error(
      SmartId::Errors::RequestSetupError,
      /Either 'documentNumber' or 'semanticsIdentifier' must be set/
    )
  end

  it "raises when rpChallenge is invalid base64" do
    builder.with_document_number("PNOLT-40504040001-MOCK-Q")
    builder.with_rp_challenge("invalid")

    expect { builder.init_authentication_session }.to raise_error(
      SmartId::Errors::RequestSetupError,
      /must be Base64-encoded/
    )
  end
end
