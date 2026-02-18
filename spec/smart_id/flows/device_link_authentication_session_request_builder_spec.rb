# frozen_string_literal: true

RSpec.describe SmartId::Flows::DeviceLinkAuthenticationSessionRequestBuilder do
  class DeviceLinkAuthenticationTestConnector
    attr_reader :called_method, :called_request, :called_argument

    def init_anonymous_device_link_authentication(request)
      @called_method = :anonymous
      @called_request = request
      { "sessionID" => "sid-1", "sessionToken" => "token", "sessionSecret" => "secret", "deviceLinkBase" => "https://link" }
    end

    def init_device_link_authentication_with_document(request, document_number)
      @called_method = :document
      @called_request = request
      @called_argument = document_number
      { "sessionID" => "sid-1", "sessionToken" => "token", "sessionSecret" => "secret", "deviceLinkBase" => "https://link" }
    end

    def init_device_link_authentication(request, semantics_identifier)
      @called_method = :semantics
      @called_request = request
      @called_argument = semantics_identifier
      { "sessionID" => "sid-1", "sessionToken" => "token", "sessionSecret" => "secret", "deviceLinkBase" => "https://link" }
    end
  end

  let(:connector) { DeviceLinkAuthenticationTestConnector.new }
  let(:builder) { described_class.new(connector) }
  let(:rp_challenge) { Base64.strict_encode64("x" * 32) }

  before do
    builder.with_relying_party_uuid("00000000-0000-4000-8000-000000000000")
    builder.with_relying_party_name("DEMO")
    builder.with_rp_challenge(rp_challenge)
    builder.with_interactions([{ type: "displayTextAndPIN", displayText60: "Log in" }])
  end

  it "creates mapped payload and calls anonymous init when no identifier is set" do
    builder.init_authentication_session

    expect(connector.called_method).to eq(:anonymous)
    expect(connector.called_request[:signatureProtocol]).to eq("ACSP_V2")
    expect(connector.called_request[:signatureProtocolParameters][:signatureAlgorithm]).to eq("rsassa-pss")
    expect(connector.called_request[:signatureProtocolParameters][:signatureAlgorithmParameters][:hashAlgorithm]).to eq("SHA3-512")
    expect(connector.called_request[:interactions]).to be_a(String)
    expect(builder.get_authentication_session_request).to eq(connector.called_request)
  end

  it "routes to document-number connector method when document number is provided" do
    builder.with_document_number("PNOLT-40504040001-MOCK-Q")
    builder.init_authentication_session

    expect(connector.called_method).to eq(:document)
    expect(connector.called_argument).to eq("PNOLT-40504040001-MOCK-Q")
  end

  it "raises when both semantics identifier and document number are set" do
    builder.with_document_number("PNOLT-40504040001-MOCK-Q")
    builder.with_semantics_identifier("PNOEE-30303039914")

    expect { builder.init_authentication_session }.to raise_error(
      SmartId::Errors::RequestSetupError,
      /Only one of 'semanticsIdentifier' or 'documentNumber'/
    )
  end

  it "raises when rpChallenge is invalid base64" do
    builder.with_rp_challenge("invalid")

    expect { builder.init_authentication_session }.to raise_error(
      SmartId::Errors::RequestSetupError,
      /must be Base64-encoded/
    )
  end
end
