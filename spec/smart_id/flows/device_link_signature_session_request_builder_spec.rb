# frozen_string_literal: true

RSpec.describe SmartIdRuby::Flows::DeviceLinkSignatureSessionRequestBuilder do
  DeviceLinkSignableDataInput = Struct.new(:data_to_sign, :hash_algorithm)

  class DeviceLinkSignatureTestConnector
    attr_reader :called_method, :called_request, :called_argument
    attr_accessor :response

    def initialize
      @response = {
        "sessionID" => "sid-1",
        "sessionToken" => "token",
        "sessionSecret" => "secret",
        "deviceLinkBase" => "https://example.com/device-link"
      }
    end

    def init_device_link_signature(request, semantics_identifier)
      @called_method = :semantics
      @called_request = request
      @called_argument = semantics_identifier
      response
    end

    def init_device_link_signature_with_document(request, document_number)
      @called_method = :document
      @called_request = request
      @called_argument = document_number
      response
    end
  end

  let(:connector) { DeviceLinkSignatureTestConnector.new }
  let(:builder) { described_class.new(connector) }

  before do
    builder.with_relying_party_uuid("test-relying-party-uuid")
    builder.with_relying_party_name("DEMO")
    builder.with_interactions([{ type: "displayTextAndPIN", displayText200: "Please sign the document" }])
    builder.with_signable_data("Test data")
  end

  it "creates mapped payload and routes to semantics connector" do
    builder.with_semantics_identifier("PNOEE-31111111111")
    builder.init_signature_session

    expect(connector.called_method).to eq(:semantics)
    expect(connector.called_argument).to eq("PNOEE-31111111111")
    expect(connector.called_request[:signatureProtocol]).to eq("RAW_DIGEST_SIGNATURE")
    expect(connector.called_request[:signatureProtocolParameters][:signatureAlgorithm]).to eq("rsassa-pss")
    expect(connector.called_request[:signatureProtocolParameters][:signatureAlgorithmParameters][:hashAlgorithm]).to eq("SHA-512")
    expect(connector.called_request[:interactions]).to be_a(String)
  end

  it "routes to document-number connector when document number is provided" do
    builder.with_document_number("PNOEE-31111111111-MOCK-Q")
    builder.init_signature_session

    expect(connector.called_method).to eq(:document)
    expect(connector.called_argument).to eq("PNOEE-31111111111-MOCK-Q")
  end

  it "stores and returns signature request after initialization" do
    builder.with_semantics_identifier("PNOEE-31111111111")
    builder.init_signature_session

    request = builder.signature_session_request
    expect(request[:relyingPartyUUID]).to eq("test-relying-party-uuid")
    expect(request[:relyingPartyName]).to eq("DEMO")
  end

  it "raises when reading signature request before initialization" do
    expect { builder.signature_session_request }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /Signature session has not been initiated yet/
    )
  end

  it "uses provided hash algorithm for signable data object" do
    builder.with_signable_data(DeviceLinkSignableDataInput.new("Test data", "SHA-256"))
    builder.with_semantics_identifier("PNOEE-31111111111")
    builder.init_signature_session

    digest = connector.called_request[:signatureProtocolParameters][:digest]
    hash_algorithm = connector.called_request[:signatureProtocolParameters][:signatureAlgorithmParameters][:hashAlgorithm]
    expected = Base64.strict_encode64(OpenSSL::Digest::SHA256.digest("Test data"))

    expect(hash_algorithm).to eq("SHA-256")
    expect(digest).to eq(expected)
  end

  it "raises when both semantics identifier and document number are set" do
    builder.with_semantics_identifier("PNOEE-31111111111")
    builder.with_document_number("PNOEE-31111111111-MOCK-Q")

    expect { builder.init_signature_session }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /Only one of 'semanticsIdentifier' or 'documentNumber'/
    )
  end

  it "raises when both semantics identifier and document number are missing" do
    expect { builder.init_signature_session }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /Either 'documentNumber' or 'semanticsIdentifier' must be set. Anonymous signing is not allowed/
    )
  end

  it "raises when initial callback URL is invalid" do
    builder.with_semantics_identifier("PNOEE-31111111111")
    builder.with_initial_callback_url("http://example.com")

    expect { builder.init_signature_session }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /must match pattern \^https:\/\/\[\^\|\]\+\$/
    )
  end

  it "raises when nonce is invalid" do
    builder.with_semantics_identifier("PNOEE-31111111111")
    builder.with_nonce("")

    expect { builder.init_signature_session }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /Value for 'nonce' length must be between 1 and 30 characters\./
    )
  end

  it "raises when response missing sessionToken" do
    connector.response = {
      "sessionID" => "sid-1",
      "sessionToken" => nil,
      "sessionSecret" => "secret",
      "deviceLinkBase" => "https://example.com/device-link"
    }
    builder.with_semantics_identifier("PNOEE-31111111111")

    expect { builder.init_signature_session }.to raise_error(
      SmartIdRuby::Errors::UnprocessableResponseError,
      /response field 'sessionToken' is missing or empty/
    )
  end
end
