# frozen_string_literal: true

RSpec.describe SmartId::Flows::CertificateByDocumentNumberRequestBuilder do
  class TestConnector
    attr_reader :called_document_number, :called_request
    attr_accessor :response

    def get_certificate_by_document_number(document_number, request)
      @called_document_number = document_number
      @called_request = request
      response
    end
  end

  let(:connector) { TestConnector.new }
  let(:builder) { described_class.new(connector) }
  let(:certificate_base64) { Base64.strict_encode64(generated_certificate.to_der) }
  let(:generated_certificate) do
    key = OpenSSL::PKey::RSA.new(1024)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse("/CN=TESTNUMBER")
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now
    cert.not_after = Time.now + 3600
    cert.sign(key, OpenSSL::Digest::SHA256.new)
    cert
  end

  before do
    builder.with_document_number("PNOEE-1234567890-MOCK-Q")
    builder.with_relying_party_uuid("00000000-0000-0000-0000-000000000000")
    builder.with_relying_party_name("DEMO")
    connector.response = {
      "state" => "OK",
      "cert" => {
        "value" => certificate_base64,
        "certificateLevel" => "QUALIFIED"
      }
    }
  end

  it "queries certificate by document number and parses certificate response" do
    result = builder.get_certificate_by_document_number

    expect(connector.called_document_number).to eq("PNOEE-1234567890-MOCK-Q")
    expect(connector.called_request).to include(
      relyingPartyUUID: "00000000-0000-0000-0000-000000000000",
      relyingPartyName: "DEMO",
      certificateLevel: "QUALIFIED"
    )
    expect(result[:certificate_level]).to eq("QUALIFIED")
    expect(result[:certificate]).to be_a(OpenSSL::X509::Certificate)
  end

  it "omits certificate level from request when set to nil but validates against default QUALIFIED" do
    builder.with_certificate_level(nil)
    result = builder.get_certificate_by_document_number

    expect(connector.called_request).not_to have_key(:certificateLevel)
    expect(result[:certificate_level]).to eq("QUALIFIED")
  end

  it "raises when document number is empty" do
    builder.with_document_number(nil)

    expect { builder.get_certificate_by_document_number }.to raise_error(
      SmartId::Errors::RequestSetupError,
      /Value for 'documentNumber' cannot be empty/
    )
  end

  it "raises when response state is DOCUMENT_UNUSABLE" do
    connector.response = { "state" => "DOCUMENT_UNUSABLE", "cert" => nil }

    expect { builder.get_certificate_by_document_number }.to raise_error(SmartId::Errors::DocumentUnusableError)
  end

  it "raises when response certificate level is unsupported" do
    connector.response = {
      "state" => "OK",
      "cert" => { "value" => certificate_base64, "certificateLevel" => "INVALID" }
    }

    expect { builder.get_certificate_by_document_number }.to raise_error(
      SmartId::Errors::UnprocessableResponseError,
      /cert.certificateLevel' has unsupported value/
    )
  end

  it "raises when response certificate level is lower than requested" do
    builder.with_certificate_level("QUALIFIED")
    connector.response = {
      "state" => "OK",
      "cert" => { "value" => certificate_base64, "certificateLevel" => "ADVANCED" }
    }

    expect { builder.get_certificate_by_document_number }.to raise_error(
      SmartId::Errors::UnprocessableResponseError,
      /Queried certificate has lower level than requested/
    )
  end

  it "raises when cert value is not base64" do
    connector.response = {
      "state" => "OK",
      "cert" => { "value" => "NOT@BASE64!", "certificateLevel" => "QUALIFIED" }
    }

    expect { builder.get_certificate_by_document_number }.to raise_error(
      SmartId::Errors::UnprocessableResponseError,
      /cert.value' does not have Base64-encoded value/
    )
  end
end
