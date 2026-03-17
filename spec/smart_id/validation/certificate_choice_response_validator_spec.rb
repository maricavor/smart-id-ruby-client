# frozen_string_literal: true

RSpec.describe SmartIdRuby::Validation::CertificateChoiceResponseValidator do
  let(:certificate_validator) { instance_double(SmartIdRuby::Validation::CertificateValidator, validate: true) }
  let(:validator) { described_class.new(certificate_validator: certificate_validator) }

  let(:certificate) do
    key = OpenSSL::PKey::RSA.new(1024)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.new(
      [
        ["C", "EE", OpenSSL::ASN1::PRINTABLESTRING],
        ["CN", "TEST", OpenSSL::ASN1::UTF8STRING],
        ["serialNumber", "PNOEE-38001085718", OpenSSL::ASN1::UTF8STRING]
      ]
    )
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    cert.sign(key, OpenSSL::Digest::SHA256.new)
    cert
  end

  let(:valid_status) do
    {
      "result" => { "endResult" => "OK", "documentNumber" => "PNOEE-38001085718" },
      "interactionTypeUsed" => "displayTextAndPIN",
      "deviceIpAddress" => "127.0.0.1",
      "cert" => {
        "value" => Base64.strict_encode64(certificate.to_der),
        "certificateLevel" => "QUALIFIED"
      }
    }
  end

  it "returns mapped certificate choice response on valid status" do
    response = validator.validate(valid_status, "QUALIFIED")

    expect(response).to be_a(SmartIdRuby::Models::CertificateChoiceResponse)
    expect(response.document_number).to eq("PNOEE-38001085718")
    expect(response.certificate_level).to eq("QUALIFIED")
    expect(response.device_ip_address).to eq("127.0.0.1")
  end

  it "raises when result is missing" do
    status = valid_status.merge("result" => nil)

    expect { validator.validate(status, "QUALIFIED") }.to raise_error(
      SmartIdRuby::Errors::UnprocessableResponseError,
      /Certificate choice session status field 'result' is missing/
    )
  end

  it "raises certificate level mismatch when response level is lower than requested" do
    status = valid_status.merge("cert" => valid_status["cert"].merge("certificateLevel" => "ADVANCED"))

    expect { validator.validate(status, "QUALIFIED") }.to raise_error(
      SmartIdRuby::Errors::CertificateLevelMismatchError,
      /certificate level is lower than requested/i
    )
  end
end
