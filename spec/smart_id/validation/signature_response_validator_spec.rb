# frozen_string_literal: true

RSpec.describe SmartIdRuby::Validation::SignatureResponseValidator do
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
    extension_factory = OpenSSL::X509::ExtensionFactory.new
    extension_factory.subject_certificate = cert
    extension_factory.issuer_certificate = cert
    cert.add_extension(extension_factory.create_extension("keyUsage", "nonRepudiation", true))
    cert.sign(key, OpenSSL::Digest::SHA256.new)
    cert
  end

  let(:valid_status) do
    {
      "state" => "COMPLETE",
      "result" => { "endResult" => "OK", "documentNumber" => "PNOEE-38001085718" },
      "signatureProtocol" => "RAW_DIGEST_SIGNATURE",
      "interactionTypeUsed" => "displayTextAndPIN",
      "signature" => {
        "value" => Base64.strict_encode64("sig"),
        "flowType" => "Notification",
        "signatureAlgorithm" => "rsassa-pss",
        "signatureAlgorithmParameters" => {
          "hashAlgorithm" => "SHA-256",
          "maskGenAlgorithm" => {
            "algorithm" => "id-mgf1",
            "parameters" => { "hashAlgorithm" => "SHA-256" }
          },
          "saltLength" => 32,
          "trailerField" => "0xbc"
        }
      },
      "cert" => {
        "value" => Base64.strict_encode64(certificate.to_der),
        "certificateLevel" => "ADVANCED"
      }
    }
  end

  it "returns mapped signature response on valid session status" do
    response = validator.validate(valid_status, "ADVANCED")

    expect(response).to be_a(SmartIdRuby::Models::SignatureResponse)
    expect(response.document_number).to eq("PNOEE-38001085718")
    expect(response.algorithm_name).to eq("rsassa-pss")
    expect(response.certificate_level).to eq("ADVANCED")
  end

  it "raises when session status state is empty" do
    status = valid_status.merge("state" => "")

    expect { validator.validate(status, "ADVANCED") }.to raise_error(
      SmartIdRuby::Errors::UnprocessableResponseError,
      /Signature session status field 'state' is empty/
    )
  end

  it "raises document unusable error for DOCUMENT_UNUSABLE end result" do
    status = valid_status.merge("result" => { "endResult" => "DOCUMENT_UNUSABLE" })

    expect { validator.validate(status, "ADVANCED") }.to raise_error(SmartIdRuby::Errors::DocumentUnusableError)
  end

  it "raises when QUALIFIED certificate is missing QCStatements extension" do
    status = valid_status.merge("cert" => valid_status["cert"].merge("certificateLevel" => "QUALIFIED"))
    policy_extension = instance_double("OpenSSL::X509::Extension", oid: "certificatePolicies", value: "1.3.6.1.4.1.10015.17.2,0.4.0.194112.1.2")
    key_usage_extension = instance_double("OpenSSL::X509::Extension", oid: "keyUsage", value: "Non Repudiation")
    cert_without_qc_statements = instance_double("OpenSSL::X509::Certificate", extensions: [policy_extension, key_usage_extension])
    allow(validator).to receive(:parse_certificate).and_return(cert_without_qc_statements)

    expect { validator.validate(status, "QUALIFIED") }.to raise_error(
      SmartIdRuby::Errors::UnprocessableResponseError,
      /Certificate does not have 'QCStatements' extension/
    )
  end

  it "accepts QUALIFIED certificate when QCStatements contains electronic signature OID" do
    status = valid_status.merge("cert" => valid_status["cert"].merge("certificateLevel" => "QUALIFIED"))
    policy_extension = instance_double("OpenSSL::X509::Extension", oid: "certificatePolicies", value: "1.3.6.1.4.1.10015.17.2,0.4.0.194112.1.2")
    key_usage_extension = instance_double("OpenSSL::X509::Extension", oid: "keyUsage", value: "Non Repudiation")

    statement = OpenSSL::ASN1::Sequence(
      [
        OpenSSL::ASN1::ObjectId("0.4.0.1862.1.6"),
        OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("0.4.0.1862.1.6.1")])
      ]
    )
    qc_payload = OpenSSL::ASN1::Sequence([statement]).to_der
    qc_outer = OpenSSL::ASN1::Sequence(
      [
        OpenSSL::ASN1::ObjectId("1.3.6.1.5.5.7.1.3"),
        OpenSSL::ASN1::OctetString(qc_payload)
      ]
    ).to_der
    qc_extension = instance_double("OpenSSL::X509::Extension", oid: "qcStatements", to_der: qc_outer, value: "")

    cert_with_qc_statements = instance_double(
      "OpenSSL::X509::Certificate",
      extensions: [policy_extension, key_usage_extension, qc_extension]
    )
    allow(validator).to receive(:parse_certificate).and_return(cert_with_qc_statements)

    response = validator.validate(status, "QUALIFIED")
    expect(response.certificate_level).to eq("QUALIFIED")
  end
end
