# frozen_string_literal: true

RSpec.describe SmartIdRuby::Validation::NotificationAuthenticationResponseValidator do
  let(:delegate_validator) { instance_double(SmartIdRuby::Validation::DeviceLinkAuthenticationResponseValidator) }
  let(:validator) do
    described_class.new(
      device_link_authentication_response_validator: delegate_validator
    )
  end

  let(:certificate) do
    key = OpenSSL::PKey::RSA.new(1024)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.new(
      [
        ["C", "EE", OpenSSL::ASN1::PRINTABLESTRING],
        ["SN", "TAMM", OpenSSL::ASN1::UTF8STRING],
        ["GN", "TOOMAS", OpenSSL::ASN1::UTF8STRING],
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

  it "delegates validation and maps certificate to authentication identity" do
    mapped_identity = SmartIdRuby::Models::AuthenticationIdentity.new(
      given_name: "TOOMAS",
      surname: "TAMM",
      identity_number: "38001085718",
      country: "EE",
      auth_certificate: certificate
    )
    expect(delegate_validator).to receive(:validate)
      .with(:status, :request, nil, "SMART_ID", "BROKER")
      .and_return(mapped_identity)

    identity = validator.validate(:status, :request, "SMART_ID", "BROKER")
    expect(identity).to eq(mapped_identity)
  end
end
