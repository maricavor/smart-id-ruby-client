# frozen_string_literal: true

RSpec.describe SmartId::Validation::NotificationAuthenticationResponseValidator do
  let(:delegate_validator) { instance_double(SmartId::Validation::DeviceLinkAuthenticationResponseValidator) }
  let(:identity_mapper) { instance_double(SmartId::Validation::AuthenticationIdentityMapper) }
  let(:validator) do
    described_class.new(
      device_link_authentication_response_validator: delegate_validator,
      authentication_identity_mapper: identity_mapper
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
    response = SmartId::Models::AuthenticationResponse.new(
      end_result: "OK",
      document_number: "PNOEE-38001085718",
      signature_value: "c2ln",
      server_random: "c2VydmVycmFuZG9tZGF0YQ==",
      user_challenge: "123",
      flow_type: "Notification",
      signature_algorithm: "rsassa-pss",
      certificate_value: Base64.strict_encode64(certificate.to_der),
      certificate_level: "QUALIFIED",
      interaction_type_used: "displayTextAndPIN",
      device_ip_address: nil
    )
    expect(delegate_validator).to receive(:validate)
      .with(:status, :request, nil, "SMART_ID", "BROKER")
      .and_return(response)

    mapped_identity = SmartId::Models::AuthenticationIdentity.new(
      given_name: "TOOMAS",
      surname: "TAMM",
      identity_number: "38001085718",
      country: "EE",
      auth_certificate: certificate
    )
    expect(identity_mapper).to receive(:from).with(instance_of(OpenSSL::X509::Certificate)).and_return(mapped_identity)

    identity = validator.validate(:status, :request, "SMART_ID", "BROKER")
    expect(identity).to eq(mapped_identity)
  end
end
