# frozen_string_literal: true

RSpec.describe SmartIdRuby::Validation::BaseAuthenticationResponseValidator do
  let(:validator_class) do
    Class.new(described_class)
  end

  let(:signature_value_validator) { instance_double(SmartIdRuby::Validation::SignatureValueValidator, validate: true) }
  let(:certificate_validator) { instance_double(SmartIdRuby::Validation::AuthenticationCertificateValidator) }
  let(:authentication_identity_mapper) { instance_double(SmartIdRuby::Validation::AuthenticationIdentityMapper) }
  let(:validator) do
    validator_class.new(
      signature_value_validator: signature_value_validator,
      certificate_validator: certificate_validator,
      authentication_identity_mapper: authentication_identity_mapper
    )
  end

  let(:certificate) do
    key = OpenSSL::PKey::RSA.new(1024)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse("/CN=Smart-ID Test")
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert
  end

  it "uses empty callback payload segment by default" do
    request = {
      relyingPartyName: "DEMO",
      signatureProtocolParameters: { rpChallenge: Base64.strict_encode64("x" * 32) },
      interactions: Base64.strict_encode64('[{"type":"displayTextAndPIN"}]')
    }
    status = SmartIdRuby::Models::SessionStatus.from_h(
      {
        state: "COMPLETE",
        result: { endResult: "OK", documentNumber: "PNOLT-40504040001-MOCK-Q" },
        signatureProtocol: "ACSP_V2",
        signature: {
          value: Base64.strict_encode64("signature"),
          serverRandom: Base64.strict_encode64("server-random-123456"),
          userChallenge: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi12345678",
          flowType: "Notification",
          signatureAlgorithm: "rsassa-pss",
          signatureAlgorithmParameters: {
            hashAlgorithm: "SHA-256",
            maskGenAlgorithm: {
              algorithm: "id-mgf1",
              parameters: { hashAlgorithm: "SHA-256" }
            },
            saltLength: 32,
            trailerField: "0xbc"
          }
        },
        cert: {
          value: Base64.strict_encode64(certificate.to_der),
          certificateLevel: "ADVANCED"
        },
        interactionTypeUsed: "displayTextAndPIN"
      }
    )

    allow(certificate_validator).to receive(:validate).and_return(certificate)
    allow(authentication_identity_mapper).to receive(:from).and_return(:identity)
    expect(signature_value_validator).to receive(:validate).with(
      hash_including(payload: include("|displayTextAndPIN||Notification"))
    )

    expect(validator.validate(status, request, nil, "SMART_ID", "BROKER")).to eq(:identity)
  end
end
