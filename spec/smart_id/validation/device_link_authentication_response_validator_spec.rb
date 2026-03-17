# frozen_string_literal: true

RSpec.describe SmartIdRuby::Validation::DeviceLinkAuthenticationResponseValidator do
  subject(:validator) { described_class.new }
  let(:schema_name) { "smart-id-demo" }
  let(:brokered_rp_name) { nil }
  let(:rp_challenge) { Base64.strict_encode64("x" * 32) }
  let(:interactions) do
    Base64.strict_encode64(JSON.generate([{ type: "displayTextAndPIN", displayText60: "Log in" }]))
  end

  let(:authentication_session_request) do
    {
      relyingPartyName: "DEMO",
      certificateLevel: "ADVANCED",
      signatureProtocolParameters: {
        rpChallenge: rp_challenge
      },
      interactions: interactions,
      initialCallbackUrl: "https://example.com/callback"
    }
  end
  let(:certificate_fixture) { generate_certificate_fixture }
  let(:advanced_certificate_value) { certificate_fixture[:certificate_value] }
  let(:private_key) { certificate_fixture[:private_key] }
  let(:default_user_challenge) { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi12345678" }

  let(:valid_status) do
    signed_status(flow_type: "QR", user_challenge: default_user_challenge)
  end

  it "returns mapped authentication identity for valid status" do
    identity = validator.validate(valid_status, authentication_session_request, nil, schema_name, brokered_rp_name)

    expect(identity).to be_a(SmartIdRuby::Models::AuthenticationIdentity)
  end

  it "raises when session is not complete" do
    running = SmartIdRuby::Models::SessionStatus.from_h(state: "RUNNING")

    expect { validator.validate(running, authentication_session_request, nil, schema_name, brokered_rp_name) }.to raise_error(
      SmartIdRuby::Errors::SessionNotCompleteError
    )
  end

  it "raises mapped end-result error when endResult is not OK" do
    timeout_status = SmartIdRuby::Models::SessionStatus.from_h(
      state: "COMPLETE",
      result: { endResult: "TIMEOUT", documentNumber: "PNOLT-40504040001-MOCK-Q" }
    )

    expect { validator.validate(timeout_status, authentication_session_request, nil, schema_name, brokered_rp_name) }.to raise_error(
      SmartIdRuby::Errors::SessionEndResultError,
      "Session timed out without getting any response from user"
    )
  end

  it "maps USER_REFUSED_INTERACTION displayTextAndPIN to specific exception class" do
    refused_status = SmartIdRuby::Models::SessionStatus.from_h(
      state: "COMPLETE",
      result: {
        endResult: "USER_REFUSED_INTERACTION",
        documentNumber: "PNOLT-40504040001-MOCK-Q",
        details: { interaction: "displayTextAndPIN" }
      }
    )

    expect { validator.validate(refused_status, authentication_session_request, nil, schema_name, brokered_rp_name) }.to raise_error(
      SmartIdRuby::Errors::UserRefusedDisplayTextAndPinError,
      "User pressed Cancel on PIN screen."
    )
  end

  it "maps USER_REFUSED_INTERACTION confirmationMessage to specific exception class" do
    refused_status = SmartIdRuby::Models::SessionStatus.from_h(
      state: "COMPLETE",
      result: {
        endResult: "USER_REFUSED_INTERACTION",
        documentNumber: "PNOLT-40504040001-MOCK-Q",
        details: { interaction: "confirmationMessage" }
      }
    )

    expect { validator.validate(refused_status, authentication_session_request, nil, schema_name, brokered_rp_name) }.to raise_error(
      SmartIdRuby::Errors::UserRefusedConfirmationMessageError,
      "User cancelled on confirmationMessage screen"
    )
  end

  it "maps USER_REFUSED_INTERACTION confirmationMessageAndVerificationCodeChoice to specific exception class" do
    refused_status = SmartIdRuby::Models::SessionStatus.from_h(
      state: "COMPLETE",
      result: {
        endResult: "USER_REFUSED_INTERACTION",
        documentNumber: "PNOLT-40504040001-MOCK-Q",
        details: { interaction: "confirmationMessageAndVerificationCodeChoice" }
      }
    )

    expect { validator.validate(refused_status, authentication_session_request, nil, schema_name, brokered_rp_name) }.to raise_error(
      SmartIdRuby::Errors::UserRefusedConfirmationMessageWithVerificationChoiceError,
      "User cancelled on confirmationMessageAndVerificationCodeChoice screen"
    )
  end

  it "raises unprocessable error when USER_REFUSED_INTERACTION details are missing" do
    refused_status = SmartIdRuby::Models::SessionStatus.from_h(
      state: "COMPLETE",
      result: {
        endResult: "USER_REFUSED_INTERACTION",
        documentNumber: "PNOLT-40504040001-MOCK-Q"
      }
    )

    expect { validator.validate(refused_status, authentication_session_request, nil, schema_name, brokered_rp_name) }.to raise_error(
      SmartIdRuby::Errors::UnprocessableResponseError,
      "Details for refused interaction are missing"
    )
  end

  it "raises unprocessable error when USER_REFUSED_INTERACTION type is unknown" do
    refused_status = SmartIdRuby::Models::SessionStatus.from_h(
      state: "COMPLETE",
      result: {
        endResult: "USER_REFUSED_INTERACTION",
        documentNumber: "PNOLT-40504040001-MOCK-Q",
        details: { interaction: "unknownInteraction" }
      }
    )

    expect { validator.validate(refused_status, authentication_session_request, nil, schema_name, brokered_rp_name) }.to raise_error(
      SmartIdRuby::Errors::UnprocessableResponseError,
      "Unexpected interaction type: unknownInteraction"
    )
  end

  it "raises when required signature field is missing" do
    invalid = signed_status(flow_type: "QR", user_challenge: nil)

    expect { validator.validate(invalid, authentication_session_request, nil, schema_name, brokered_rp_name) }.to raise_error(
      SmartIdRuby::Errors::UnprocessableResponseError,
      /signature\.userChallenge/
    )
  end

  it "raises when certificate level is lower than requested level" do
    advanced_cert_status = signed_status(flow_type: "QR", user_challenge: default_user_challenge)

    expect { validator.validate(advanced_cert_status, { certificateLevel: "QUALIFIED" }, nil, schema_name, brokered_rp_name) }.to raise_error(
      SmartIdRuby::Errors::UnprocessableResponseError,
      "Signer's certificate is below requested certificate level"
    )
  end

  it "requires schemaName" do
    expect { validator.validate(valid_status, authentication_session_request) }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      "Parameter 'schemaName' is not provided"
    )
  end

  it "requires userChallengeVerifier for Web2App flow" do
    web2app = signed_status(flow_type: "Web2App", user_challenge: default_user_challenge)

    expect { validator.validate(web2app, authentication_session_request, nil, schema_name, brokered_rp_name) }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      "Parameter 'userChallengeVerifier' must be provided for 'flowType' - Web2App"
    )
  end

  it "validates userChallengeVerifier digest for same-device flow" do
    verifier = "test-verifier"
    user_challenge = Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(verifier), padding: false)
    app2app = signed_status(flow_type: "App2App", user_challenge: user_challenge)

    expect { validator.validate(app2app, authentication_session_request, "wrong", schema_name, brokered_rp_name) }.to raise_error(
      SmartIdRuby::Errors::UnprocessableResponseError,
      "Device link authentication 'signature.userChallenge' does not validate with 'userChallengeVerifier'"
    )

    identity = validator.validate(app2app, authentication_session_request, verifier, schema_name, brokered_rp_name)
    expect(identity).to be_a(SmartIdRuby::Models::AuthenticationIdentity)
  end

  it "raises when signature value does not match calculated signature" do
    invalid_signature_status = signed_status(
      flow_type: "QR",
      user_challenge: default_user_challenge,
      signature_value_override: Base64.strict_encode64("invalid-signature")
    )

    expect do
      validator.validate(invalid_signature_status, authentication_session_request, nil, schema_name, brokered_rp_name)
    end.to raise_error(
      SmartIdRuby::Errors::UnprocessableResponseError,
      "Provided signature value does not match the calculated signature value"
    )
  end

  def signed_status(flow_type:, user_challenge:, signature_value_override: nil)
    signature_payload = {
      serverRandom: Base64.strict_encode64("server-random-123456"),
      userChallenge: user_challenge,
      flowType: flow_type,
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
    }
    signature_value = signature_value_override || sign_signature_value(signature_payload)
    signature_payload[:value] = signature_value

    SmartIdRuby::Models::SessionStatus.from_h(
      {
        state: "COMPLETE",
        result: { endResult: "OK", documentNumber: "PNOLT-40504040001-MOCK-Q" },
        signatureProtocol: "ACSP_V2",
        signature: signature_payload,
        cert: {
          value: advanced_certificate_value,
          certificateLevel: "ADVANCED"
        },
        interactionTypeUsed: "displayTextAndPIN",
        deviceIpAddress: "127.0.0.1"
      }
    )
  end

  def sign_signature_value(signature_payload)
    payload = construct_payload(signature_payload)
    digest = OpenSSL::Digest::SHA256.new
    signature = private_key.sign_pss(digest, payload, salt_length: 32, mgf1_hash: "SHA256")
    Base64.strict_encode64(signature)
  end

  def construct_payload(signature_payload)
    [
      schema_name,
      "ACSP_V2",
      signature_payload[:serverRandom],
      authentication_session_request[:signatureProtocolParameters][:rpChallenge],
      signature_payload[:userChallenge] || "",
      Base64.strict_encode64(authentication_session_request[:relyingPartyName].encode("UTF-8")),
      "",
      Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(authentication_session_request[:interactions].to_s)),
      "displayTextAndPIN",
      signature_payload[:flowType] == "QR" ? "" : authentication_session_request[:initialCallbackUrl],
      signature_payload[:flowType]
    ].join("|")
  end

  def generate_certificate_fixture
    key = OpenSSL::PKey::RSA.new(1024)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = Random.rand(1..999_999)
    cert.subject = OpenSSL::X509::Name.parse("/CN=Smart-ID Test")
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = cert
    cert.add_extension(ef.create_extension("basicConstraints", "CA:FALSE", true))
    cert.add_extension(ef.create_extension("keyUsage", "digitalSignature", true))
    cert.add_extension(ef.create_extension("extendedKeyUsage", "clientAuth", false))
    cert.sign(key, OpenSSL::Digest::SHA256.new)
    {
      certificate_value: Base64.strict_encode64(cert.to_der),
      private_key: key
    }
  end
end
