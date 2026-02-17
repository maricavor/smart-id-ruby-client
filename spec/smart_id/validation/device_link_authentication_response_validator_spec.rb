# frozen_string_literal: true

RSpec.describe SmartId::Validation::DeviceLinkAuthenticationResponseValidator do
  subject(:validator) { described_class.new }

  let(:authentication_session_request) do
    { certificateLevel: "QUALIFIED" }
  end

  let(:valid_status) do
    SmartId::Models::SessionStatus.from_h(
      {
        state: "COMPLETE",
        result: { endResult: "OK", documentNumber: "PNOLT-40504040001-MOCK-Q" },
        signatureProtocol: "ACSP_V2",
        signature: {
          value: Base64.strict_encode64("signature-bytes"),
          serverRandom: Base64.strict_encode64("server-random-123456"),
          userChallenge: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi12345678",
          flowType: "QR",
          signatureAlgorithm: "rsassa-pss"
        },
        cert: {
          value: "base64-certificate-value",
          certificateLevel: "QUALIFIED"
        },
        interactionTypeUsed: "displayTextAndPIN",
        deviceIpAddress: "127.0.0.1"
      }
    )
  end

  it "returns typed authentication response for valid status" do
    response = validator.validate(valid_status, authentication_session_request)

    expect(response).to be_a(SmartId::Models::AuthenticationResponse)
    expect(response.end_result).to eq("OK")
    expect(response.document_number).to eq("PNOLT-40504040001-MOCK-Q")
    expect(response.certificate_level).to eq("QUALIFIED")
  end

  it "raises when session is not complete" do
    running = SmartId::Models::SessionStatus.from_h(state: "RUNNING")

    expect { validator.validate(running, authentication_session_request) }.to raise_error(
      SmartId::Errors::SessionNotCompleteError
    )
  end

  it "raises mapped end-result error when endResult is not OK" do
    timeout_status = SmartId::Models::SessionStatus.from_h(
      state: "COMPLETE",
      result: { endResult: "TIMEOUT", documentNumber: "PNOLT-40504040001-MOCK-Q" }
    )

    expect { validator.validate(timeout_status, authentication_session_request) }.to raise_error(
      SmartId::Errors::SessionEndResultError,
      "Session timed out without getting any response from user"
    )
  end

  it "uses java-equivalent USER_REFUSED_INTERACTION message when details are present" do
    refused_status = SmartId::Models::SessionStatus.from_h(
      state: "COMPLETE",
      result: {
        endResult: "USER_REFUSED_INTERACTION",
        documentNumber: "PNOLT-40504040001-MOCK-Q",
        details: { interaction: "displayTextAndPIN" }
      }
    )

    expect { validator.validate(refused_status, authentication_session_request) }.to raise_error(
      SmartId::Errors::SessionEndResultError,
      "User pressed Cancel on PIN screen."
    )
  end

  it "raises when required signature field is missing" do
    invalid = SmartId::Models::SessionStatus.from_h(
      state: "COMPLETE",
      result: { endResult: "OK", documentNumber: "PNOLT-40504040001-MOCK-Q" },
      signatureProtocol: "ACSP_V2",
      signature: {
        value: Base64.strict_encode64("signature-bytes"),
        serverRandom: Base64.strict_encode64("server-random-123456"),
        flowType: "QR",
        signatureAlgorithm: "rsassa-pss"
      },
      cert: { value: "base64-certificate-value", certificateLevel: "QUALIFIED" },
      interactionTypeUsed: "displayTextAndPIN"
    )

    expect { validator.validate(invalid, authentication_session_request) }.to raise_error(
      SmartId::Errors::UnprocessableResponseError,
      /signature\.userChallenge/
    )
  end

  it "raises when certificate level is lower than requested level" do
    advanced_cert_status = SmartId::Models::SessionStatus.from_h(
      state: "COMPLETE",
      result: { endResult: "OK", documentNumber: "PNOLT-40504040001-MOCK-Q" },
      signatureProtocol: "ACSP_V2",
      signature: {
        value: Base64.strict_encode64("signature-bytes"),
        serverRandom: Base64.strict_encode64("server-random-123456"),
        userChallenge: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi12345678",
        flowType: "QR",
        signatureAlgorithm: "rsassa-pss"
      },
      cert: { value: "base64-certificate-value", certificateLevel: "ADVANCED" },
      interactionTypeUsed: "displayTextAndPIN"
    )

    expect { validator.validate(advanced_cert_status, authentication_session_request) }.to raise_error(
      SmartId::Errors::UnprocessableResponseError,
      /lower than requested level/
    )
  end
end
