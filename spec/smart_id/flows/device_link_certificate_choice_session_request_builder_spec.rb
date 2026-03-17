# frozen_string_literal: true

RSpec.describe SmartIdRuby::Flows::DeviceLinkCertificateChoiceSessionRequestBuilder do
  class DeviceLinkCertificateChoiceTestConnector
    attr_reader :called_request
    attr_accessor :response

    def initialize
      @response = {
        "sessionID" => "test-session-id",
        "sessionToken" => "test-session-token",
        "sessionSecret" => "test-session-secret",
        "deviceLinkBase" => "https://example.com/device-link"
      }
    end

    def init_device_link_certificate_choice(request)
      @called_request = request
      response
    end
  end

  let(:connector) { DeviceLinkCertificateChoiceTestConnector.new }
  let(:builder) { described_class.new(connector) }

  before do
    builder.with_relying_party_uuid("test-relying-party-uuid")
    builder.with_relying_party_name("DEMO")
    builder.with_certificate_level("QUALIFIED")
    builder.with_nonce("1234567890")
    builder.with_initial_callback_url("https://example.com/callback")
  end

  it "initiates certificate choice and maps request payload" do
    response = builder.init_certificate_choice

    expect(response["sessionID"]).to eq("test-session-id")
    expect(connector.called_request).to include(
      relyingPartyUUID: "test-relying-party-uuid",
      relyingPartyName: "DEMO",
      certificateLevel: "QUALIFIED",
      nonce: "1234567890",
      initialCallbackUrl: "https://example.com/callback"
    )
  end

  it "maps capabilities as trimmed unique values" do
    builder.with_capabilities("A", " ", nil, "A", "B")
    builder.init_certificate_choice

    expect(connector.called_request[:capabilities]).to eq(%w[A B])
  end

  it "maps requestProperties when share_md_client_ip_address is set" do
    builder.with_share_md_client_ip_address(true)
    builder.init_certificate_choice

    expect(connector.called_request[:requestProperties]).to eq({ shareMdClientIpAddress: true })
  end

  it "accepts nil nonce and nil initial callback URL" do
    builder.with_nonce(nil)
    builder.with_initial_callback_url(nil)

    expect { builder.init_certificate_choice }.not_to raise_error
  end

  it "raises when relyingPartyUUID is missing" do
    builder.with_relying_party_uuid(nil)

    expect { builder.init_certificate_choice }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /Value for 'relyingPartyUUID' cannot be empty/
    )
  end

  it "raises when nonce length is invalid" do
    builder.with_nonce("")

    expect { builder.init_certificate_choice }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /Value for 'nonce' must have length between 1 and 30 characters/
    )
  end

  it "raises when initial callback URL is invalid" do
    builder.with_initial_callback_url("http://example.com")

    expect { builder.init_certificate_choice }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /Value for 'initialCallbackUrl' must match pattern \^https:\/\/\[\^\|\]\+\$/
    )
  end

  it "raises when response sessionToken is missing" do
    connector.response = {
      "sessionID" => "test-session-id",
      "sessionToken" => "",
      "sessionSecret" => "test-session-secret",
      "deviceLinkBase" => "https://example.com/device-link"
    }

    expect { builder.init_certificate_choice }.to raise_error(
      SmartIdRuby::Errors::UnprocessableResponseError,
      /response field 'sessionToken' is missing or empty/
    )
  end
end
