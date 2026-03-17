# frozen_string_literal: true

RSpec.describe SmartIdRuby::Flows::NotificationCertificateChoiceSessionRequestBuilder do
  class NotificationCertificateChoiceTestConnector
    attr_reader :called_request, :called_semantics_identifier
    attr_accessor :response

    def initialize
      @response = { "sessionID" => "00000000-0000-0000-0000-000000000000" }
    end

    def init_notification_certificate_choice(request, semantics_identifier)
      @called_request = request
      @called_semantics_identifier = semantics_identifier
      response
    end
  end

  let(:connector) { NotificationCertificateChoiceTestConnector.new }
  let(:builder) { described_class.new(connector) }

  before do
    builder.with_relying_party_uuid("00000000-0000-4000-8000-000000000000")
    builder.with_relying_party_name("DEMO")
    builder.with_semantics_identifier("PNOEE-48010010101")
  end

  it "inits certificate choice with semantics identifier" do
    builder.init_certificate_choice

    expect(connector.called_semantics_identifier).to eq("PNOEE-48010010101")
    expect(connector.called_request[:relyingPartyUUID]).to eq("00000000-0000-4000-8000-000000000000")
    expect(connector.called_request[:relyingPartyName]).to eq("DEMO")
  end

  it "maps certificate level and nonce when set" do
    builder.with_certificate_level("QSCD")
    builder.with_nonce("nonce-1")
    builder.init_certificate_choice

    expect(connector.called_request[:certificateLevel]).to eq("QSCD")
    expect(connector.called_request[:nonce]).to eq("nonce-1")
  end

  it "maps requestProperties when share_md_client_ip_address is set" do
    builder.with_share_md_client_ip_address(true)
    builder.init_certificate_choice

    expect(connector.called_request[:requestProperties]).to eq({ shareMdClientIpAddress: true })
  end

  it "maps capabilities as trimmed unique values" do
    builder.with_capabilities("A", " ", nil, "A", "B")
    builder.init_certificate_choice

    expect(connector.called_request[:capabilities]).to eq(%w[A B])
  end

  it "raises when semantics identifier is missing" do
    builder.with_semantics_identifier(nil)

    expect { builder.init_certificate_choice }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /Value for 'semanticIdentifier' must be set/
    )
  end

  it "raises when relying party uuid is missing" do
    builder.with_relying_party_uuid(nil)

    expect { builder.init_certificate_choice }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /Value for 'relyingPartyUUID' cannot be empty/
    )
  end

  it "raises when nonce is invalid" do
    builder.with_nonce("")

    expect { builder.init_certificate_choice }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /Value for 'nonce' length must be between 1 and 30 characters/
    )
  end

  it "raises when response sessionID is missing" do
    connector.response = { "sessionID" => "" }

    expect { builder.init_certificate_choice }.to raise_error(
      SmartIdRuby::Errors::UnprocessableResponseError,
      /Notification-based certificate choice response field 'sessionID' is missing or empty/
    )
  end
end
