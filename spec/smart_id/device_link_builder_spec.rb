# frozen_string_literal: true

require "uri"

RSpec.describe SmartIdRuby::DeviceLinkBuilder do
  let(:device_link_base) { "https://smart-id.com/device-link/" }
  let(:session_token) { "token123" }
  let(:session_secret) { Base64.strict_encode64("session-secret") }
  let(:digest) { Base64.strict_encode64("digest") }
  let(:interactions_base64) { Base64.strict_encode64('[{"type":"displayTextAndPIN","displayText60":"Log in"}]') }

  describe "#create_unprotected_uri" do
    it "builds URI for QR flow" do
      uri = described_class.new
        .with_device_link_base(device_link_base)
        .with_session_token(session_token)
        .with_session_type(SmartIdRuby::SessionType::AUTHENTICATION)
        .with_device_link_type(SmartIdRuby::DeviceLinkType::QR_CODE)
        .with_lang("eng")
        .with_elapsed_seconds(1)
        .create_unprotected_uri

      params = URI.decode_www_form(uri.query).to_h
      expect(uri.host).to eq("smart-id.com")
      expect(params["version"]).to eq("1.0")
      expect(params["sessionType"]).to eq("auth")
      expect(params["deviceLinkType"]).to eq("QR")
      expect(params["sessionToken"]).to eq("token123")
      expect(params["elapsedSeconds"]).to eq("1")
    end

    it "raises when elapsedSeconds is missing for QR" do
      expect do
        described_class.new
          .with_device_link_base(device_link_base)
          .with_session_token(session_token)
          .with_session_type(SmartIdRuby::SessionType::AUTHENTICATION)
          .with_device_link_type(SmartIdRuby::DeviceLinkType::QR_CODE)
          .with_lang("eng")
          .create_unprotected_uri
      end.to raise_error(
        SmartIdRuby::Errors::RequestSetupError,
        /elapsedSeconds' must be set when 'deviceLinkType' is QR_CODE/
      )
    end
  end

  describe "#build_device_link" do
    it "adds authCode to QR authentication link" do
      uri = described_class.new
        .with_device_link_base(device_link_base)
        .with_session_token(session_token)
        .with_session_type(SmartIdRuby::SessionType::AUTHENTICATION)
        .with_device_link_type(SmartIdRuby::DeviceLinkType::QR_CODE)
        .with_lang("eng")
        .with_elapsed_seconds(1)
        .with_digest(digest)
        .with_interactions(interactions_base64)
        .with_relying_party_name("DEMO")
        .build_device_link(session_secret)

      params = URI.decode_www_form(uri.query).to_h
      expect(params["authCode"]).to match(/\A[A-Za-z0-9_-]{43}\z/)
    end

    it "accepts interaction objects and encodes them for authCode payload" do
      uri = described_class.new
        .with_device_link_base(device_link_base)
        .with_session_token(session_token)
        .with_session_type(SmartIdRuby::SessionType::AUTHENTICATION)
        .with_device_link_type(SmartIdRuby::DeviceLinkType::QR_CODE)
        .with_lang("eng")
        .with_elapsed_seconds(1)
        .with_digest(digest)
        .with_interactions([SmartIdRuby::NotificationInteraction.display_text_and_pin("Log in")])
        .with_relying_party_name("DEMO")
        .build_device_link(session_secret)

      params = URI.decode_www_form(uri.query).to_h
      expect(params["authCode"]).to match(/\A[A-Za-z0-9_-]{43}\z/)
    end

    it "raises for certificate choice when digest is set" do
      expect do
        described_class.new
          .with_device_link_base(device_link_base)
          .with_session_token(session_token)
          .with_session_type(SmartIdRuby::SessionType::CERTIFICATE_CHOICE)
          .with_device_link_type(SmartIdRuby::DeviceLinkType::QR_CODE)
          .with_lang("eng")
          .with_elapsed_seconds(1)
          .with_digest(digest)
          .with_relying_party_name("DEMO")
          .build_device_link(session_secret)
      end.to raise_error(
        SmartIdRuby::Errors::RequestSetupError,
        /'digest' must be empty when 'sessionType' is CERTIFICATE_CHOICE/
      )
    end

    it "raises for same-device flow without callback URL" do
      expect do
        described_class.new
          .with_device_link_base(device_link_base)
          .with_session_token(session_token)
          .with_session_type(SmartIdRuby::SessionType::AUTHENTICATION)
          .with_device_link_type(SmartIdRuby::DeviceLinkType::APP_2_APP)
          .with_lang("eng")
          .with_digest(digest)
          .with_interactions(interactions_base64)
          .with_relying_party_name("DEMO")
          .build_device_link(session_secret)
      end.to raise_error(
        SmartIdRuby::Errors::RequestSetupError,
        /'initialCallbackUrl' must be provided when 'deviceLinkType' is APP_2_APP or WEB_2_APP/
      )
    end
  end
end
