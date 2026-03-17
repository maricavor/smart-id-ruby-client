# frozen_string_literal: true

RSpec.describe SmartIdRuby::CallbackUrlUtil do
  describe ".create_callback_url" do
    it "returns callback url with generated token in value query param" do
      callback_url = described_class.create_callback_url("https://example.com/auth/sid_plus/web2app/callback")
      uri = URI.parse(callback_url.url)
      params = URI.decode_www_form(uri.query.to_s).to_h

      expect(uri.scheme).to eq("https")
      expect(params["value"]).to eq(callback_url.token)
      expect(callback_url.token).not_to be_empty
    end

    it "raises when base url is empty" do
      expect { described_class.create_callback_url(" ") }.to raise_error(
        SmartIdRuby::Errors::RequestSetupError,
        /Parameter for 'baseUrl' cannot be empty/
      )
    end
  end

  describe ".validate_session_secret_digest" do
    it "passes when callback digest matches calculated value" do
      session_secret = Base64.strict_encode64("test-secret")
      digest = Base64.urlsafe_encode64(
        OpenSSL::Digest::SHA256.digest(Base64.strict_decode64(session_secret)),
        padding: false
      )

      expect { described_class.validate_session_secret_digest(digest, session_secret) }.not_to raise_error
    end

    it "raises mismatch error when digest does not match" do
      session_secret = Base64.strict_encode64("test-secret")

      expect { described_class.validate_session_secret_digest("invalidDigest", session_secret) }.to raise_error(
        SmartIdRuby::Errors::SessionSecretMismatchError,
        /does not match/
      )
    end

    it "raises when session secret is not valid base64" do
      expect { described_class.validate_session_secret_digest("abc", "%%%") }.to raise_error(
        SmartIdRuby::Errors::RequestSetupError,
        /not Base64-encoded value/
      )
    end
  end
end
