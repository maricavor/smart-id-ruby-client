# frozen_string_literal: true

RSpec.describe SmartIdRuby::Rest::Connector do
  subject(:connector) { described_class.new(host_url: "https://sid.example.test/v3/") }

  # A Faraday error raised by the adapter — a timeout or a dropped connection — carries no
  # response hash. Reading error.response[:status] on one raises NoMethodError and buries
  # the real failure.
  describe "errors raised without a response" do
    it "maps a timeout to NetworkTimeoutError" do
      expect { connector.send(:handle_faraday_error, Faraday::TimeoutError.new("execution expired"), "session/1") }
        .to raise_error(SmartIdRuby::Errors::NetworkTimeoutError)
    end

    it "maps a dropped connection to a response error" do
      expect { connector.send(:handle_faraday_error, Faraday::ConnectionFailed.new("connection reset"), "session/1") }
        .to raise_error(SmartIdRuby::Errors::ResponseError, /connection reset/)
    end

    it "maps a server error without a response to a response error" do
      expect { connector.send(:handle_faraday_error, Faraday::ServerError.new("boom"), "session/1") }
        .to raise_error(SmartIdRuby::Errors::ResponseError, /boom/)
    end

    it "maps a client error without a response to a response error" do
      expect { connector.send(:handle_faraday_error, Faraday::ClientError.new("odd"), "session/1") }
        .to raise_error(SmartIdRuby::Errors::ResponseError, /odd/)
    end

    it "never raises NoMethodError" do
      [Faraday::TimeoutError.new("t"), Faraday::ConnectionFailed.new("c"),
       Faraday::ServerError.new("s"), Faraday::ClientError.new("c")].each do |error|
        expect { connector.send(:handle_faraday_error, error, "session/1") }
          .to raise_error(SmartIdRuby::Errors::Error)
      end
    end
  end

  describe "errors that do carry a response" do
    it "still maps 580 to server maintenance" do
      error = Faraday::ServerError.new(nil, { status: 580, body: "maintenance" })

      expect { connector.send(:handle_faraday_error, error, "session/1") }
        .to raise_error(SmartIdRuby::Errors::ServerMaintenanceError)
    end

    it "still maps 471 to no suitable account" do
      error = Faraday::ClientError.new(nil, { status: 471, body: "" })

      expect { connector.send(:handle_faraday_error, error, "session/1") }
        .to raise_error(SmartIdRuby::Errors::NoSuitableAccountOfRequestedTypeFoundError)
    end

    it "still maps 472 to person should view the Smart-ID portal" do
      error = Faraday::ClientError.new(nil, { status: 472, body: "" })

      expect { connector.send(:handle_faraday_error, error, "session/1") }
        .to raise_error(SmartIdRuby::Errors::PersonShouldViewSmartIdPortalError)
    end

    it "still maps 480 to an unsupported client API version" do
      error = Faraday::ClientError.new(nil, { status: 480, body: "" })

      expect { connector.send(:handle_faraday_error, error, "session/1") }
        .to raise_error(SmartIdRuby::Errors::UnsupportedClientApiVersionError)
    end

    it "still maps 401 to a relying party configuration error" do
      error = Faraday::UnauthorizedError.new(nil, { status: 401, body: "" })

      expect { connector.send(:handle_faraday_error, error, "session/1") }
        .to raise_error(SmartIdRuby::Errors::RelyingPartyAccountConfigurationError)
    end
  end

  describe "a long poll that times out" do
    it "surfaces as NetworkTimeoutError rather than NoMethodError" do
      connection = instance_double(Faraday::Connection)
      allow(connection).to receive(:get).and_raise(Faraday::TimeoutError.new("execution expired"))
      allow(connector).to receive(:connection).and_return(connection)

      expect { connector.get_session_status("session-id") }
        .to raise_error(SmartIdRuby::Errors::NetworkTimeoutError)
    end
  end
end
