# frozen_string_literal: true

RSpec.describe SmartId::Rest::SessionStatusPoller do
  class PollerTestConnector
    attr_reader :session_ids

    def initialize(statuses)
      @statuses = statuses.dup
      @session_ids = []
    end

    def get_session_status(session_id)
      @session_ids << session_id
      @statuses.shift
    end
  end

  it "delegates single status query to connector" do
    connector = PollerTestConnector.new([SmartId::Models::SessionStatus.from_h({ "state" => "RUNNING" })])
    poller = described_class.new(connector)

    response = poller.get_session_status("session-123")

    expect(response).to be_a(SmartId::Models::SessionStatus)
    expect(response).to be_running
    expect(connector.session_ids).to eq(["session-123"])
  end

  it "polls until state is COMPLETE and returns final status" do
    connector = PollerTestConnector.new(
      [
        SmartId::Models::SessionStatus.from_h({ "state" => "RUNNING" }),
        SmartId::Models::SessionStatus.from_h({ "state" => "RUNNING" }),
        SmartId::Models::SessionStatus.from_h({ "state" => "COMPLETE", "result" => { "endResult" => "OK" } })
      ]
    )
    poller = described_class.new(connector)
    poller.set_polling_sleep_time(:milliseconds, 0)

    response = poller.fetch_final_session_status("session-456")

    expect(response).to be_a(SmartId::Models::SessionStatus)
    expect(response).to be_complete
    expect(response.result.end_result).to eq("OK")
    expect(connector.session_ids).to eq(["session-456", "session-456", "session-456"])
  end
end
