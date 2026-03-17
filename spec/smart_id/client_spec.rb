# frozen_string_literal: true

RSpec.describe SmartIdRuby::Client do
  subject(:client) { described_class.new }

  before do
    client.relying_party_uuid = "00000000-0000-4000-8000-000000000000"
    client.relying_party_name = "DEMO"
    client.host_url = "https://sid.demo.sk.ee/smart-id-rp/v3/"
  end

  it "creates flow builders with default relying party values" do
    builder = client.create_device_link_authentication

    expect(builder).to be_a(SmartIdRuby::Flows::DeviceLinkAuthenticationSessionRequestBuilder)
    expect(builder.relying_party_uuid).to eq(client.relying_party_uuid)
    expect(builder.relying_party_name).to eq(client.relying_party_name)
  end

  it "creates notification authentication builder with default relying party values" do
    builder = client.create_notification_authentication

    expect(builder).to be_a(SmartIdRuby::Flows::NotificationAuthenticationSessionRequestBuilder)
    expect(builder.relying_party_uuid).to eq(client.relying_party_uuid)
    expect(builder.relying_party_name).to eq(client.relying_party_name)
  end

  it "creates notification signature builder with default relying party values" do
    builder = client.create_notification_signature

    expect(builder).to be_a(SmartIdRuby::Flows::NotificationSignatureSessionRequestBuilder)
    expect(builder.relying_party_uuid).to eq(client.relying_party_uuid)
    expect(builder.relying_party_name).to eq(client.relying_party_name)
  end

  it "creates linked notification signature builder with default relying party values" do
    builder = client.create_linked_notification_signature

    expect(builder).to be_a(SmartIdRuby::Flows::LinkedNotificationSignatureSessionRequestBuilder)
    expect(builder.relying_party_uuid).to eq(client.relying_party_uuid)
    expect(builder.relying_party_name).to eq(client.relying_party_name)
  end

  it "creates device-link signature builder with default relying party values" do
    builder = client.create_device_link_signature

    expect(builder).to be_a(SmartIdRuby::Flows::DeviceLinkSignatureSessionRequestBuilder)
    expect(builder.relying_party_uuid).to eq(client.relying_party_uuid)
    expect(builder.relying_party_name).to eq(client.relying_party_name)
  end

  it "creates device-link certificate-choice builder with default relying party values" do
    builder = client.create_device_link_certificate_request

    expect(builder).to be_a(SmartIdRuby::Flows::DeviceLinkCertificateChoiceSessionRequestBuilder)
    expect(builder.relying_party_uuid).to eq(client.relying_party_uuid)
    expect(builder.relying_party_name).to eq(client.relying_party_name)
  end

  it "creates notification certificate-choice builder with default relying party values" do
    builder = client.create_notification_certificate_choice

    expect(builder).to be_a(SmartIdRuby::Flows::NotificationCertificateChoiceSessionRequestBuilder)
    expect(builder.relying_party_uuid).to eq(client.relying_party_uuid)
    expect(builder.relying_party_name).to eq(client.relying_party_name)
  end

  it "creates certificate-by-document-number builder with default relying party values" do
    builder = client.create_certificate_by_document_number

    expect(builder).to be_a(SmartIdRuby::Flows::CertificateByDocumentNumberRequestBuilder)
    expect(builder.relying_party_uuid).to eq(client.relying_party_uuid)
    expect(builder.relying_party_name).to eq(client.relying_party_name)
  end

  it "creates a session status poller with default polling interval" do
    poller = client.session_status_poller

    expect(poller).to be_a(SmartIdRuby::Rest::SessionStatusPoller)
    expect(poller.polling_sleep_time).to eq({ unit: :seconds, timeout: 1 })
  end

  it "raises when host_url is missing before connector initialization" do
    client.host_url = nil

    expect { client.smart_id_connector }.to raise_error(
      SmartIdRuby::Errors::RequestSetupError,
      /host_url/
    )
  end
end
