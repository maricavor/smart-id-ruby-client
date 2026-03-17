# smart_id

Ruby client gem for integrating Smart-ID RP API v3.1 into Ruby applications.

This gem follows the same high-level flow model as the Smart-ID Java client:

- start session (authentication / certificate choice / signature)
- poll session status
- validate final session response

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick setup](#quick-setup)
- [Logging](#logging)
- [Interactions](#interactions)
- [Flows](#flows)
  - [Notification authentication](#notification-authentication)
  - [Device-link authentication](#device-link-authentication)
  - [Notification signature](#notification-signature)
  - [Device-link signature](#device-link-signature)
  - [Certificate by document number](#certificate-by-document-number)
  - [Device-link certificate choice + linked notification signature](#device-link-certificate-choice--linked-notification-signature)
  - [Notification certificate choice](#notification-certificate-choice)
- [Generating device link and QR-code](#generating-device-link-and-qr-code)
- [Session status polling](#session-status-polling)
- [Response validation](#response-validation)
- [Network and SSL configuration](#network-and-ssl-configuration)
- [Exception handling](#exception-handling)
- [Development](#development)
- [License](#license)

## Requirements

- Ruby `>= 3.0`

## Installation

Add to your app:

```bash
bundle add smart_id_ruby
```

Or install directly:

```bash
gem install smart_id_ruby
```

## Quick setup

```ruby
require "smart_id_ruby"
require "base64"
require "securerandom"

SmartIdRuby.configure do |config|
  config.relying_party_uuid = ENV.fetch("SMART_ID_RP_UUID")
  config.relying_party_name = ENV.fetch("SMART_ID_RP_NAME")
  config.host_url = ENV.fetch("SMART_ID_HOST_URL") # e.g. https://sid.demo.sk.ee/smart-id-rp/v3/
  config.default_certificate_level = "QUALIFIED" # optional app-level default
  config.poller_timeout_seconds = 10             # optional
end

client = SmartIdRuby.client
```

## Logging

The library uses `SmartIdRuby.logger` for connector-level logs.
Default level is `WARN`.

```ruby
require "logger"
require "smart_id_ruby"

SmartIdRuby.logger = Logger.new($stdout)
SmartIdRuby.logger.level = Logger::DEBUG
```

At `DEBUG`, logs include method, URL, and status code.
Request and response bodies are not logged by default.

## Interactions

You can pass interactions either as hashes or helper objects.

### Hash style

```ruby
[
  { type: "displayTextAndPIN", displayText60: "Log in" },
  { type: "confirmationMessage", displayText200: "Confirm login" }
]
```

### Helper style (`NotificationInteraction`)

```ruby
[
  SmartIdRuby::NotificationInteraction.confirmationMessageAndVerificationCodeChoice("Confirm login"),
  SmartIdRuby::NotificationInteraction.confirmationMessage("Confirm login fallback"),
  SmartIdRuby::NotificationInteraction.displayTextAndPin("Log in fallback")
]
```

Ruby-style aliases are also available:

- `display_text_and_pin`
- `confirmation_message`
- `confirmation_message_and_verification_code_choice`

## Flows

### Notification authentication

```ruby
rp_challenge = Base64.strict_encode64(SecureRandom.random_bytes(32))

auth_builder = client.create_notification_authentication
  .with_document_number("PNOEE-30303039914") # or .with_semantics_identifier("PNOEE-...")
  .with_certificate_level("QUALIFIED")
  .with_rp_challenge(rp_challenge)
  .with_interactions([
    SmartIdRuby::NotificationInteraction.displayTextAndPin("Log in")
  ])
  .with_share_md_client_ip_address(true) # optional

auth_init = auth_builder.init_authentication_session
session_id = auth_init["sessionID"] || auth_init[:sessionID]
```

### Device-link authentication

```ruby
rp_challenge = Base64.strict_encode64(SecureRandom.random_bytes(32))

builder = client.create_device_link_authentication
  .with_rp_challenge(rp_challenge)
  .with_interactions([
    SmartIdRuby::NotificationInteraction.confirmationMessage("Log in to MyApp")
  ])
  .with_initial_callback_url("https://example.com/callback") # optional

# Anonymous device-link auth (no identifier)
init = builder.init_authentication_session

# Identified flow variants:
# builder.with_document_number("PNOLT-40504040001-MOCK-Q")
# builder.with_semantics_identifier("PNOEE-30303039914")
```

### Notification signature

```ruby
sig_builder = client.create_notification_signature
  .with_semantics_identifier("PNOEE-30303039914") # or .with_document_number(...)
  .with_certificate_level("QUALIFIED")
  .with_signable_data("data to sign")
  .with_interactions([
    SmartIdRuby::NotificationInteraction.displayTextAndPin("Please sign")
  ])
  .with_nonce(SecureRandom.hex(8)) # optional

sig_init = sig_builder.init_signature_session
session_id = sig_init["sessionID"] || sig_init[:sessionID]
```

You can use `with_signable_hash(...)` instead of `with_signable_data(...)`.

### Device-link signature

```ruby
sig_builder = client.create_device_link_signature
  .with_document_number("PNOLT-40504040001-MOCK-Q") # or .with_semantics_identifier(...)
  .with_certificate_level("QUALIFIED")
  .with_signable_data("data to sign")
  .with_interactions([
    SmartIdRuby::NotificationInteraction.confirmationMessage("Please sign document")
  ])
  .with_initial_callback_url("https://example.com/callback") # optional

sig_init = sig_builder.init_signature_session
```

### Certificate by document number

```ruby
result = client.create_certificate_by_document_number
  .with_document_number("PNOLT-40504040001-MOCK-Q")
  .with_certificate_level("QUALIFIED")
  .get_certificate_by_document_number

certificate_level = result[:certificate_level]
certificate = result[:certificate] # OpenSSL::X509::Certificate
```

### Device-link certificate choice + linked notification signature

```ruby
cert_choice_init = client.create_device_link_certificate_request
  .with_certificate_level("QUALIFIED")
  .with_nonce(SecureRandom.hex(8))
  .init_certificate_choice

cert_choice_session_id = cert_choice_init["sessionID"] || cert_choice_init[:sessionID]

cert_choice_status = client.session_status_poller.fetch_final_session_status(cert_choice_session_id)

cert_choice_response = SmartIdRuby::Validation::CertificateChoiceResponseValidator.new
  .validate(cert_choice_status, "QUALIFIED")

linked_sig_init = client.create_linked_notification_signature
  .with_document_number(cert_choice_response.document_number)
  .with_linked_session_id(cert_choice_session_id)
  .with_signable_data("data to sign")
  .with_interactions([
    SmartIdRuby::NotificationInteraction.displayTextAndPin("Please sign")
  ])
  .init_signature_session
```

### Notification certificate choice

```ruby
init = client.create_notification_certificate_choice
  .with_semantics_identifier("PNOEE-30303039914")
  .with_certificate_level("QUALIFIED")
  .with_nonce(SecureRandom.hex(8))
  .init_certificate_choice

session_id = init["sessionID"] || init[:sessionID]
```

## Generating device link and QR-code

After starting a device-link flow (authentication, signature, or certificate choice),
you can create a signed device-link URI and QR image.

```ruby
# Example: after device-link authentication init
auth_builder = client.create_device_link_authentication
  .with_rp_challenge(Base64.strict_encode64(SecureRandom.random_bytes(32)))
  .with_interactions([SmartIdRuby::NotificationInteraction.displayTextAndPin("Log in")])
  .with_document_number("PNOLT-40504040001-MOCK-Q")

init = auth_builder.init_authentication_session

session_token = init["sessionToken"] || init[:sessionToken]
session_secret = init["sessionSecret"] || init[:sessionSecret]
device_link_base = init["deviceLinkBase"] || init[:deviceLinkBase]
request = auth_builder.get_authentication_session_request
request_interactions = request[:interactions]
request_digest = request.dig(:signatureProtocolParameters, :rpChallenge)
```

Build unprotected and protected device-link:

```ruby
dynamic = client.create_dynamic_content
  .with_device_link_base(device_link_base)
  .with_session_type(SmartIdRuby::SessionType::AUTHENTICATION)
  .with_device_link_type(SmartIdRuby::DeviceLinkType::QR_CODE)
  .with_session_token(session_token)
  .with_elapsed_seconds(1)
  .with_lang("eng")
  .with_digest(request_digest)
  .with_interactions(request_interactions)

unprotected_uri = dynamic.create_unprotected_uri
device_link_uri = dynamic.build_device_link(session_secret)
```

Generate QR-code (PNG Data URI by default):

```ruby
qr_data_uri = SmartIdRuby::QrCodeGenerator.generate_data_uri(device_link_uri.to_s)

# or create image object and convert manually
image = SmartIdRuby::QrCodeGenerator.generate_image(device_link_uri.to_s, 610, 610, 4)
qr_data_uri = SmartIdRuby::QrCodeGenerator.convert_to_data_uri(image, "png")
```

`DeviceLinkBuilder` also provides Java-style aliases:
`withDeviceLinkBase`, `withSessionType`, `withDeviceLinkType`,
`withSessionToken`, `createUnprotectedUri`, `buildDeviceLink`.

## Session status polling

Use `SessionStatusPoller` for both one-shot and final-status polling.

```ruby
poller = client.session_status_poller

# Query once
status = poller.get_session_status(session_id)

# Poll until COMPLETE
final_status = poller.fetch_final_session_status(session_id)
```

Tune polling behavior:

```ruby
client.set_session_status_response_socket_open_time(:seconds, 5) # timeoutMs for each status request
client.set_polling_sleep_timeout(:seconds, 1)                    # sleep between polls
```

Supported time units are `:milliseconds`, `:seconds`, `:minutes`, `:hours`.

## Response validation

Builders validate request/initialization responses.  
For final session status payloads, use validators:

### Notification authentication response validator

```ruby
identity = SmartIdRuby::Validation::NotificationAuthenticationResponseValidator.new
  .validate(
    final_status,
    auth_builder.get_authentication_session_request,
    "SMART_ID", # schema_name
    nil         # brokered_rp_name (optional)
  )
```

### Device-link authentication response validator

```ruby
response = SmartIdRuby::Validation::DeviceLinkAuthenticationResponseValidator.new.validate(
  final_status,
  auth_builder.get_authentication_session_request,
  nil,        # user_challenge_verifier (required for Web2App/App2App)
  "SMART_ID", # schema_name
  nil         # brokered_rp_name
)
```

### Signature response validator

```ruby
signature = SmartIdRuby::Validation::SignatureResponseValidator.new
  .validate(final_status, "QUALIFIED")
```

### Certificate choice response validator

```ruby
choice = SmartIdRuby::Validation::CertificateChoiceResponseValidator.new
  .validate(final_status, "QUALIFIED")
```

## Network and SSL configuration

### Faraday request options

```ruby
client.network_connection_config = {
  open_timeout: 5,
  timeout: 30,
  headers: { "X-Request-ID" => "123" }
}
```

You can also nest options under `:request`:

```ruby
client.network_connection_config = {
  request: {
    open_timeout: 5,
    timeout: 30
  }
}
```

### Custom Faraday connection

```ruby
client.configured_connection = Faraday.new(url: client.host_url) do |f|
  f.adapter Faraday.default_adapter
end
```

### Trusting custom CA certificates

```ruby
cert_store = OpenSSL::X509::Store.new
cert_store.set_default_paths
# cert_store.add_cert(OpenSSL::X509::Certificate.new(File.read("ca.pem")))

ssl_context = OpenSSL::SSL::SSLContext.new
ssl_context.cert_store = cert_store

client.trust_ssl_context = ssl_context
```

## Exception handling

Main exception classes:

- `SmartIdRuby::Errors::RequestSetupError`
- `SmartIdRuby::Errors::RequestValidationError`
- `SmartIdRuby::Errors::UnprocessableResponseError`
- `SmartIdRuby::Errors::SessionEndResultError`
- `SmartIdRuby::Errors::SessionNotCompleteError`
- `SmartIdRuby::Errors::CertificateLevelMismatchError`
- `SmartIdRuby::Errors::DocumentUnusableError`
- `SmartIdRuby::Errors::UserRefusedDisplayTextAndPinError`
- `SmartIdRuby::Errors::UserRefusedConfirmationMessageError`
- `SmartIdRuby::Errors::UserRefusedConfirmationMessageWithVerificationChoiceError`

Connector/network-related classes:

- `SmartIdRuby::Errors::SessionNotFoundError`
- `SmartIdRuby::Errors::UserAccountNotFoundError`
- `SmartIdRuby::Errors::RelyingPartyAccountConfigurationError`
- `SmartIdRuby::Errors::NoSuitableAccountOfRequestedTypeFoundError`
- `SmartIdRuby::Errors::PersonShouldViewSmartIdPortalError`
- `SmartIdRuby::Errors::UnsupportedClientApiVersionError`
- `SmartIdRuby::Errors::ServerMaintenanceError`

## Development

After checking out the repo:

```bash
bin/setup
bundle exec rake
```

## License

The gem is available as open source under the terms of the MIT License.
