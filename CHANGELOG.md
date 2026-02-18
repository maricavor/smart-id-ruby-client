## [Unreleased]

- Implemented `NotificationAuthenticationSessionRequestBuilder` with Java-parity request mapping, validation rules, identifier routing, and response validation.
- Implemented `NotificationSignatureSessionRequestBuilder` with Java-parity request mapping, digest input handling, validation rules, identifier routing, and response validation.
- Implemented `CertificateByDocumentNumberRequestBuilder` with Java-parity request/response validation, certificate parsing, and `DocumentUnusableError` handling.
- Added focused specs for notification authentication/signature builders and client factory wiring.
- Added focused specs for certificate-by-document-number builder and client factory wiring.
- Added runtime dependency on `base64` to avoid Ruby 3.4 default-gem warnings.

## [0.1.0] - 2026-02-17

- Initial release
