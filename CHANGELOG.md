## [Unreleased]

- Implemented `NotificationAuthenticationSessionRequestBuilder` with Java-parity request mapping, validation rules, identifier routing, and response validation.
- Implemented `NotificationSignatureSessionRequestBuilder` with Java-parity request mapping, digest input handling, validation rules, identifier routing, and response validation.
- Implemented `DeviceLinkSignatureSessionRequestBuilder` with Java-parity request mapping, digest input handling, identifier routing, callback URL validation, and response validation.
- Implemented `DeviceLinkCertificateChoiceSessionRequestBuilder` with Java-parity request mapping, nonce/callback validation, and response validation.
- Implemented `NotificationCertificateChoiceSessionRequestBuilder` with Java-parity request mapping, semantics-identifier requirement, nonce validation, and response validation.
- Implemented `LinkedNotificationSignatureSessionRequestBuilder` with Java-parity request mapping, digest input handling, linked-session validation, and response validation.
- Implemented `CertificateByDocumentNumberRequestBuilder` with Java-parity request/response validation, certificate parsing, and `DocumentUnusableError` handling.
- Implemented `NotificationAuthenticationResponseValidator`, `SignatureResponseValidator`, and `CertificateChoiceResponseValidator` with Java-parity session validation and response mapping.
- Implemented trust-chain certificate validation parity with `TrustedCaCertStore` and `CertificateValidator`, and wired chain validation into signature/certificate-choice/authentication certificate validation flows.
- Added `AuthenticationIdentity`, `SignatureResponse`, and `CertificateChoiceResponse` models for validator outputs and added `CertificateLevelMismatchError`.
- Added `AuthenticationIdentityMapper` parity behavior to map identity fields from certificate subject and derive date-of-birth with certificate-attribute-first + national-identity fallback logic.
- Added focused specs for notification authentication/signature builders and client factory wiring.
- Added focused specs for certificate-by-document-number builder and client factory wiring.
- Added focused validator specs for notification-authentication, signature, and certificate-choice response validation flows.
- Added runtime dependency on `base64` to avoid Ruby 3.4 default-gem warnings.

## [0.1.0] - 2026-02-17

- Initial release
