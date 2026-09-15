## [0.2.0] - 2026-09-14

- **Bundled SK ID Solutions CA certificates**, matching what `smart-id-java-client` ships,
  so trust-chain validation works without any setup. Signer certificates chain to SK's own
  eID CAs, which are not present in any operating system CA bundle — before this, chain
  validation failed for every real Smart-ID certificate. New entry points:
  `TrustedCaCertStore.production` (live CAs), `TrustedCaCertStore.demo` (sid.demo.sk.ee),
  `.default` (follows configuration), plus `.from_directory`, `.from_pkcs12` and
  `.from_certificates` for supplying your own.
- **`CertificateValidator` now defaults to the bundled store** for the configured
  environment instead of the system CA store alone. Pass `trusted_ca_cert_store: nil` for
  the old behaviour. This is the default `SignatureResponseValidator` uses, so signature
  responses validate out of the box.
- New configuration key `trusted_ca_environment` (`:production` by default, `:demo` for the
  demo service).
- **Transport errors no longer crash the client.** `Rest::Connector` read
  `error.response[:status]` unconditionally, but a `Faraday::TimeoutError` — which is a
  `Faraday::ServerError` — carries no response, so a long-poll session status request that
  timed out raised `NoMethodError: undefined method '[]' for nil` instead of something
  catchable. Timeouts now raise the new `Errors::NetworkTimeoutError` (distinct from
  `SessionTimeoutError`, which means the user did not respond), and a dropped connection
  raises `Errors::ResponseError` rather than leaking a raw Faraday exception.
- **ADVANCED signature certificates are checked properly.** The certificate purpose
  validation returned early for ADVANCED, so any Non-Repudiation certificate from any CA in
  the trust store was accepted. It now requires the non-qualified Smart-ID policy OIDs
  (`1.3.6.1.4.1.10015.17.1`, `0.4.0.2042.1.1`), matching `smart-id-java-client`.
- **`SignatureValueValidator` no longer rewrites its own errors.** A blanket
  `rescue StandardError` swallowed the `RequestSetupError`s raised for missing parameters
  and reported them as "Signature value validation failed"; gem errors are re-raised as-is.
  Found by giving the class its first specs.

## [Unreleased]

- Implemented trust-chain certificate validation parity with `TrustedCaCertStore` and `CertificateValidator`, and wired chain validation into signature/certificate-choice/authentication certificate validation flows.
- Added `AuthenticationIdentity`, `SignatureResponse`, and `CertificateChoiceResponse` models for validator outputs and added `CertificateLevelMismatchError`.
- Added `AuthenticationIdentityMapper` parity behavior to map identity fields from certificate subject and derive date-of-birth with certificate-attribute-first + national-identity fallback logic.
- Added focused specs for notification authentication/signature builders and client factory wiring.
- Added focused specs for certificate-by-document-number builder and client factory wiring.
- Added focused validator specs for notification-authentication, signature, and certificate-choice response validation flows.
- Added runtime dependency on `base64` to avoid Ruby 3.4 default-gem warnings.

## [0.1.0] - 2026-02-17

- Initial release
