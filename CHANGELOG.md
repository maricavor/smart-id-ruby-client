# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Added support for Smart-ID API v 2.0
- Added truststore_password and truststore_path configuration attributes
- Added SessionResultValidator for confirmation response
- Added CertificateLevelValidator for confirmation response
- Added CertificateLevel, Interaction, SemanticsIdentifier classes

### Changed
- Improved CertificateValidator for confirmation response

### Fixed
- Fixed ConfirmationPoller call method