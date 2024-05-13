require "smart_id/version"
require "smart_id/utils/authentication_hash"
require "smart_id/utils/certificate_validator"
require "smart_id/utils/session_result_validator"
require "smart_id/utils/verification_code_calculator"
require "smart_id/utils/semantics_identifier"
require "smart_id/utils/interaction"
require "smart_id/utils/certificate_loader"
require "smart_id/utils/certificate_level"
require "smart_id/utils/certificate_level_validator"
require "smart_id/api/request"
require "smart_id/api/response"
require "smart_id/api/confirmation_response"
require "smart_id/api/authentication/identity_number"
require "smart_id/api/authentication/document"
require "smart_id/api/authentication/confirmation_poller"
require "smart_id/authentication_certificate/date_of_birth_from_attribute"
require "smart_id/authentication_certificate/certificate"
require "smart_id/authentication_certificate/content"

module SmartId
  @@environment = "DEMO" # possible options are demo and production
  @@relying_party_uuid = nil
  @@relying_party_name = nil
  @@default_certificate_level = "ADVANCED" # possible values are "ADVANCED", "QUALIFIED"
  @@poller_timeout_seconds = 10
  @@truststore_path = nil
  @@truststore_password = nil
  @@tls_config = nil

  def self.configure(&block)
    yield(self)
  end

  def self.relying_party_uuid=(value)
    @@relying_party_uuid = value
  end

  def self.relying_party_uuid
    @@relying_party_uuid
  end

  def self.relying_party_name=(value)
    @@relying_party_name = value
  end

  def self.relying_party_name
    @@relying_party_name
  end

  def self.default_certificate_level=(value)
    @@default_certificate_level = value
  end

  def self.default_certificate_level
    @@default_certificate_level
  end

  def self.poller_timeout_seconds=(value)
    @@poller_timeout_seconds = value
  end

  def self.poller_timeout_seconds
    @@poller_timeout_seconds
  end

  def self.host_url=(value)
    @@host_url = value
  end

  def self.host_url
    @@host_url
  end

  def self.truststore_path=(value)
    @@truststore_path = value
  end

  def self.truststore_path
    @@truststore_path
  end

  def self.truststore_password=(value)
    @@truststore_password = value
  end

  def self.truststore_password
    @@truststore_password
  end

  def self.tls_config=(value)
    @@tls_config = value
  end

  def self.tls_config
    @@tls_config
  end
end
