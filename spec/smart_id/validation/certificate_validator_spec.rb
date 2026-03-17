# frozen_string_literal: true

RSpec.describe SmartIdRuby::Validation::CertificateValidator do
  def build_ca_certificate(common_name)
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = rand(1000..9999)
    cert.subject = OpenSSL::X509::Name.parse("/C=EE/CN=#{common_name}")
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 86_400
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = cert
    cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
    cert.add_extension(ef.create_extension("keyUsage", "keyCertSign,cRLSign", true))
    cert.add_extension(ef.create_extension("subjectKeyIdentifier", "hash"))
    cert.sign(key, OpenSSL::Digest::SHA256.new)
    [cert, key]
  end

  def build_leaf_certificate(cn, issuer_cert, issuer_key)
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = rand(10_000..99_999)
    cert.subject = OpenSSL::X509::Name.parse("/C=EE/CN=#{cn}")
    cert.issuer = issuer_cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 86_400
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = issuer_cert
    cert.add_extension(ef.create_extension("basicConstraints", "CA:FALSE", true))
    cert.add_extension(ef.create_extension("keyUsage", "digitalSignature,keyEncipherment", true))
    cert.add_extension(ef.create_extension("authorityKeyIdentifier", "keyid:always"))
    cert.add_extension(ef.create_extension("subjectKeyIdentifier", "hash"))
    cert.sign(issuer_key, OpenSSL::Digest::SHA256.new)
    cert
  end

  it "validates certificate chain against configured trust anchors" do
    root_cert, root_key = build_ca_certificate("Test Root CA")
    leaf_cert = build_leaf_certificate("Leaf", root_cert, root_key)

    store = SmartIdRuby::Validation::TrustedCaCertStore.new(
      trust_anchors: [root_cert],
      trusted_ca_certificates: [root_cert],
      ocsp_enabled: false
    )
    validator = described_class.new(trusted_ca_cert_store: store, use_system_store: false)

    expect { validator.validate(leaf_cert) }.not_to raise_error
  end

  it "raises when certificate chain cannot be validated" do
    root_cert, root_key = build_ca_certificate("Untrusted Root CA")
    leaf_cert = build_leaf_certificate("Leaf", root_cert, root_key)
    validator = described_class.new(use_system_store: false)

    expect { validator.validate(leaf_cert) }.to raise_error(
      SmartIdRuby::Errors::UnprocessableResponseError,
      /Certificate chain validation failed/
    )
  end
end
