# frozen_string_literal: true

RSpec.describe SmartId::Validation::AuthenticationIdentityMapper do
  let(:mapper) { described_class.new }

  def build_certificate(subject_name)
    key = OpenSSL::PKey::RSA.new(1024)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = subject_name
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    cert.sign(key, OpenSSL::Digest::SHA256.new)
    cert
  end

  it "maps basic identity attributes from certificate subject" do
    subject = OpenSSL::X509::Name.new(
      [
        ["C", "EE", OpenSSL::ASN1::PRINTABLESTRING],
        ["SN", "TAMM", OpenSSL::ASN1::UTF8STRING],
        ["GN", "TOOMAS", OpenSSL::ASN1::UTF8STRING],
        ["serialNumber", "PNOEE-38001085718", OpenSSL::ASN1::UTF8STRING]
      ]
    )
    certificate = build_certificate(subject)

    identity = mapper.from(certificate)

    expect(identity.given_name).to eq("TOOMAS")
    expect(identity.surname).to eq("TAMM")
    expect(identity.identity_number).to eq("38001085718")
    expect(identity.country).to eq("EE")
    expect(identity.date_of_birth).to eq(Date.new(1980, 1, 8))
  end

  it "returns nil date_of_birth for newer Latvian personal codes that do not encode DOB" do
    subject = OpenSSL::X509::Name.new(
      [
        ["C", "LV", OpenSSL::ASN1::PRINTABLESTRING],
        ["SN", "TEST", OpenSSL::ASN1::UTF8STRING],
        ["GN", "USER", OpenSSL::ASN1::UTF8STRING],
        ["serialNumber", "PNOLV-321299-12345", OpenSSL::ASN1::UTF8STRING]
      ]
    )
    certificate = build_certificate(subject)

    identity = mapper.from(certificate)
    expect(identity.date_of_birth).to be_nil
  end

  it "prefers certificate attribute date_of_birth over national identity number fallback" do
    subject = OpenSSL::X509::Name.new(
      [
        ["C", "EE", OpenSSL::ASN1::PRINTABLESTRING],
        ["SN", "TEST", OpenSSL::ASN1::UTF8STRING],
        ["GN", "USER", OpenSSL::ASN1::UTF8STRING],
        ["serialNumber", "PNOEE-38001085718", OpenSSL::ASN1::UTF8STRING]
      ]
    )
    certificate = build_certificate(subject)
    allow(mapper).to receive(:extract_date_of_birth_from_certificate).and_return(Date.new(2001, 2, 3))

    identity = mapper.from(certificate)
    expect(identity.date_of_birth).to eq(Date.new(2001, 2, 3))
  end
end
