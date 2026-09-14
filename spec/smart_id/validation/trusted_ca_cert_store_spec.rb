# frozen_string_literal: true

RSpec.describe SmartIdRuby::Validation::TrustedCaCertStore do
  def common_name(certificate)
    certificate.subject.to_a.assoc("CN")&.at(1)
  end

  around do |example|
    original = SmartIdRuby.configuration.trusted_ca_environment
    example.run
    SmartIdRuby.configure { |config| config.trusted_ca_environment = original }
  end

  describe "bundled certificates" do
    it "loads SK's live CA certificates" do
      store = described_class.production

      expect(common_name(store.trust_anchors.first)).not_to be_nil
      expect(store.trust_anchors.map { |cert| common_name(cert) })
        .to include("SK ID Solutions ROOT G1E", "SK ID Solutions ROOT G1R", "EE Certification Centre Root CA")
      expect(store.trusted_ca_certificates.map { |cert| common_name(cert) })
        .to include("SK ID Solutions EID-Q 2024E", "SK ID Solutions EID-Q 2024R", "EID-SK 2016", "NQ-SK 2016")
    end

    it "loads SK's demo CA certificates" do
      store = described_class.demo

      expect(store.trust_anchors.map { |cert| common_name(cert) })
        .to include("TEST of SK ID Solutions ROOT G1E", "TEST of SK ID Solutions ROOT G1R")
      expect(store.trusted_ca_certificates.map { |cert| common_name(cert) })
        .to include("TEST of SK ID Solutions EID-Q 2024E")
    end

    it "keeps the environments separate" do
      production = described_class.production.trusted_ca_certificates.map { |cert| common_name(cert) }

      expect(production).to all(satisfy { |name| !name.start_with?("TEST of") })
    end

    it "bundles only anchors that are self-signed" do
      described_class::ENVIRONMENTS.each do |environment|
        anchors = described_class.for_environment(environment).trust_anchors
        expect(anchors).to all(satisfy { |cert| described_class.self_signed?(cert) })
      end
    end

    it "bundles intermediates that chain to the bundled anchors" do
      described_class::ENVIRONMENTS.each do |environment|
        store = described_class.for_environment(environment)
        openssl_store = OpenSSL::X509::Store.new
        store.trust_anchors.each { |anchor| openssl_store.add_cert(anchor) }

        store.trusted_ca_certificates.each do |intermediate|
          expect(openssl_store.verify(intermediate))
            .to be(true), "#{common_name(intermediate)} does not chain to a bundled anchor"
        end
      end
    end

    it "does not build certificates twice" do
      expect(described_class.production.trust_anchors.first)
        .to equal(described_class.production.trust_anchors.first)
    end

    it "rejects an unknown environment" do
      expect { described_class.for_environment(:staging) }
        .to raise_error(SmartIdRuby::Errors::RequestSetupError, /Unsupported trusted CA environment/)
    end

    it "disables OCSP unless asked for" do
      expect(described_class.production).not_to be_ocsp_enabled
      expect(described_class.production(ocsp_enabled: true)).to be_ocsp_enabled
    end
  end

  describe ".default" do
    it "follows the configured environment" do
      SmartIdRuby.configure { |config| config.trusted_ca_environment = :demo }
      expect(described_class.default.trust_anchors.map { |cert| common_name(cert) })
        .to include("TEST of SK ID Solutions ROOT G1E")

      SmartIdRuby.configure { |config| config.trusted_ca_environment = :production }
      expect(described_class.default.trust_anchors.map { |cert| common_name(cert) })
        .to include("SK ID Solutions ROOT G1E")
    end

    it "defaults to production when the environment is not configured" do
      SmartIdRuby.configure { |config| config.trusted_ca_environment = nil }
      expect(described_class.default.trust_anchors.map { |cert| common_name(cert) })
        .to include("SK ID Solutions ROOT G1E")
    end
  end

  describe ".from_certificates" do
    it "treats self-signed certificates as anchors and the rest as intermediates" do
      anchor = described_class.demo.trust_anchors.first
      intermediate = described_class.demo.trusted_ca_certificates.first

      store = described_class.from_certificates([intermediate, anchor])

      expect(store.trust_anchors).to eq([anchor])
      expect(store.trusted_ca_certificates).to eq([intermediate])
    end
  end

  describe ".from_directory" do
    it "reads the anchors and intermediates subdirectories" do
      store = described_class.from_directory(File.join(described_class::CERTIFICATE_ROOT, "demo"))

      expect(store.trust_anchors.size).to eq(described_class.demo.trust_anchors.size)
      expect(store.trusted_ca_certificates.size).to eq(described_class.demo.trusted_ca_certificates.size)
    end

    it "partitions a flat directory by self-signedness" do
      store = described_class.from_directory(File.join(described_class::CERTIFICATE_ROOT, "demo", "intermediates"))

      expect(store.trust_anchors).to be_empty
      expect(store.trusted_ca_certificates.size).to eq(described_class.demo.trusted_ca_certificates.size)
    end

    it "returns an empty store for a directory that does not exist" do
      expect(described_class.from_directory("/nonexistent/path")).to be_empty
    end
  end

  describe ".from_pkcs12" do
    it "reads a PKCS#12 truststore" do
      key = OpenSSL::PKey::RSA.new(2048)
      holder = OpenSSL::X509::Certificate.new
      holder.version = 2
      holder.serial = 1
      holder.subject = OpenSSL::X509::Name.parse("/C=EE/CN=truststore holder")
      holder.issuer = holder.subject
      holder.public_key = key.public_key
      holder.not_before = Time.now - 3600
      holder.not_after = Time.now + 3600
      holder.sign(key, OpenSSL::Digest::SHA256.new)

      demo = described_class.demo
      p12 = OpenSSL::PKCS12.create("changeit", "demo", key, holder,
                                   demo.trust_anchors + demo.trusted_ca_certificates)

      Tempfile.create(["truststore", ".p12"]) do |file|
        file.binmode
        file.write(p12.to_der)
        file.flush

        store = described_class.from_pkcs12(file.path, "changeit")
        names = (store.trust_anchors + store.trusted_ca_certificates).map { |cert| common_name(cert) }
        expect(names).to include("TEST of SK ID Solutions EID-Q 2024E")
        expect(store.trust_anchors.map { |cert| common_name(cert) }).to include("TEST of SK ID Solutions ROOT G1E")
      end
    end

    it "raises a setup error on a wrong password" do
      Tempfile.create(["truststore", ".p12"]) do |file|
        file.binmode
        file.write("not a pkcs12 file")
        file.flush

        expect { described_class.from_pkcs12(file.path, "changeit") }
          .to raise_error(SmartIdRuby::Errors::RequestSetupError, /Failed to read PKCS#12 truststore/)
      end
    end
  end

  describe "explicit construction" do
    it "still accepts anchors and intermediates directly" do
      store = described_class.new(trust_anchors: [], trusted_ca_certificates: [], ocsp_enabled: true)

      expect(store).to be_empty
      expect(store).to be_ocsp_enabled
    end
  end
end
