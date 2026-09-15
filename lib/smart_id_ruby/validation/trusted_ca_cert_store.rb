# frozen_string_literal: true

require "openssl"

module SmartIdRuby
  module Validation
    # Container for trust anchors and CA certificates used in validation.
    #
    # The gem ships SK ID Solutions' CA certificates for both environments, so the common
    # cases need no setup:
    #
    #   SmartIdRuby::Validation::TrustedCaCertStore.production
    #   SmartIdRuby::Validation::TrustedCaCertStore.demo
    #
    # `default` follows `SmartIdRuby.configuration.trusted_ca_environment` (`:production`
    # unless configured otherwise) and is what the validators use when none is given.
    #
    # Signer certificates chain to SK's own eID CAs, which are not in any operating system
    # CA bundle — that store holds TLS roots. Without one of these stores, chain validation
    # of a signature response fails for every real certificate, in both environments.
    class TrustedCaCertStore
      ENVIRONMENTS = %i[production demo].freeze
      CERTIFICATE_ROOT = File.expand_path("../../../certificates", __dir__).freeze

      attr_reader :trust_anchors, :trusted_ca_certificates, :ocsp_enabled

      def initialize(trust_anchors:, trusted_ca_certificates:, ocsp_enabled: false)
        @trust_anchors = Array(trust_anchors).dup.freeze
        @trusted_ca_certificates = Array(trusted_ca_certificates).dup.freeze
        @ocsp_enabled = !!ocsp_enabled
      end

      def ocsp_enabled?
        ocsp_enabled
      end

      def empty?
        trust_anchors.empty? && trusted_ca_certificates.empty?
      end

      class << self
        # The bundled store for the configured environment.
        def default(ocsp_enabled: false)
          for_environment(configured_environment, ocsp_enabled: ocsp_enabled)
        end

        # SK's live CAs: ROOT G1E / G1R and EE Certification Centre Root CA as anchors,
        # EID-Q 2024E/R, EID-NQ 2021E/R, EID-SK 2016 and NQ-SK 2016 as intermediates.
        def production(ocsp_enabled: false)
          for_environment(:production, ocsp_enabled: ocsp_enabled)
        end

        # SK's demo CAs, for sid.demo.sk.ee. Never trust these in production — they are a
        # separate hierarchy and are published for testing.
        def demo(ocsp_enabled: false)
          for_environment(:demo, ocsp_enabled: ocsp_enabled)
        end

        def for_environment(environment, ocsp_enabled: false)
          name = environment.to_s.to_sym
          unless ENVIRONMENTS.include?(name)
            raise SmartIdRuby::Errors::RequestSetupError,
                  "Unsupported trusted CA environment: #{environment.inspect}. " \
                  "Supported values are #{ENVIRONMENTS.map(&:inspect).join(", ")}"
          end

          anchors, intermediates = bundled_certificates(name)
          new(trust_anchors: anchors, trusted_ca_certificates: intermediates, ocsp_enabled: ocsp_enabled)
        end

        # Build a store from a directory. Either lay it out as the bundled ones —
        # `anchors/` and `intermediates/` subdirectories — or point at a flat directory of
        # PEM/DER certificates, in which case self-signed ones become the anchors.
        def from_directory(path, ocsp_enabled: false)
          anchors_dir = File.join(path, "anchors")
          intermediates_dir = File.join(path, "intermediates")

          if Dir.exist?(anchors_dir) || Dir.exist?(intermediates_dir)
            new(trust_anchors: read_directory(anchors_dir),
                trusted_ca_certificates: read_directory(intermediates_dir),
                ocsp_enabled: ocsp_enabled)
          else
            from_certificates(read_directory(path), ocsp_enabled: ocsp_enabled)
          end
        end

        # Build a store from a PKCS#12 truststore (the shape SK distributes).
        def from_pkcs12(path, password, ocsp_enabled: false)
          p12 = OpenSSL::PKCS12.new(File.binread(path), password)
          from_certificates((Array(p12.ca_certs) + [p12.certificate]).compact, ocsp_enabled: ocsp_enabled)
        rescue OpenSSL::PKCS12::PKCS12Error => e
          raise SmartIdRuby::Errors::RequestSetupError, "Failed to read PKCS#12 truststore '#{path}': #{e.message}"
        end

        # Partition a flat list: self-signed certificates are anchors, the rest
        # intermediates.
        def from_certificates(certificates, ocsp_enabled: false)
          anchors, intermediates = Array(certificates).compact.partition { |cert| self_signed?(cert) }
          new(trust_anchors: anchors, trusted_ca_certificates: intermediates, ocsp_enabled: ocsp_enabled)
        end

        def self_signed?(certificate)
          certificate.issuer == certificate.subject
        end

        private

        def configured_environment
          configured = SmartIdRuby.configuration.trusted_ca_environment if SmartIdRuby.respond_to?(:configuration)
          configured.nil? ? :production : configured.to_s.to_sym
        rescue NoMethodError
          :production
        end

        def bundled_certificates(environment)
          @bundled_certificates ||= {}
          @bundled_certificates[environment] ||= load_bundle(File.join(CERTIFICATE_ROOT, environment.to_s))
        end

        def load_bundle(base)
          anchors = read_directory(File.join(base, "anchors"))
          if anchors.empty?
            raise SmartIdRuby::Errors::RequestSetupError,
                  "No bundled trust anchors found under #{base}. The gem package looks incomplete."
          end

          [anchors.freeze, read_directory(File.join(base, "intermediates")).freeze]
        end

        def read_directory(path)
          return [] unless Dir.exist?(path)

          Dir.glob(File.join(path, "*")).sort.filter_map { |file| read_certificate(file) }
        end

        def read_certificate(path)
          return nil unless File.file?(path)

          OpenSSL::X509::Certificate.new(File.binread(path))
        rescue OpenSSL::X509::CertificateError => e
          raise SmartIdRuby::Errors::RequestSetupError, "Failed to read certificate '#{path}': #{e.message}"
        end
      end
    end
  end
end
