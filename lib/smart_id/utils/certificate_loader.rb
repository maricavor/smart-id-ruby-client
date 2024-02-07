module SmartId
  module Utils
    class CertificateLoader
      def self.load_pkcs12_certificates(path, password)
        p12 = load_pkcs12_truststore(path, password)

        extract_trusted_certificates(p12)
      end

      def self.extract_trusted_certificates(p12)
        p12.ca_certs.each_with_object([]) do |cert, trusted_certificates|
          common_name = cert.subject.to_a.find { |name, _, _| name == 'CN' }&.last
          next unless common_name

          trusted_certificates << OpenSSL::X509::Certificate.new(cert)
        end
      end

      def self.load_pkcs12_truststore(path, password)
        OpenSSL::PKCS12.new(File.binread(path), password)
      rescue OpenSSL::PKCS12::PKCS12Error => e
        raise "File at #{path} is not a valid PKCS12 file: #{e.message}"
      end

      private_class_method :new, :load_pkcs12_truststore, :extract_trusted_certificates
    end
  end
end
