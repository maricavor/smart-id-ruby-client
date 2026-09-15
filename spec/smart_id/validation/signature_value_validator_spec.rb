# frozen_string_literal: true

RSpec.describe SmartIdRuby::Validation::SignatureValueValidator do
  subject(:validator) { described_class.new }

  let(:key) { OpenSSL::PKey::RSA.new(2048) }
  let(:payload) { "the canonicalized SignedInfo bytes" }

  let(:certificate) do
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse("/C=EE/CN=TEST,OK")
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert
  end

  def parameters(hash_algorithm: "SHA-512", mgf_hash_algorithm: "SHA-512", salt_length: 64)
    SmartIdRuby::Models::SessionSignatureAlgorithmParameters.from_h(
      "hashAlgorithm" => hash_algorithm,
      "maskGenAlgorithm" => { "algorithm" => "id-mgf1", "parameters" => { "hashAlgorithm" => mgf_hash_algorithm } },
      "saltLength" => salt_length,
      "trailerField" => "0xbc"
    )
  end

  def pss_signature(data: payload, digest: "SHA512", salt_length: 64, mgf1_hash: "SHA512", signing_key: key)
    Base64.strict_encode64(
      signing_key.sign_pss(digest, data, salt_length: salt_length, mgf1_hash: mgf1_hash)
    )
  end

  def validate(signature_value, params = parameters)
    validator.validate(signature_value: signature_value, payload: payload,
                       certificate: certificate, signature_algorithm_parameters: params)
  end

  describe "a signature the device really produced" do
    it "accepts an RSASSA-PSS signature over the payload" do
      expect { validate(pss_signature) }.not_to raise_error
    end

    it "accepts SHA-256 with the matching salt length" do
      signature = pss_signature(digest: "SHA256", salt_length: 32, mgf1_hash: "SHA256")

      params = parameters(hash_algorithm: "SHA-256", mgf_hash_algorithm: "SHA-256", salt_length: 32)

      expect { validate(signature, params) }.not_to raise_error
    end
  end

  describe "a signature that does not belong to this payload" do
    it "rejects a signature made over different data" do
      signature = pss_signature(data: "something else entirely")

      expect { validate(signature) }.to raise_error(
        SmartIdRuby::Errors::UnprocessableResponseError,
        /does not match the calculated signature value/
      )
    end

    it "rejects a signature made with a different key" do
      signature = pss_signature(signing_key: OpenSSL::PKey::RSA.new(2048))

      expect { validate(signature) }.to raise_error(
        SmartIdRuby::Errors::UnprocessableResponseError,
        /does not match the calculated signature value/
      )
    end

    it "rejects a PKCS#1 v1.5 signature presented as PSS" do
      signature = Base64.strict_encode64(key.sign(OpenSSL::Digest.new("SHA512"), payload))

      expect { validate(signature) }.to raise_error(SmartIdRuby::Errors::UnprocessableResponseError)
    end
  end

  describe "parameters that do not match the signature" do
    it "rejects a mismatched hash algorithm" do
      params = parameters(hash_algorithm: "SHA-256", mgf_hash_algorithm: "SHA-256", salt_length: 32)

      expect { validate(pss_signature, params) }
        .to raise_error(SmartIdRuby::Errors::UnprocessableResponseError)
    end

    it "rejects a mismatched salt length" do
      expect { validate(pss_signature, parameters(salt_length: 32)) }
        .to raise_error(SmartIdRuby::Errors::UnprocessableResponseError)
    end

    it "rejects a mismatched MGF1 hash algorithm" do
      expect { validate(pss_signature, parameters(mgf_hash_algorithm: "SHA-256")) }
        .to raise_error(SmartIdRuby::Errors::UnprocessableResponseError)
    end

    it "rejects an unsupported hash algorithm" do
      expect { validate(pss_signature, parameters(hash_algorithm: "MD5")) }.to raise_error(
        SmartIdRuby::Errors::UnprocessableResponseError,
        /Invalid signature algorithm parameters were provided/
      )
    end
  end

  describe "malformed input" do
    it "raises a setup error when the signature value is missing" do
      expect { validate(nil) }.to raise_error(
        SmartIdRuby::Errors::RequestSetupError, /'signatureValue' is not provided/
      )
    end

    it "raises a setup error when the parameters are missing" do
      expect { validate(pss_signature, nil) }.to raise_error(
        SmartIdRuby::Errors::RequestSetupError, /'rsaSsaPssParameters' is not provided/
      )
    end

    it "raises a setup error when the payload is missing" do
      expect do
        validator.validate(signature_value: pss_signature, payload: nil,
                           certificate: certificate, signature_algorithm_parameters: parameters)
      end.to raise_error(SmartIdRuby::Errors::RequestSetupError, /'payload' is not provided/)
    end

    it "raises a setup error when the certificate is missing" do
      expect do
        validator.validate(signature_value: pss_signature, payload: payload,
                           certificate: nil, signature_algorithm_parameters: parameters)
      end.to raise_error(SmartIdRuby::Errors::RequestSetupError, /'certificate' is not provided/)
    end

    it "rejects a signature value that is not valid Base64" do
      expect { validate("not base64 $$$") }.to raise_error(SmartIdRuby::Errors::UnprocessableResponseError)
    end
  end
end
