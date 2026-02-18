# frozen_string_literal: true

require "base64"
require "openssl"

module SmartId
  module Validation
    class SignatureResponseValidator
      BASE64_PATTERN = /\A[a-zA-Z0-9+\/]+={0,2}\z/.freeze
      CERTIFICATE_LEVEL_ORDER = { "ADVANCED" => 1, "QUALIFIED" => 2, "QSCD" => 2 }.freeze
      SUPPORTED_FLOW_TYPES = ["QR", "Web2App", "App2App", "Notification"].freeze
      SUPPORTED_TRAILER_FIELD = "0xbc"
      SUPPORTED_MASK_GEN_ALGORITHM = "id-mgf1"
      QC_STATEMENTS_EXTENSION_OID = "1.3.6.1.5.5.7.1.3"
      QC_TYPE_STATEMENT_OID = "0.4.0.1862.1.6"
      QUALIFIED_ELECTRONIC_SIGNATURE_OID = "0.4.0.1862.1.6.1"
      SUPPORTED_HASH_ALGORITHMS = {
        "SHA-256" => 32,
        "SHA-384" => 48,
        "SHA-512" => 64,
        "SHA3-256" => 32,
        "SHA3-384" => 48,
        "SHA3-512" => 64
      }.freeze

      END_RESULT_MESSAGES = {
        "USER_REFUSED" => "User pressed cancel in app",
        "TIMEOUT" => "Session timed out without getting any response from user",
        "DOCUMENT_UNUSABLE" => "Document is unusable. User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason.",
        "WRONG_VC" => "User selected wrong verification code",
        "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP" => "User app version does not support any of the provided interactions.",
        "USER_REFUSED_CERT_CHOICE" => "User has multiple accounts and pressed Cancel on device choice screen on any device.",
        "PROTOCOL_FAILURE" => "A logical error occurred in the signing protocol.",
        "EXPECTED_LINKED_SESSION" => "The app received a different transaction while waiting for the linked session that follows the device-link based cert-choice session",
        "SERVER_ERROR" => "Process was terminated due to server-side technical error",
        "ACCOUNT_UNUSABLE" => "The account is currently unusable"
      }.freeze

      def initialize(certificate_validator: CertificateValidator.new)
        @certificate_validator = certificate_validator
      end

      def validate(session_status, requested_certificate_level)
        status = normalize_status(session_status)
        if status.nil?
          raise SmartId::Errors::RequestSetupError, "Parameter 'sessionStatus' is not provided"
        end
        if requested_certificate_level.nil?
          raise SmartId::Errors::RequestSetupError, "Parameter 'requestedCertificateLevel' is not provided"
        end
        if blank?(status.state)
          raise SmartId::Errors::UnprocessableResponseError, "Signature session status field 'state' is empty"
        end
        unless status.complete?
          raise SmartId::Errors::RequestSetupError, "Session is not complete. State: #{status.state}"
        end

        validate_session_result(status, requested_certificate_level)
      end

      private

      def validate_session_result(status, requested_certificate_level)
        result = status.result
        if result.nil?
          raise SmartId::Errors::UnprocessableResponseError, "Signature session status field 'result' is missing"
        end
        if blank?(result.end_result)
          raise SmartId::Errors::UnprocessableResponseError, "Signature session status field 'result.endResult' is empty"
        end

        unless result.end_result == "OK"
          handle_error_result(result)
        end

        if blank?(result.document_number)
          raise SmartId::Errors::UnprocessableResponseError, "Signature session status field 'result.documentNumber' is empty"
        end
        if blank?(status.interaction_type_used)
          raise SmartId::Errors::UnprocessableResponseError, "Signature session status field 'interactionTypeUsed' is empty"
        end
        if blank?(status.signature_protocol)
          raise SmartId::Errors::UnprocessableResponseError, "Signature session status field 'signatureProtocol' is empty"
        end

        certificate_level, certificate = validate_certificate(status.cert, requested_certificate_level)
        validate_signature(status)

        SmartId::Models::SignatureResponse.new(
          end_result: result.end_result,
          signature_value_in_base64: status.signature.value,
          algorithm_name: status.signature.signature_algorithm,
          flow_type: status.signature.flow_type,
          certificate: certificate,
          requested_certificate_level: requested_certificate_level,
          certificate_level: certificate_level,
          document_number: result.document_number,
          interaction_flow_used: status.interaction_type_used,
          device_ip_address: status.device_ip_address,
          rsa_ssa_pss_parameters: status.signature.signature_algorithm_parameters
        )
      end

      def validate_certificate(session_certificate, requested_certificate_level)
        if session_certificate.nil?
          raise SmartId::Errors::UnprocessableResponseError, "Signature session status field 'cert' is missing"
        end
        if blank?(session_certificate.value)
          raise SmartId::Errors::UnprocessableResponseError, "Signature session status field 'cert.value' is empty"
        end
        if blank?(session_certificate.certificate_level)
          raise SmartId::Errors::UnprocessableResponseError, "Signature session status field 'cert.certificateLevel' is empty"
        end
        unless CERTIFICATE_LEVEL_ORDER.key?(session_certificate.certificate_level)
          raise SmartId::Errors::UnprocessableResponseError, "Signature session status field 'cert.certificateLevel' has unsupported value"
        end

        level = session_certificate.certificate_level
        requested_level = requested_certificate_level.to_s
        requested_level = "QUALIFIED" if requested_level.strip.empty?
        if CERTIFICATE_LEVEL_ORDER[level] < CERTIFICATE_LEVEL_ORDER.fetch(requested_level, CERTIFICATE_LEVEL_ORDER["QUALIFIED"])
          raise SmartId::Errors::CertificateLevelMismatchError
        end

        certificate = parse_certificate(session_certificate.value, "Signature certificate is invalid")
        @certificate_validator.validate(certificate) if @certificate_validator
        validate_signature_certificate_purpose(certificate, level)
        [level, certificate]
      end

      def validate_signature_certificate_purpose(certificate, certificate_level)
        key_usage = certificate.extensions.find { |ext| ext.oid == "keyUsage" }&.value.to_s
        unless key_usage.match?(/Non[- ]Repudiation/i)
          raise SmartId::Errors::UnprocessableResponseError, "Certificate does not have Non-Repudiation set in 'KeyUsage' extension"
        end
        return if certificate_level == "ADVANCED"

        policy_oids = extract_certificate_policy_oids(certificate)
        if policy_oids.empty?
          raise SmartId::Errors::UnprocessableResponseError, "Certificate does not have certificate policy OIDs"
        end
        required = ["1.3.6.1.4.1.10015.17.2", "0.4.0.194112.1.2"]
        unless (required - policy_oids).empty?
          raise SmartId::Errors::UnprocessableResponseError,
                "Certificate does not contain required qualified certificate policy OIDs"
        end
        validate_certificate_can_be_used_for_qualified_electronic_signature(certificate)
      end

      def validate_certificate_can_be_used_for_qualified_electronic_signature(certificate)
        extension = certificate.extensions.find { |ext| ext.oid == "qcStatements" || ext.oid == QC_STATEMENTS_EXTENSION_OID }
        if extension.nil?
          raise SmartId::Errors::UnprocessableResponseError, "Certificate does not have 'QCStatements' extension"
        end

        unless has_qualified_signature_oid?(extension)
          raise SmartId::Errors::UnprocessableResponseError,
                "Certificate does not have electronic signature OID (#{QUALIFIED_ELECTRONIC_SIGNATURE_OID}) in QCStatements extension."
        end
      end

      def has_qualified_signature_oid?(extension)
        decoded = OpenSSL::ASN1.decode(extension.to_der)
        octet_string = decoded.value.find { |node| node.is_a?(OpenSSL::ASN1::OctetString) }
        return false if octet_string.nil?

        inner = OpenSSL::ASN1.decode(octet_string.value)
        contains_qc_type_statement_with_esign?(inner)
      rescue OpenSSL::ASN1::ASN1Error
        raise SmartId::Errors::RequestSetupError, "Unable to parse QCStatements extension"
      end

      def contains_qc_type_statement_with_esign?(root_node)
        statement_nodes = collect_asn1_sequences(root_node)
        statement_nodes.any? do |statement|
          values = statement.value
          next false unless values.is_a?(Array) && values.first.is_a?(OpenSSL::ASN1::ObjectId)
          next false unless values.first.oid == QC_TYPE_STATEMENT_OID

          contains_object_id?(statement, QUALIFIED_ELECTRONIC_SIGNATURE_OID)
        end
      end

      def collect_asn1_sequences(node, acc = [])
        return acc unless node.respond_to?(:value)

        value = node.value
        if node.is_a?(OpenSSL::ASN1::Sequence) && value.is_a?(Array)
          acc << node
          value.each { |child| collect_asn1_sequences(child, acc) }
        elsif value.is_a?(Array)
          value.each { |child| collect_asn1_sequences(child, acc) }
        end
        acc
      end

      def contains_object_id?(node, expected_oid)
        return false unless node.respond_to?(:value)

        value = node.value
        return value == expected_oid if node.is_a?(OpenSSL::ASN1::ObjectId)
        return false unless value.is_a?(Array)

        value.any? { |child| contains_object_id?(child, expected_oid) }
      end

      def validate_signature(status)
        unless status.signature_protocol.to_s.casecmp("RAW_DIGEST_SIGNATURE").zero?
          raise SmartId::Errors::UnprocessableResponseError, "Signature session status field 'signatureProtocol' has unsupported value"
        end

        signature = status.signature
        if signature.nil?
          raise SmartId::Errors::UnprocessableResponseError, "Signature session status field 'signature' is missing"
        end

        validate_signature_value(signature.value)
        validate_signature_algorithm_name(signature.signature_algorithm)
        validate_flow_type(signature.flow_type)
        validate_signature_algorithm_parameters(signature.signature_algorithm_parameters)
      end

      def validate_signature_value(value)
        if blank?(value)
          raise SmartId::Errors::UnprocessableResponseError, "Signature session status field 'signature.value' is empty"
        end
        unless BASE64_PATTERN.match?(value)
          raise SmartId::Errors::UnprocessableResponseError, "Signature session status field 'signature.value' does not have Base64-encoded value"
        end
      end

      def validate_signature_algorithm_name(signature_algorithm)
        if blank?(signature_algorithm)
          raise SmartId::Errors::UnprocessableResponseError, "Signature session status field 'signature.signatureAlgorithm' is missing"
        end
        unless signature_algorithm == "rsassa-pss"
          raise SmartId::Errors::UnprocessableResponseError, "Signature session status field 'signature.signatureAlgorithm' has unsupported value"
        end
      end

      def validate_flow_type(flow_type)
        if blank?(flow_type)
          raise SmartId::Errors::UnprocessableResponseError, "Signature session status field `signature.flowType` is empty"
        end
        unless SUPPORTED_FLOW_TYPES.include?(flow_type)
          raise SmartId::Errors::UnprocessableResponseError, "Signature session status field 'signature.flowType' has unsupported value"
        end
      end

      def validate_signature_algorithm_parameters(params)
        if params.nil?
          raise SmartId::Errors::UnprocessableResponseError,
                "Signature session status field 'signature.signatureAlgorithmParameters' is missing"
        end
        hash_algorithm = params.hash_algorithm
        if blank?(hash_algorithm)
          raise SmartId::Errors::UnprocessableResponseError,
                "Signature session status field 'signature.signatureAlgorithmParameters.hashAlgorithm' is empty"
        end
        unless SUPPORTED_HASH_ALGORITHMS.key?(hash_algorithm)
          raise SmartId::Errors::UnprocessableResponseError,
                "Signature session status field 'signature.signatureAlgorithmParameters.hashAlgorithm' has unsupported value"
        end

        mask_gen_algorithm = params.mask_gen_algorithm
        if mask_gen_algorithm.nil?
          raise SmartId::Errors::UnprocessableResponseError,
                "Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm' is missing"
        end
        mask_algorithm = fetch_hash_value(mask_gen_algorithm, :algorithm)
        if blank?(mask_algorithm)
          raise SmartId::Errors::UnprocessableResponseError,
                "Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.algorithm' is empty"
        end
        unless mask_algorithm == SUPPORTED_MASK_GEN_ALGORITHM
          raise SmartId::Errors::UnprocessableResponseError,
                "Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.algorithm' has unsupported value"
        end
        mask_parameters = fetch_hash_value(mask_gen_algorithm, :parameters)
        if mask_parameters.nil?
          raise SmartId::Errors::UnprocessableResponseError,
                "Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters' is missing"
        end
        mask_hash_algorithm = fetch_hash_value(mask_parameters, :hashAlgorithm)
        if blank?(mask_hash_algorithm)
          raise SmartId::Errors::UnprocessableResponseError,
                "Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' is empty"
        end
        unless SUPPORTED_HASH_ALGORITHMS.key?(mask_hash_algorithm)
          raise SmartId::Errors::UnprocessableResponseError,
                "Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' has unsupported value"
        end
        unless hash_algorithm == mask_hash_algorithm
          raise SmartId::Errors::UnprocessableResponseError,
                "Signature session status field 'signature.signatureAlgorithmParameters.maskGenAlgorithm.parameters.hashAlgorithm' value does not match 'signature.signatureAlgorithmParameters.hashAlgorithm' value"
        end

        if params.salt_length.nil?
          raise SmartId::Errors::UnprocessableResponseError,
                "Signature session status field 'signature.signatureAlgorithmParameters.saltLength' is missing"
        end
        unless params.salt_length == SUPPORTED_HASH_ALGORITHMS[hash_algorithm]
          raise SmartId::Errors::UnprocessableResponseError,
                "Signature session status field 'signature.signatureAlgorithmParameters.saltLength' has invalid value"
        end
        if blank?(params.trailer_field)
          raise SmartId::Errors::UnprocessableResponseError,
                "Signature status field `signature.signatureAlgorithmParameters.trailerField` is empty"
        end
        unless params.trailer_field == SUPPORTED_TRAILER_FIELD
          raise SmartId::Errors::UnprocessableResponseError,
                "Signature status field `signature.signatureAlgorithmParameters.trailerField` has unsupported value"
        end
      end

      def handle_error_result(result)
        if result.end_result == "USER_REFUSED_INTERACTION"
          raise_user_refused_interaction_error(result)
        end
        if result.end_result == "DOCUMENT_UNUSABLE"
          raise SmartId::Errors::DocumentUnusableError
        end

        raise SmartId::Errors::SessionEndResultError.new(
          result.end_result,
          END_RESULT_MESSAGES[result.end_result] || "Unexpected session result: #{result.end_result}"
        )
      end

      def raise_user_refused_interaction_error(result)
        interaction = result.details&.interaction
        if blank?(interaction)
          raise SmartId::Errors::UnprocessableResponseError, "Details for refused interaction are missing"
        end

        case interaction
        when "displayTextAndPIN"
          raise SmartId::Errors::UserRefusedDisplayTextAndPinError
        when "confirmationMessage"
          raise SmartId::Errors::UserRefusedConfirmationMessageError
        when "confirmationMessageAndVerificationCodeChoice"
          raise SmartId::Errors::UserRefusedConfirmationMessageWithVerificationChoiceError
        else
          raise SmartId::Errors::UnprocessableResponseError, "Unexpected interaction type: #{interaction}"
        end
      end

      def parse_certificate(value, error_message)
        decoded = Base64.decode64(value.to_s)
        certificate = OpenSSL::X509::Certificate.new(decoded)
        now = Time.now
        return certificate if certificate.not_before <= now && now <= certificate.not_after

        raise SmartId::Errors::UnprocessableResponseError, error_message
      rescue OpenSSL::X509::CertificateError, ArgumentError
        raise SmartId::Errors::UnprocessableResponseError, error_message
      end

      def extract_certificate_policy_oids(certificate)
        extension = certificate.extensions.find { |ext| ext.oid == "certificatePolicies" }
        return [] unless extension

        extension.value.scan(/\b\d+(?:\.\d+)+\b/)
      end

      def normalize_status(session_status)
        return session_status if session_status.respond_to?(:result)
        return SmartId::Models::SessionStatus.from_h(session_status) if session_status.is_a?(Hash)

        nil
      end

      def fetch_hash_value(payload, key)
        return nil unless payload.respond_to?(:[])

        payload[key] || payload[key.to_s]
      end

      def blank?(value)
        value.nil? || value.to_s.strip.empty?
      end
    end
  end
end
