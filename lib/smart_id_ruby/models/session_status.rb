# frozen_string_literal: true

module SmartIdRuby
  module Models
    # Represents response for active Smart-ID session query.
    # state - Required. Current state of the session, e.g. "RUNNING", "COMPLETE".
    # result - Required if state is "COMPLETE". Details about how session ended.
    # signature_protocol - Required if end result is OK. Signature protocol used, e.g. "ACSP_V2" or "RAW_DIGEST_SIGNATURE".
    # signature - Required if end result is OK. Signature data containing the actual signature and related information.
    # cert - Required if end result is OK. Signer's certificate data.
    # ignored_properties - Properties that were ignored from the session request.
    # interaction_type_used - Required if end result is OK. Interaction type that was used in the session.
    # device_ip_address - IP address of the device used in the session.
    class SessionStatus
      attr_reader :state, :result, :signature_protocol, :signature, :cert,
                  :ignored_properties, :interaction_type_used, :device_ip_address

      def initialize(
        state: nil,
        result: nil,
        signature_protocol: nil,
        signature: nil,
        cert: nil,
        ignored_properties: nil,
        interaction_type_used: nil,
        device_ip_address: nil
      )
        @state = state
        @result = result
        @signature_protocol = signature_protocol
        @signature = signature
        @cert = cert
        @ignored_properties = ignored_properties
        @interaction_type_used = interaction_type_used
        @device_ip_address = device_ip_address
      end

      def running?
        state.to_s.casecmp("RUNNING").zero?
      end

      def complete?
        state.to_s.casecmp("COMPLETE").zero?
      end

      def to_h
        {
          state: state,
          result: result.to_h,
          signature_protocol: signature_protocol,
          signature: signature.to_h,
          cert: cert.to_h,
          ignored_properties: ignored_properties,
          interaction_type_used: interaction_type_used,
          device_ip_address: device_ip_address
        }
      end

      def self.from_h(payload)
        return new unless payload.is_a?(Hash)

        new(
          state: fetch(payload, :state),
          result: SessionResult.from_h(fetch(payload, :result)),
          signature_protocol: fetch(payload, :signatureProtocol),
          signature: SessionSignature.from_h(fetch(payload, :signature)),
          cert: SessionCertificate.from_h(fetch(payload, :cert)),
          ignored_properties: fetch(payload, :ignoredProperties),
          interaction_type_used: fetch(payload, :interactionTypeUsed),
          device_ip_address: fetch(payload, :deviceIpAddress)
        )
      end

      def self.fetch(payload, key)
        payload[key] || payload[key.to_s]
      end
      private_class_method :fetch
    end

    # Represents session result data returned by Smart-ID.
    class SessionResult
      attr_reader :end_result, :document_number, :details

      def initialize(end_result: nil, document_number: nil, details: nil)
        @end_result = end_result
        @document_number = document_number
        @details = details
      end

      def to_h
        {
          end_result: end_result,
          document_number: document_number,
          details: details.to_h
        }
      end

      def self.from_h(payload)
        return nil unless payload.is_a?(Hash)

        new(
          end_result: fetch(payload, :endResult),
          document_number: fetch(payload, :documentNumber),
          details: SessionResultDetails.from_h(fetch(payload, :details))
        )
      end

      def self.fetch(payload, key)
        payload[key] || payload[key.to_s]
      end
      private_class_method :fetch
    end

    # Represents additional result details for a session.
    class SessionResultDetails
      attr_reader :interaction

      def initialize(interaction: nil)
        @interaction = interaction
      end

      def to_h
        {
          interaction: interaction
        }
      end

      def self.from_h(payload)
        return nil unless payload.is_a?(Hash)

        new(interaction: fetch(payload, :interaction))
      end

      def self.fetch(payload, key)
        payload[key] || payload[key.to_s]
      end
      private_class_method :fetch
    end

    # Represents signature details in session status response.
    class SessionSignature
      attr_reader :value, :server_random, :user_challenge, :flow_type,
                  :signature_algorithm, :signature_algorithm_parameters

      def initialize(
        value: nil,
        server_random: nil,
        user_challenge: nil,
        flow_type: nil,
        signature_algorithm: nil,
        signature_algorithm_parameters: nil
      )
        @value = value
        @server_random = server_random
        @user_challenge = user_challenge
        @flow_type = flow_type
        @signature_algorithm = signature_algorithm
        @signature_algorithm_parameters = signature_algorithm_parameters
      end

      def to_h
        {
          value: value,
          server_random: server_random,
          user_challenge: user_challenge,
          flow_type: flow_type,
          signature_algorithm: signature_algorithm,
          signature_algorithm_parameters: signature_algorithm_parameters.to_h
        }
      end

      def self.from_h(payload)
        return nil unless payload.is_a?(Hash)

        new(
          value: fetch(payload, :value),
          server_random: fetch(payload, :serverRandom),
          user_challenge: fetch(payload, :userChallenge),
          flow_type: fetch(payload, :flowType),
          signature_algorithm: fetch(payload, :signatureAlgorithm),
          signature_algorithm_parameters: SessionSignatureAlgorithmParameters.from_h(
            fetch(payload, :signatureAlgorithmParameters)
          )
        )
      end

      def self.fetch(payload, key)
        payload[key] || payload[key.to_s]
      end
      private_class_method :fetch
    end

    # Represents signature algorithm parameters for session signature.
    class SessionSignatureAlgorithmParameters
      attr_reader :hash_algorithm, :mask_gen_algorithm, :salt_length, :trailer_field

      def initialize(hash_algorithm: nil, mask_gen_algorithm: nil, salt_length: nil, trailer_field: nil)
        @hash_algorithm = hash_algorithm
        @mask_gen_algorithm = mask_gen_algorithm
        @salt_length = salt_length
        @trailer_field = trailer_field
      end

      def to_h
        {
          hash_algorithm: hash_algorithm,
          mask_gen_algorithm: mask_gen_algorithm,
          salt_length: salt_length,
          trailer_field: trailer_field
        }
      end

      def self.from_h(payload)
        return nil unless payload.is_a?(Hash)

        new(
          hash_algorithm: fetch(payload, :hashAlgorithm),
          mask_gen_algorithm: fetch(payload, :maskGenAlgorithm),
          salt_length: fetch(payload, :saltLength),
          trailer_field: fetch(payload, :trailerField)
        )
      end

      def self.fetch(payload, key)
        payload[key] || payload[key.to_s]
      end
      private_class_method :fetch
    end

    # Represents certificate payload in session status response.
    class SessionCertificate
      attr_reader :value, :certificate_level

      def initialize(value: nil, certificate_level: nil)
        @value = value
        @certificate_level = certificate_level
      end

      def to_h
        {
          value: value,
          certificate_level: certificate_level
        }
      end

      def self.from_h(payload)
        return nil unless payload.is_a?(Hash)

        new(
          value: fetch(payload, :value),
          certificate_level: fetch(payload, :certificateLevel)
        )
      end

      def self.fetch(payload, key)
        payload[key] || payload[key.to_s]
      end
      private_class_method :fetch
    end
  end
end
