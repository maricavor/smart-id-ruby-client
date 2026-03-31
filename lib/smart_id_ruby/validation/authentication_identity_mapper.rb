# frozen_string_literal: true

require "date"
require "openssl"

module SmartIdRuby
  module Validation
    # Maps authentication certificates to typed identity models.
    class AuthenticationIdentityMapper
      # OID for dateOfBirth attribute inside subjectDirectoryAttributes extension (id-pda-dateOfBirth).
      DATE_OF_BIRTH_OID = "1.3.6.1.5.5.7.9.1"
      # OID for subjectDirectoryAttributes certificate extension.
      SUBJECT_DIRECTORY_ATTRIBUTES_OID = "subjectDirectoryAttributes"
      # OID for X.509 Subject Directory Attributes extension (2.5.29.9).
      SUBJECT_DIRECTORY_ATTRIBUTES_EXTENSION_OID = "2.5.29.9"

      # Builds an {SmartIdRuby::Models::AuthenticationIdentity} from an
      # X.509 authentication certificate.
      #
      # Extracts given name, surname, national identity number, country and
      # date of birth (either from certificate extensions or by parsing the
      # national identity number as a fallback).
      #
      # @param certificate [OpenSSL::X509::Certificate]
      # @return [SmartIdRuby::Models::AuthenticationIdentity]
      def from(certificate)
        attrs = extract_subject_attributes(certificate)

        raw_given_name = attrs["GN"] || attrs["givenName"] || attrs["GIVENNAME"]
        raw_surname = attrs["SN"] || attrs["surname"] || attrs["SURNAME"]
        identity_number = normalize_identity_number(attrs["serialNumber"] || attrs["SERIALNUMBER"])
        country = attrs["C"]

        given_name = normalize_diacritics(raw_given_name)
        surname = normalize_diacritics(raw_surname)

        log_debug_identity_attrs(raw_given_name, given_name, raw_surname, surname, identity_number, country)

        SmartIdRuby::Models::AuthenticationIdentity.new(
          given_name: given_name,
          surname: surname,
          identity_number: identity_number,
          country: country,
          auth_certificate: certificate,
          date_of_birth: extract_date_of_birth_from_certificate(certificate) || fallback_date_of_birth(country, identity_number)
        )
      end

      private

      # Extracts subject DN attributes from the certificate into a simple Hash.
      #
      # @param certificate [OpenSSL::X509::Certificate]
      # @return [Hash{String => String}]
      def extract_subject_attributes(certificate)
        certificate.subject.to_a.each_with_object({}) do |entry, attrs|
          key, value = entry[0], entry[1]
          attrs[key] = value
        end
      end

      def normalize_identity_number(serial_number)
        return nil if serial_number.nil?

        serial_number.split("-", 2).last
      end

      def fallback_date_of_birth(country, identity_number)
        return nil if blank?(country) || blank?(identity_number)

        case country.to_s.upcase
        when "EE", "LT"
          parse_ee_lt_date_of_birth(identity_number)
        when "LV"
          parse_lv_date_of_birth(identity_number)
        end
      end

      def parse_ee_lt_date_of_birth(identity_number)
        first_digit = identity_number[0]
        birth_date_part = identity_number[1, 6]
        century = case first_digit
                  when "1", "2" then "18"
                  when "3", "4" then "19"
                  when "5", "6" then "20"
                  else
                    raise SmartIdRuby::Errors::UnprocessableResponseError,
                          "Could not parse birthdate from nationalIdentityNumber=#{identity_number}"
                  end
        Date.strptime("#{century}#{birth_date_part}", "%Y%m%d")
      rescue ArgumentError
        raise SmartIdRuby::Errors::UnprocessableResponseError,
              "Could not parse birthdate from nationalIdentityNumber=#{identity_number}"
      end

      def parse_lv_date_of_birth(identity_number)
        birth_day = identity_number[0, 2]
        return nil if birth_day.match?(/\A3[2-9]\z/)

        birth_month = identity_number[2, 2]
        birth_year_two_digit = identity_number[4, 2]
        century_marker = identity_number[7]
        century = case century_marker
                  when "0" then "18"
                  when "1" then "19"
                  when "2" then "20"
                  else
                    raise SmartIdRuby::Errors::UnprocessableResponseError, "Invalid personal code: #{identity_number}"
                  end

        Date.strptime("#{century}#{birth_year_two_digit}#{birth_month}#{birth_day}", "%Y%m%d")
      rescue ArgumentError
        raise SmartIdRuby::Errors::UnprocessableResponseError,
              "Unable get birthdate from Latvian personal code #{identity_number}"
      end

      def extract_date_of_birth_from_certificate(certificate)
        extension = certificate.extensions.find do |ext|
          [SUBJECT_DIRECTORY_ATTRIBUTES_OID, SUBJECT_DIRECTORY_ATTRIBUTES_EXTENSION_OID].include?(ext.oid)
        end
        return nil if extension.nil?

        generalized_time = find_date_of_birth_generalized_time(extension)
        return nil if generalized_time.nil?

        parse_generalized_time(generalized_time)
      rescue OpenSSL::ASN1::ASN1Error, TypeError
        nil
      end

      def find_date_of_birth_generalized_time(extension)
        decoded = OpenSSL::ASN1.decode(extension.to_der)
        octet_string = decoded.value.find { |node| node.is_a?(OpenSSL::ASN1::OctetString) }
        return nil if octet_string.nil?

        inner = OpenSSL::ASN1.decode(octet_string.value)
        find_date_of_birth_in_node(inner)
      end

      def find_date_of_birth_in_node(node)
        return nil unless node.respond_to?(:value)

        value = node.value
        return nil unless value.is_a?(Array)

        value.each_with_index do |item, index|
          if item.is_a?(OpenSSL::ASN1::ObjectId) && item.value == DATE_OF_BIRTH_OID
            return extract_generalized_time(value[index + 1])
          end
          found = find_date_of_birth_in_node(item)
          return found if found
        end
        nil
      end

      def extract_generalized_time(node)
        return nil if node.nil? || !node.respond_to?(:value)

        if node.is_a?(OpenSSL::ASN1::GeneralizedTime)
          return node.value
        end

        value = node.value
        return nil unless value.is_a?(Array)

        value.each do |child|
          found = extract_generalized_time(child)
          return found if found
        end
        nil
      end

      def parse_generalized_time(value)
        parsed = if value.respond_to?(:to_time)
                   value.to_time.utc
                 else
                   Time.strptime(value.to_s, "%Y%m%d%H%M%SZ").utc
                 end
        parsed.to_date
      rescue ArgumentError
        nil
      end

      def blank?(value)
        value.nil? || value.to_s.strip.empty?
      end

      # Converts legacy escaped byte sequences inside DN values to proper UTF-8.
      # Example:
      #   "J\\xC4\\x81nis B\\xC4\\x93rzi\\xC5\\x86\\xC5\\xA1" (ASCII-8BIT)
      # becomes:
      #   "Jānis Bērziņš" (UTF-8)
      def normalize_diacritics(value)
        return nil if value.nil?

        text = value.to_s.dup

        # Legacy certificates / libraries sometimes encode diacritics as \xNN escape
        # sequences in the distinguished name string. Convert those into bytes first.
        if text.include?("\\x")
          text = text.gsub(/\\x([0-9A-Fa-f]{2})/) { Regexp.last_match(1).hex.chr }
        end

        # Then interpret as UTF-8 and scrub only truly invalid byte sequences,
        # preserving valid characters like Õ, Ä, Ö, Ü, etc.
        text.force_encoding(Encoding::UTF_8).scrub
      end

      def log_debug_identity_attrs(raw_given_name, given_name, raw_surname, surname, identity_number, country)
        logger = SmartIdRuby.logger

        logger.debug(
          "Smart-ID identity mapping: " \
          "raw_given_name=#{raw_given_name}, " \
          "normalized_given_name=#{given_name}, " \
          "raw_surname=#{raw_surname}, " \
          "normalized_surname=#{surname}, " \
          "identity_number_suffix=#{identity_number && identity_number[-4, 4]}, " \
          "country=#{country}"
        )
      rescue StandardError
        # Logging must never break authentication flow
        nil
      end
    end
  end
end
