# frozen_string_literal: true

require "date"
require "openssl"

module SmartId
  module Validation
    # Maps authentication certificates to typed identity models.
    class AuthenticationIdentityMapper
      DATE_OF_BIRTH_OID = "1.3.6.1.5.5.7.9.1"

      def from(certificate)
        attributes = extract_subject_attributes(certificate)
        identity_number = normalize_identity_number(attributes["serialNumber"] || attributes["SERIALNUMBER"])
        country = attributes["C"]

        SmartId::Models::AuthenticationIdentity.new(
          given_name: attributes["GN"] || attributes["givenName"] || attributes["GIVENNAME"],
          surname: attributes["SN"] || attributes["surname"] || attributes["SURNAME"],
          identity_number: identity_number,
          country: country,
          auth_certificate: certificate,
          date_of_birth: extract_date_of_birth_from_certificate(certificate) || fallback_date_of_birth(country, identity_number)
        )
      end

      private

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
        else
          nil
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
                    raise SmartId::Errors::UnprocessableResponseError,
                          "Could not parse birthdate from nationalIdentityNumber=#{identity_number}"
                  end
        Date.strptime("#{century}#{birth_date_part}", "%Y%m%d")
      rescue ArgumentError
        raise SmartId::Errors::UnprocessableResponseError,
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
                    raise SmartId::Errors::UnprocessableResponseError, "Invalid personal code: #{identity_number}"
                  end

        Date.strptime("#{century}#{birth_year_two_digit}#{birth_month}#{birth_day}", "%Y%m%d")
      rescue ArgumentError
        raise SmartId::Errors::UnprocessableResponseError,
              "Unable get birthdate from Latvian personal code #{identity_number}"
      end

      def extract_date_of_birth_from_certificate(certificate)
        extension = certificate.extensions.find do |ext|
          ext.oid == "subjectDirectoryAttributes" || ext.oid == "2.5.29.9"
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
    end
  end
end
