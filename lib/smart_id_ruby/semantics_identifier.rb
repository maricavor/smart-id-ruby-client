# frozen_string_literal: true

module SmartIdRuby
  # Representation of Semantic Identifier.
  class SemanticsIdentifier
    module IdentityType
      PAS = "PAS"
      IDC = "IDC"
      PNO = "PNO"
    end

    module CountryCode
      EE = "EE"
      LT = "LT"
      LV = "LV"
    end

    attr_reader :identifier

    # Supports:
    # - SemanticsIdentifier.new("PNO", "EE", "30303039914")
    # - SemanticsIdentifier.new("PNOEE-30303039914")
    def initialize(identity_type_or_identifier, country_code = nil, identity_number = nil)
      @identifier =
        if country_code.nil? && identity_number.nil?
          identity_type_or_identifier
        elsif !country_code.nil? && !identity_number.nil?
          "#{identity_type_or_identifier}#{country_code}-#{identity_number}"
        else
          raise SmartIdRuby::Errors::RequestValidationError,
                "Provide either full identifier or identityType + countryCode + identityNumber"
        end
    end
  end
end
