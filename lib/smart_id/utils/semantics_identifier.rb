require "smart_id/exceptions"

module SmartId
  module Utils
    class SemanticsIdentifier
      attr_reader :identifier

      IDENTITY_TYPES = %i[PAS IDC PNO].freeze
      COUNTRY_CODES = %i[EE LT LV BE].freeze

      def initialize(*args)
        case args.size
        when 3
          identity_type, country_code, identity_number = args
          validate_identity_type(identity_type)
          validate_country_code(country_code)
          @identifier = construct_identifier(identity_type, country_code, identity_number)
        when 1
          @identifier = args.first
        else
          raise InvalidParamsError, 'Invalid number of arguments'
        end
      end

      def construct_identifier(identity_type, country_code, identity_number)
        "#{identity_type}#{country_code}-#{identity_number}"
      end

      def to_s
        "SemanticsIdentifier{identifier='#{@identifier}'}"
      end

      private

      def validate_identity_type(identity_type)
        return if IDENTITY_TYPES.include?(identity_type.to_sym)

        raise InvalidParamsError, "Invalid identity type: #{identity_type}"
      end

      def validate_country_code(country_code)
        return if COUNTRY_CODES.include?(country_code.to_sym)

        raise InvalidParamsError, "Invalid country code: #{country_code}"
      end
    end
  end
end
