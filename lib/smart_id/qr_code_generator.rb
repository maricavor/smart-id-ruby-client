# frozen_string_literal: true

require "base64"
require "rqrcode"

module SmartId
  # Utility for generating QR-code images and Data URIs.
  class QrCodeGenerator
    DEFAULT_QR_CODE_WIDTH_PX = 610
    DEFAULT_QR_CODE_HEIGHT_PX = 610
    DEFAULT_QUIET_AREA_SIZE_MODULES = 4
    DEFAULT_FILE_FORMAT = "png"

    class << self
      def generate_data_uri(data)
        image = generate_image(data)
        convert_to_data_uri(image, DEFAULT_FILE_FORMAT)
      end

      def generate_image(data, width_px = DEFAULT_QR_CODE_WIDTH_PX, height_px = DEFAULT_QR_CODE_HEIGHT_PX, quiet_area_size = DEFAULT_QUIET_AREA_SIZE_MODULES)
        validate_data!(data)

        qrcode = RQRCode::QRCode.new(data.to_s, level: :l)
        qrcode.as_png(
          border_modules: quiet_area_size.to_i,
          module_px_size: 1
        ).resample_nearest_neighbor(width_px.to_i, height_px.to_i)
      rescue StandardError => e
        raise if e.is_a?(SmartId::Errors::RequestSetupError)

        raise SmartId::Errors::RequestSetupError, "Unable to create QR-code: #{e.message}"
      end

      def convert_to_data_uri(image, file_format = DEFAULT_FILE_FORMAT)
        format = file_format.to_s.downcase
        image_bytes = image_to_bytes(image, format)
        encoded = Base64.strict_encode64(image_bytes)
        "data:image/#{format};base64,#{encoded}"
      end

      private

      def validate_data!(data)
        return unless data.nil? || data.to_s.empty?

        raise SmartId::Errors::RequestSetupError, "Provided data cannot be empty"
      end

      def image_to_bytes(image, file_format)
        if image.respond_to?(:to_datastream)
          image.to_datastream.to_s
        elsif image.is_a?(String)
          image
        else
          raise SmartId::Errors::RequestSetupError, "Unable to generate QR-code as #{file_format}"
        end
      end
    end
  end
end
