# frozen_string_literal: true

require "base64"
require "json"

module SmartId
  module Flows
    # Base builder with shared helper methods for request builders.
    class BaseBuilder
      attr_reader :connector, :relying_party_uuid, :relying_party_name

      def initialize(connector)
        @connector = connector
      end

      def with_relying_party_uuid(value)
        @relying_party_uuid = value
        self
      end

      def with_relying_party_name(value)
        @relying_party_name = value
        self
      end

      private

      def blank?(value)
        value.nil? || value.to_s.strip.empty?
      end

      def fetch_value(container, key)
        return nil if container.nil?

        key_str = key.to_s
        snake_key = underscore_key(key_str)
        candidates = [key, key_str, snake_key.to_sym, snake_key].uniq

        if container.respond_to?(:[])
          candidates.each do |candidate|
            value = container[candidate]
            return value unless value.nil?
          end
        end

        candidates.each do |candidate|
          method_name = candidate.is_a?(Symbol) ? candidate : candidate.to_s
          return container.public_send(method_name) if container.respond_to?(method_name)
        end

        nil
      end

      def normalize_interactions(interactions)
        Array(interactions).compact.map { |interaction| normalize_interaction(interaction) }
      end

      def normalize_interaction(interaction)
        if interaction.respond_to?(:to_h)
          interaction.to_h.transform_keys(&:to_sym)
        elsif interaction.is_a?(Hash)
          interaction.transform_keys(&:to_sym)
        else
          raise SmartId::Errors::RequestSetupError, "Unsupported interaction object type: #{interaction.class}"
        end
      end

      def encode_interactions(interactions)
        Base64.strict_encode64(JSON.generate(normalize_interactions(interactions)))
      end

      def normalize_capabilities(capabilities, strip: true, reject_empty: true)
        values = Array(capabilities).flatten.compact.map(&:to_s)
        values = values.map(&:strip) if strip
        values = values.reject(&:empty?) if reject_empty
        values.uniq
      end

      def request_properties_for_share_md(share_md_client_ip_address)
        return nil if share_md_client_ip_address.nil?

        { shareMdClientIpAddress: share_md_client_ip_address }
      end

      def underscore_key(value)
        value.to_s.gsub(/([A-Z])/, "_\\1").downcase.sub(/\A_/, "")
      end
    end
  end
end
