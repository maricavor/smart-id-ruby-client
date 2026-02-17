# frozen_string_literal: true

module SmartId
  module Flows
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
    end
  end
end
