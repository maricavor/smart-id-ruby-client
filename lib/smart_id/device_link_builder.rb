# frozen_string_literal: true

module SmartId
  class DeviceLinkBuilder
    attr_reader :relying_party_name

    def with_relying_party_name(value)
      @relying_party_name = value
      self
    end
  end
end
