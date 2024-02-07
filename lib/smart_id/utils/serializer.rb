module SmartId
  module Utils
    module Serializer
      def serialize
        instance_variables.each_with_object({}) do |var, hash|
          key = var.to_s.delete('@').underscore.camelize(:lower)
          value = instance_variable_get(var)
          hash[key.to_sym] = value unless value.nil?
        end
      end
    end
  end
end
