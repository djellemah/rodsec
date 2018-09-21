require "rodsec/version"
require 'rodsec/modsec'
require 'rodsec/rule_set'
require 'rodsec/transaction'

module Rodsec
  class Error < StandardError; end

  class Intervention < StandardError
    def initialize msi
      @msi = msi
      super()
    end

    attr_reader :msi
  end
end
