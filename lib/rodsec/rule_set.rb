require 'pathname'

require_relative 'wrapper'
require_relative 'string_pointers'

module Rodsec
  class RuleSet
    def initialize tag: nil
      @tag = tag

      @rules_ptr = Wrapper.msc_create_rules_set
      @rules_ptr.free = Wrapper['msc_rules_cleanup']

      # just mirroring the c-api, not sure if it's actually useful
      @rule_count = 0
    end

    # srsly, don't mess with this
    attr_reader :rules_ptr

    attr_reader :tag, :rule_count

    include StringPointers

    # add rules from the given file
    # return number of rules added? I think?
    def add_file conf_pathname
      conf_pathname = Pathname conf_pathname
      err = Fiddle::Pointer[0]
      rv = Wrapper.msc_rules_add_file rules_ptr, (strptr conf_pathname.realpath.to_s), err.ref

      raise Error, [conf_pathname, err.to_s] if rv < 0
      @rule_count += rv
      self
    end

    # dump rules to stdout. No way to redirect that, from what I can see.
    def dump
      Wrapper.msc_rules_dump rules_ptr
      self
    end

    def add rules_text
      err = Fiddle::Pointer[0]
      rv = Wrapper.msc_rules_add rules_ptr, (strptr rules_text.to_s), err.ref
      raise Error, err.to_s if rv < 0
      @rule_count += rv
      self
    end

    def add_url key, url
      err = Fiddle::Pointer[0]
      rv = Wrapper.msc_rules_add_remote rules_ptr, (strptr key), (strptr uri), err.ref
      raise Error, err.to_s if rv < 0
      @rule_count += rv
      self
    end

    # merge other rules with self
    def merge other
      raise "must be a #{self.class.name}" unless self.class === other
      err = Fiddle::Pointer[0]
      rv = Wrapper.msc_rules_merge rules_ptr, other.rules_ptr, err.ref
      @rule_count += rv
      raise Error, err.to_s if rv < 0
      self
    end
  end
end
