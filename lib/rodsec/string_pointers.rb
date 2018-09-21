module Rodsec
  module StringPointers
    EMPTY_STRING = String.new.freeze

    def strptr str
      # nil often causes ModSecurity to segfault
      str || EMPTY_STRING
    end
  end
end
