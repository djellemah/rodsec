require_relative 'wrapper'
require_relative 'version'
require_relative 'string_pointers'

module Rodsec
  class Modsec
    def initialize &log_blk
      @msc_ptr = Wrapper.msc_init
      @msc_ptr.free = Wrapper['msc_cleanup']

      Wrapper.msc_set_connector_info @msc_ptr, (strptr info_string)

      logger_fn &log_blk
    end

    include StringPointers

    attr_reader :msc_ptr

    # Given a block, this will set the logger callback.
    # With no block, it will return the current logger callback, which may be nil.
    # 'ModSecLogCb', 'void (*) (void *, const void *)'
    # msc_set_log_cb(ModSecurity *msc, ModSecLogCb cb)
    def logger_fn &log_blk
      if block_given?
        # set the logger callback
        #
        # NOTENOTE logger_fn and logger_closure must NOT be garbage-collected,
        # otherwise callbacks from C to logger_fn will segfault. Also,
        # Fiddle::Function seems to not keep a reference its closure argument,
        # so hang on to that too.

        return_type = Fiddle::TYPE_VOID
        arg_types = Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP

        # TODO apparently the value of void_p_data1 can be set somewhere. Dunno if it's at msc level or transaction level.
        @logger_closure = Fiddle::Closure::BlockCaller.new return_type, arg_types do |void_p_data1, log_str_ptr|
          log_blk.call log_str_ptr.to_s
        end

        @logger_fn = Fiddle::Function.new @logger_closure, arg_types, return_type
        Wrapper.msc_set_log_cb @msc_ptr, @logger_fn
      else
        # return the logger callback, might be nil
        @logger_fn
      end
    end

    # given to ModSecurity.
    # should be in the form ConnectorName vX.Y.Z-tag (something else)
    def info_string
      "Rodsec v#{VERSION}"
    end

    # information about the version of libmodsecurity
    def version_info
      (Wrapper.msc_who_am_i @msc_ptr).to_s
    end
  end
end
