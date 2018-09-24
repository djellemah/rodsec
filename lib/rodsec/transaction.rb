require_relative 'wrapper'
require_relative 'string_pointers'

module Rodsec
  class Transaction
    # txn_log_tag must be convertible to a string. Defaults to self.object_id.to_s
    # it shows up in as the first argument passed to Modsec's log_blk.
    def initialize msc, ruleset, txn_log_tag: nil
      raise Error, "msc must be a #{Modsec}" unless Modsec === msc
      raise Error, "ruleset must be a #{RuleSet}" unless RuleSet === ruleset

      @msc, @ruleset = msc, ruleset
      @txn_log_tag = Fiddle::Pointer[(txn_log_tag || object_id).to_s]
      @txn_ptr = Wrapper.msc_new_transaction msc.msc_ptr, ruleset.rules_ptr, @txn_log_tag
      @txn_ptr.free = Wrapper['msc_transaction_cleanup']
    end

    attr_reader :txn_ptr

    attr_reader :msc, :ruleset

    include StringPointers

    # Raise an Intervention(ModSecurityIntervention) if necessary, or return self.
    #
    # ModSecurity will only populate the intervention structure if it detects
    # something 'disruptive' in the SecRules.
    protected def intervention!
      # Check for Intervention
      msi = Wrapper::ModSecurityIntervention.new Wrapper.msc_new_intervention
      rv = Wrapper.msc_intervention txn_ptr, msi
      raise Intervention, msi if rv > 0
      self
    end

    ##################################
    # Phase CONNECTION / SecRules  0
    # check for intervention afterwards
    def connection! client_host, client_port, server_host, server_port
      rv = Wrapper.msc_process_connection \
        txn_ptr,
        (strptr client_host), (Integer client_port),
        (strptr server_host), (Integer server_port)

      rv == 1 or raise Error, "msc_process_connection failed for #{[client_host, client_port, server_host, server_port].inspect}"

      intervention!
    end

    ##################################
    # Phase URI / 1.5
    # check for intervention afterwards
    # verb is GET POST etc
    # http_version is '1.1', '1.2' etc
    def uri! uri, verb, http_version
      rv = Wrapper.msc_process_uri txn_ptr, (strptr uri), (strptr verb), (strptr http_version)
      rv == 1 or raise Error "msc_process_uri failed for #{[uri, verb, http_version].inspect}"

      intervention!
    end

    ##################################
    # Phase REQUEST_HEADERS.  SecRules 1
    def request_headers! header_hash
      errors = header_hash.each_with_object [] do |(key, val), errors|
        key = key.to_s; val = val.to_s
        rv = Wrapper.msc_add_n_request_header txn_ptr, (strptr key), key.bytesize, (strptr val), val.bytesize
        rv == 1 or errors << "msc_add_n_request_header failed adding #{[key,val].inspect}"
      end

      raise Error errors if errors.any?

      rv = Wrapper.msc_process_request_headers txn_ptr
      rv == 1 or raise "msc_process_request_headers failed"

      intervention!
    end

    protected def enum_of_body body
      case
      when NilClass === body
        ['']
      when String === body
        [body]
      when body.respond_to?(:each)
        body
      else
        raise "dunno about #{body}"
      end
    end

    ##################################
    # Phase REQUEST_BODY.  SecRules 2
    #
    # body can be a String, or an Enumerable of strings
    def request_body! body
      enum_of_body(body).each do |body_part|
        body_part = body_part.to_s
        rv = Wrapper.msc_append_request_body txn_ptr, (strptr body_part), body_part.bytesize
        rv == 1 or raise Error, "msc_append_request_body failed"
      end

      # This MUST be called, otherwise rules aren't triggered.
      rv = Wrapper.msc_process_request_body txn_ptr
      rv == 1 or raise Error, "msc_process_request_body failed"

      intervention!
    end

    # This is probably only used when appending a body in chunks. We don't use it.
    # extern 'size_t msc_get_request_body_length(Transaction *transaction)'

    ##################################
    # Phase RESPONSE_HEADERS. SecRules 3
    # http_status_code is one of the 200, 401, 404 etc codes
    # http_with_version seems to be things like 'HTTP 1.2', not entirely sure.
    def response_headers! http_status_code = 200, http_with_version = 'HTTP 1.1', header_hash
      errors = header_hash.each_with_object [] do |(key, val), errors|
        key = key.to_s; val = val.to_s
        rv = Wrapper.msc_add_n_response_header txn_ptr, (strptr key), key.bytesize, (strptr val), val.bytesize
        rv == 1 or errors << "msc_add_n_response_header failed adding #{[key,val].inspect}"
      end

      raise Error, errors if errors.any?

      rv = Wrapper.msc_process_response_headers txn_ptr, (Integer http_status_code), (strptr http_with_version)
      rv == 1 or raise "msc_process_response_headers failed"

      intervention!
    end

    # Called after msc_process_response_headers "to inform a new response code"
    # Not mandatory. Not sure what it means really. Maybe it affects the intervention values?
    # extern 'int msc_update_status_code(Transaction *transaction, int status)'

    ##################################
    # Phase RESPONSE_BODY. SecRules 4
    #
    # body can be a String, or an Enumerable of strings
    def response_body! body
      enum_of_body(body).each do |body_part|
        body_part = body_part.to_s
        rv = Wrapper.msc_append_response_body txn_ptr, (strptr body_part), body_part.bytesize
        rv == 1 or raise Error, 'msc_append_response_body failed'
      end

      # This MUST be called, otherwise rules aren't triggered
      rv = Wrapper.msc_process_response_body txn_ptr
      rv == 1 or raise Error, "msc_process_response_body failed"

      intervention!
    end

    # Needed if ModSecurity modifies the outgoing body. We don't make use of that.
    # extern 'const char *msc_get_response_body(Transaction *transaction)'
    # extern 'size_t msc_get_response_body_length(Transaction *transaction)'

    ##################################
    # Phase LOGGING. SecRules 5.
    # just logs all information. Response can be sent prior to this, or concurrently.
    def logging
      rv = Wrapper.msc_process_logging txn_ptr
      rv == 1 or raise 'msc_process_logging failed'

      self
    end
  end
end
