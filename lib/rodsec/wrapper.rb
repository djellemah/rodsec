require 'fiddle'
require 'fiddle/import'

module Rodsec
  module Wrapper
    extend Fiddle::Importer

    dlext = RbConfig::CONFIG['DLEXT']
    msc_intervention = dlopen File.join __dir__, "msc_intervention.#{dlext}"
    dlload msc_intervention, "libmodsecurity.#{dlext}"

    ###########################
    # from modsecurity/modsecurity.h
    typealias 'ModSecurity', 'void'

    # ModSecurity *msc_init();
    extern 'ModSecurity *msc_init()'
    extern 'void msc_cleanup(ModSecurity *msc)'

    extern 'void msc_set_connector_info(ModSecurity *msc, const char *connector)'
    extern 'const char *msc_who_am_i(ModSecurity *msc)'

    # logging callback
    # see ModSecurity/headers/modsecurity/modsecurity.h:221
    typealias 'ModSecLogCb', 'void (*) (void *, const void *)'
    extern 'void msc_set_log_cb(ModSecurity *msc, ModSecLogCb cb)'

    ###########################
    # from modsecurity/rules.h
    typealias 'Rules', 'void'

    extern 'Rules *msc_create_rules_set()'
    extern 'int msc_rules_cleanup(Rules *rules)'

    extern 'int msc_rules_add(Rules *rules, const char *plain_rules, const char **error)'
    extern 'int msc_rules_add_file(Rules *rules, const char *file, const char **error)'
    extern 'int msc_rules_add_remote(Rules *rules, const char *key, const char *uri, const char **error)'

    extern 'int msc_rules_merge(Rules *rules_dst, Rules *rules_from, const char **error)'
    extern 'void msc_rules_dump(Rules *rules)'

    ###########################
    # from modsecurity/transaction.h
    # Phase documentation in src/transaction.cc
    # A bit more phase documentation in modsecurity/modsecurity.h near enum Phases
    typealias 'Transaction', 'void'

    extern 'Transaction *msc_new_transaction(ModSecurity *ms, Rules *rules, void *logCbData)'
    extern 'void msc_transaction_cleanup(Transaction *transaction)'

    # Phase CONNECTION / SecRules  0
    extern 'int msc_process_connection(Transaction *transaction, const char *client, int cPort, const char *server, int sPort)'

    # Phase URI / 1.5
    extern 'int msc_process_uri(Transaction *transaction, const char *uri, const char *protocol, const char *http_version)'

    # Phase REQUEST_HEADERS.  SecRules 1
    extern 'int msc_add_request_header(Transaction *transaction, const unsigned char *key, const unsigned char *value)'
    extern 'int msc_add_n_request_header(Transaction *transaction, const unsigned char *key, size_t len_key, const unsigned char *value, size_t len_value)'
    extern 'int msc_process_request_headers(Transaction *transaction)'

    # Phase REQUEST_BODY.  SecRules 2
    extern 'int msc_append_request_body(Transaction *transaction, const unsigned char *body, size_t size)'
    extern 'int msc_request_body_from_file(Transaction *transaction, const char *path)'
    extern 'int msc_process_request_body(Transaction *transaction)'
    extern 'size_t msc_get_request_body_length(Transaction *transaction)'

    # Phase RESPONSE_HEADERS. SecRules 3
    extern 'int msc_add_response_header(Transaction *transaction, const unsigned char *key, const unsigned char *value)'
    extern 'int msc_add_n_response_header(Transaction *transaction, const unsigned char *key, size_t len_key, const unsigned char *value, size_t len_value)'
    extern 'int msc_process_response_headers(Transaction *transaction, int code, const char* protocol)'

    # Called after msc_process_response_headers "to inform a new response code"
    # Not mandatory. Not sure what it means really.
    extern 'int msc_update_status_code(Transaction *transaction, int status)'

    # Phase RESPONSE_BODY. SecRules 4
    extern 'int msc_append_response_body(Transaction *transaction, const unsigned char *body, size_t size)'
    extern 'int msc_process_response_body(Transaction *transaction)'

    extern 'const char *msc_get_response_body(Transaction *transaction)'
    extern 'size_t msc_get_response_body_length(Transaction *transaction)'

    # Phase LOGGING. SecRules 5. Just log the transaction to the registered logger.
    extern 'int msc_process_logging(Transaction *transaction)'

    # Phase INTERVENTIONS (interleaved)
    #
    extern 'int msc_intervention(Transaction *transaction, ModSecurityIntervention *it)'

    ###############################
    # And now we need a little cpp work to access this struct without without spectacularly leaking memory.

    # This isn't used. But ah kept it cos it's purty.
    def self.free_fn_ptr
      @free_fn_ptr ||= Fiddle::Function.new Fiddle::RUBY_FREE, [Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOID
    end

    # from modsecurity/intervention.h
    # typedef struct ModSecurityIntervention_t {
    #     int status;
    #     int pause;
    #     char *url;
    #     char *log;
    #     int disruptive;
    # } ModSecurityIntervention;
    ModSecurityIntervention_t = struct ['int status', 'int pause', 'char *url', 'char *log', 'int disruptive']

    class ModSecurityIntervention < ModSecurityIntervention_t
      def initialize( *args )
        super
        to_ptr.free = Wrapper['msc_free_intervention']
      end

      def log
        ptr = super
        ptr.to_s unless ptr.null?
      end

      def url
        ptr = super
        ptr.to_s unless ptr.null?
      end

      def to_h
        @entity.instance_variable_get(:@members).map do |member|
          [member, (send member)]
        end.to_h
      end
    end

    # These two are defined in the msc_intervention extension
    extern 'ModSecurityIntervention_t * msc_new_intervention()'
    extern 'int msc_free_intervention(ModSecurityIntervention *it)'
  end
end
