require_relative '../rodsec.rb'

module Rodsec
  # Thanks to rack-contrib/deflect for the basic idea, and some of the docs.
  class Rack
    attr_reader :options, :log_blk, :logger

    # === Required Options:
    #
    #   :config_dir the directory containing the ModSecurity config and rules files
    #
    # === Optional Options:
    #
    #   :logger   must respond_to #puts which takes a string. Defaults to a StringIO at #logger
    #
    #   :log_blk  a callable that takes |src_class,string| Defaults to sending
    #             only the string to logger. The ModSecurity logs are highly
    #             structured and you might want to parse the, so the src_class
    #             helps disambiguate the source of the logs. Making parsing easier.
    #
    #   ? :msi_blk  called with [status, headers, body] if there's an intervention from ModSecurity.
    #
    #
    # === Examples:
    #
    #  use Rodsec::Rack, config_dir: 'your_config_path', log: (mylogger = StringIO.new)
    #  use Rodsec::Rack, config_dir: 'your_config_path', log_blk: -> src_class, str { my_funky_parse_msi_to_hash str }
    def initialize app, config_dir:, logger: nil, log_blk: nil
      @app = app

      @log_blk = log_blk || -> _tag, str{self.logger.puts str}
      @msc = Rodsec::Modsec.new{|str| @log_blk.call Rodsec::Modsec, str}

      @logger = logger || StringIO.new

      @log_blk.call self.class, "#{self.class} starting with #{@msc.version_info}"
      read_config config_dir
    end

    def read_config config_dir
      config_dir = Pathname config_dir
      rules_dir = config_dir + 'rules'

      # NOTE the first two config files MUST be loaded before the rules files
      config_rules = Rodsec::RuleSet.new
      config_rules.add_file config_dir + 'modsecurity.conf'
      config_rules.add_file config_dir + 'crs-setup.conf'

      # Now load the rules files
      rules_files = rules_dir.children.select{|p| p.to_s =~ /.*conf$/}.sort

      @rules = rules_files.reduce config_rules do |ax, fn|
        # ruby 2.3.x syntax :-|
        begin
          log_blk.call self.class, "loading rules file: #{fn}"
          rules = Rodsec::RuleSet.new tag: fn
          rules.add_file fn
          ax.merge rules
        rescue
          log_blk.call self.class, "error loading rules file: #{$!}"
          ax
        end
      end
    end

    REMOTE_HOST = 'REMOTE_HOST'.freeze
    REMOTE_ADDR = 'REMOTE_ADDR'.freeze
    SERVER_NAME = 'SERVER_NAME'.freeze
    HTTP_HOST = 'HTTP_HOST'.freeze
    SERVER_PORT = 'SERVER_PORT'.freeze
    HTTP_VERSION = 'HTTP_VERSION'.freeze
    REQUEST_PATH = 'REQUEST_PATH'.freeze
    REQUEST_METHOD = 'REQUEST_METHOD'.freeze
    SLASH = '/'.freeze
    DASH = '-'.freeze
    UNDERSCORE = '_'.freeze
    EMPTY = String.new.freeze

    def call env
      txn = Rodsec::Transaction.new @msc, @rules

      ################
      # incoming
      remote_addr = env[REMOTE_HOST] || env[REMOTE_ADDR]
      server_addr = env[HTTP_HOST] || env[SERVER_NAME]
      txn.connection! remote_addr, 0, server_addr, (env[SERVER_PORT] || 0)

      _, version = env[HTTP_VERSION]&.split(SLASH)
      txn.uri! env[REQUEST_PATH], env[REQUEST_METHOD], version

      http_headers = env.map do |key,val|
        # TODO what about Set-Cookie and things like that?
        key =~ /HTTP_(.*)|(CONTENT_.*)/ or next
        header_name = $1 || $2
        dashified = header_name.split(UNDERSCORE).map(&:capitalize).join(DASH)
        [dashified, val]
      end.compact.to_h
      txn.request_headers! http_headers

      # Have to rewind afterwards, otherwise other layers can't get the content
      rack_input = env['rack.input']
      body = rack_input.read
      rack_input.rewind

      # Looks like this MUST be called (even with an empty body is fine),
      # otherwise ModSecurity never triggers the rules, even though ModSecurity
      # can detect something dodgy in the headers. That needs what they call
      # self-contained mode.
      # TODO what about a DOS from a very large body?
      txn.request_body! body

      ################
      # chain
      status, headers, body = @app.call env

      ################
      # outgoing
      txn.response_headers! status, env[HTTP_VERSION], headers

      # TODO do the append_body calls
      # TODO handle hijacking? Not sure.
      txn.response_body! body.each_with_object(String.new){|l,buf| buf << l}

      # Logging. From ModSecurity's point of view this could be in a separate
      # thread. Dunno how rack will handle that though. Also, there's no way to
      # wait for a thread doing that logging. So it would have to be spawned and
      # then left to die. Alone. In the rain.
      txn.logging

      # all ok
      return status, headers, body

    rescue Rodsec::Intervention => iex
      log_blk.call self.class, iex.msi.log
      # rack interface specification says we have to call close on the body, if
      # it responds to close
      body.respond_to?(:close) && body.close
      # Intervention!
      return iex.msi.status, {'Content-Type' => 'text/plain'}, ["Forbidden\n"]
    end
  end
end
