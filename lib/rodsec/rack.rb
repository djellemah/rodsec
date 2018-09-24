require_relative '../rodsec.rb'

module Rodsec
  # Thanks to rack-contrib/deflect for the basic idea, and some of the docs.
  class Rack
    # === Required Options:
    #
    #   :config   Proc, or the directory containing the ModSecurity config files
    #             modsecurity.conf and crs-setup.conf. If it's a Proc, which
    #             must return a Rodsec::Ruleset instance containing all the
    #             rules you want.
    #
    # === Optional Options:
    #
    #   :rules    the directory containing the ModSecurity rules files.
    #             Defaults to ${config}/rules. Ignored if you pass a proc to config
    #
    #   :logger   must respond_to #puts which takes a string. Defaults to a StringIO at #logger
    #
    #   :log_blk  a callable that takes |tag,string| Defaults to sending
    #             only the string to logger. The ModSecurity logs are highly
    #             structured and you might want to parse them, so the tag
    #             helps disambiguate the source of the logs.
    #
    #   ? :msi_blk  called with [status, headers, body] if there's an intervention from ModSecurity.
    #
    #
    # === Examples:
    #
    #  use Rodsec::Rack, config: 'your_config_path', log: (mylogger = StringIO.new)
    #  use Rodsec::Rack, config: 'your_config_path', log_blk: -> src_class, str { my_funky_parse_msi_to_hash str }
    def initialize app, config:, rules: nil, logger: nil, log_blk: nil
      @app = app

      @log_blk = log_blk || -> _tag, str{self.logger.puts str}
      @msc = Rodsec::Modsec.new{|tag,str| @log_blk.call tag, str}

      @logger = logger || StringIO.new

      @log_blk.call self.class, "#{self.class} starting with #{@msc.version_info}"

      set_rules config, rules
    end

    attr_reader :log_blk, :logger

    include ReadConfig

    protected def set_rules config, rules
      case config
      when Proc
        @rules = config.call
      else
        @rules = read_config config, rules, &log_blk
      end
    end

    REQUEST_URI = 'REQUEST_URI'.freeze
    REMOTE_HOST = 'REMOTE_HOST'.freeze
    REMOTE_ADDR = 'REMOTE_ADDR'.freeze
    SERVER_NAME = 'SERVER_NAME'.freeze
    HTTP_HOST = 'HTTP_HOST'.freeze
    SERVER_PORT = 'SERVER_PORT'.freeze
    HTTP_VERSION = 'HTTP_VERSION'.freeze
    REQUEST_METHOD = 'REQUEST_METHOD'.freeze
    SLASH = '/'.freeze
    HTTP_HEADER_RX = /HTTP_(.*)|(CONTENT_.*)/.freeze
    DASH = '-'.freeze
    UNDERSCORE = '_'.freeze
    EMPTY = String.new.freeze

    RACK_INPUT = 'rack.input'.freeze

    def call env
      txn = Rodsec::Transaction.new @msc, @rules, txn_log_tag: env[REQUEST_URI]

      ################
      # incoming

      # uri! scope for variables
      lambda do
        remote_addr = env[REMOTE_HOST] || env[REMOTE_ADDR]
        server_addr = env[HTTP_HOST] || env[SERVER_NAME]
        txn.connection! remote_addr, 0, server_addr, (env[SERVER_PORT] || 0)

        _, version = env[HTTP_VERSION]&.split(SLASH)

        txn.uri! env[REQUEST_URI], env[REQUEST_METHOD], version
      end.call

      # request_headers! - another scope for variables
      lambda do
        http_headers = env.map do |key,val|
          key =~ HTTP_HEADER_RX or next
          header_name = $1 || $2
          dashified = header_name.split(UNDERSCORE).map(&:capitalize).join(DASH)
          [dashified, val]
        end.compact.to_h

        txn.request_headers! http_headers
      end.call

      # request_body! MUST be called (even with an empty body is fine),
      # otherwise ModSecurity never triggers the rules, even though ModSecurity
      # can detect something dodgy in the headers. That needs what they call
      # self-contained mode.
      env[RACK_INPUT].tap do |rack_input|
        # ruby-2.3 syntax :-|
        begin
          # What about a DOS from a very large body?
          #
          # Rack spec says rack.input must be rewindable at the http-server
          # level, so it's all in memory by now anyway, nothing we can do to
          # affect that here.
          txn.request_body! rack_input
        ensure
          # Have to rewind input, otherwise other rack apps can't get the content
          rack_input.rewind
        end
      end

      ################
      # rack chain
      status, headers, body = @app.call env

      ################
      # outgoing
      txn.response_headers! status, env[HTTP_VERSION], headers

      # TODO handle hijacking? Not sure.
      # body is an Enumerable, which response_body! will handle
      txn.response_body! body

      # Logging. From ModSecurity's point of view this could be in a separate
      # thread. Dunno how rack will handle that though. Also, there's no way to
      # wait for a thread doing that logging. So it would have to be spawned and
      # then left to die. Alone. In the rain.
      txn.logging

      # all ok
      return status, headers, body

    rescue Rodsec::Intervention => iex
      log_blk.call :intervention, iex.msi.log
      # rack interface specification says we have to call close on the body, if
      # it responds to close
      body.respond_to?(:close) && body.close
      # Intervention!
      return iex.msi.status, {'Content-Type' => 'text/plain'}, [ ::Rack::Utils::HTTP_STATUS_CODES[iex.msi.status] ].compact
    end
  end
end
