#!/usr/bin/env rackup

require 'pathname'
require 'yaml'

$: << (Pathname(__dir__).parent + 'lib').realpath.to_s

require 'rack'
require 'rodsec/rack'

rules_dir = (Pathname __dir__).parent.parent + 'owasp-modsecurity-crs/rules'
config_dir = (Pathname __dir__).parent + 'spec/config'

use Rodsec::Rack, config: config_dir, rules: rules_dir, log_blk: -> tag, str { p tag: tag, str: str }

fn = Proc.new do |env|
  case env['REQUEST_METHOD']
  when 'POST'
    body = env['rack.input'].read
    ['200', {'Content-Type' => 'text/plain'}, [body]]

  when 'GET'
    body = YAML.load_file Pathname(__dir__) + 'body.yml'
    ['200', {'Content-Type' => 'text/plain'}, body]
  else
    ['200', {}, []]
  end
end

run fn
