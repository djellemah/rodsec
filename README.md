# Rodsec

An ffi wrapper for [ModSecurity](https://www.modsecurity.org/) Web Application
Firewall. It will need a ruleset, most likely you'll want to use
[OWASP ModSecurity Core Rule Set (CRS)](https://coreruleset.org/).

This gem also provides a Rack middleware which can return a 403 Forbidden
response to bad requests, in many cases before your application code runs.

## Installation

Install [ModSecurity >= 3.0.0](https://www.modsecurity.org/download.html). This
gem's native extensions will not compile without it. As of 23-Sep-2018, you may
have to compile ModSecurity yourself, seems that distro packages of 3.0.0
versions are not available.

And now back to your scheduled gem installation dance. Add this line to your
application's Gemfile:

```ruby
gem 'rodsec'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install rodsec


## Usage

### ModSecurity config

Copy `spec/config/modsecurity.conf`, `spec/config/crs-setup.conf`, and
`spec/config/unicode.mapping` into a config directory in your app somewhere.
These are pre-configured to signal an intervention on dodgy requests or
responses - the rack middleware in this gem returns a 403 "Forbidden" in those
cases.

You should be able to use the config files as-is. Possibly decrease the paranoia
level in `crs-setup.conf` from 3 to 1 or 2.

Then you'll need a ruleset - start with the
[OWASP CRS](https://github.com/SpiderLabs/owasp-modsecurity-crs/).

Easiest is a directory structure like this:

```
config/
  modsecurity.conf
  crs-setup.conf
  unicode.mapping
  rules/
    # copy files from OWASP CRS rules/*
    REQUEST-920-PROTOCOL-ENFORCEMENT.conf
    ...
    RESPONSE-980-CORRELATION.conf
    ...
    scanners-headers.data
    ...
```

The location of your ```rules``` directory is configurable if you
really need to - see comments in ```Rodsec::Rack``` source.

Take a look at the ```*.example``` files in ```rules/```.

Copying the rules files is a manual step because you really want to have at
least some idea of what rules you've activated, and how to handle false
positives. Search for ModSecurity and apache or nginx and you'll get lots to
read.

### Rack/Rails

Now you can add a ```use``` line to your rack config. In plain rack this would
be something like

``` ruby
use Rodsec::Rack, config: config_dir, log_blk: -> tag, str { p tag: tag, str: str }
```

See
[official Rails docs](https://guides.rubyonrails.org/rails_on_rack.html#configuring-middleware-stack)
on adding rack middleware to rails.

You'll know it worked when you see "loading rules file" log messages showing up
in your ```log_blk:``` lambda on application startup.

### Standalone

You can also use this gem without rack.

``` ruby
msc = Rodsec::Modsec.new do |tag, str|
  # this block will be called with log strings from ModSecurity
  puts tag, str
end

# load config files
rule_set = Rodsec::ReadConfig.read_config config_dir, rules_dir do |tag, str|
  p tag => str
end

# Now check one, or several, request/response cycles.
# You'll need a new Transaction instance for each cycle.
txn = Rodsec::Transaction.new msc, rule_set, txn_log_tag: 'my_first_transaction'
begin
  # method calls MUST be in this order
  txn.connection! ...
  txn.uri! ...
  txn.request_headers! ...
  txn.request_body! ...
  txn.response_headers! ...
  txn.response_body! ...

  txn.logging
rescue Rodsec::Intervention => iex
  # a good place to do some logging...
  puts iex.msi.to_h # so you can see what fields are available
  puts "http_status: #{iex.msi.status}"
end
```

## Acknowledgements

Thanks to [NETSTOCK](https://www.netstock.co/) for funding development.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run
`rake spec` to run the tests. You can also run `bin/console` for an interactive
prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To
release a new version, update the version number in `version.rb`, and then run
`bundle exec rake release`, which will create a git tag for the version, push
git commits and tags, and push the `.gem` file to
[rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at
https://github.com/djellemah/rodsec.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
