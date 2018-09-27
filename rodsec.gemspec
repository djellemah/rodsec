# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rodsec/version'

Gem::Specification.new do |spec|
  spec.name          = 'rodsec'
  spec.version       = Rodsec::VERSION
  spec.authors       = ['John Anderson']
  spec.email         = ['panic@semiosix.com']

  spec.summary       = %q{Wrapper for ModSecurity with Rack middleware}
  spec.description   = %q{A ruby ffi wrapper for ModSecurity that also provides a Rack middleware}
  spec.homepage      = 'http://github.com/djellemah/rodsec'
  spec.license       = 'MIT'

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata['allowed_push_host'] = "https://rubygems.org"
  else
    raise 'RubyGems 2.0 or newer is required to protect against public gem pushes.'
  end

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec(?!/config)|features|modsec_lib)/})
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.extensions << %q[ext/msc_intervention/extconf.rb]

  spec.add_dependency 'rack', '>= 1.4.7'
  spec.add_development_dependency 'bundler', '~> 1.15'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'pry'
  spec.add_development_dependency 'rake-compiler', '>= 1.0.5'
end
