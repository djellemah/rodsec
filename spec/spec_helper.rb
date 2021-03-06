require "bundler/setup"
require "rodsec"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  # config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = %i[should]
  end
end

# rspec, shutup already about 'deprecated old syntax'. I've already enabled it.
if RSpec::Mocks::Syntax.instance_variable_defined? :@warn_about_should
  RSpec::Mocks::Syntax.instance_variable_set :@warn_about_should, false
end
