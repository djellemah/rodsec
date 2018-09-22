require "bundler/gem_tasks"
require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec)

# from rake-compiler gem https://github.com/rake-compiler/rake-compiler
require 'rake/extensiontask'
gs = Gem::Specification.load 'rodsec.gemspec'
Rake::ExtensionTask.new 'msc_intervention', gs do |ext|
  ext.lib_dir = 'lib/rodsec'
end

task :spec => :compile
task :default => :spec
task :build => :compile
