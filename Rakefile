require "bundler/gem_tasks"
require 'rake'
require 'rake/extensiontask'
require 'rake/testtask'

Rake::ExtensionTask.new('openssl')

# the same as before
Rake::TestTask.new do |t|
  t.libs << 'test'
end
