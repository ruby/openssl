gem 'rake-compiler', '~> 0.9'

require 'rake'
require 'rake/extensiontask'
require 'rake/testtask'

Rake::ExtensionTask.new('openssl')

# the same as before
Rake::TestTask.new do |t|
  t.libs << 'test'
  t.warning = true
end
