gem 'rake-compiler'

require 'rake'
require 'rake/extensiontask'
require 'rake/testtask'
require 'rdoc/task'

Rake::ExtensionTask.new('openssl')

Rake::TestTask.new do |t|
  t.libs << 'test'
  t.warning = true
end

Rake::ExtensionTask.new('test/mdebug') do |ext|
  # hack to emit mdebug.so under ./test/
  ext.ext_dir = 'test/mdebug'
  ext.lib_dir = '.'
end

RDoc::Task.new do |rdoc|
  rdoc.main = "README.md"
  rdoc.rdoc_files.include("*.md", "lib/**/*.rb", "ext/**/*.c")
end

task :test => :debug
task :debug do
  ruby "-I./lib -ropenssl -ve'puts OpenSSL::OPENSSL_VERSION, OpenSSL::OPENSSL_LIBRARY_VERSION'"
end

namespace :sync do
  task :from_ruby do
    sh "./tool/sync-with-trunk"
  end

  task :to_ruby do
    trunk_path = ENV.fetch("RUBY_TRUNK_PATH", "../ruby")

    rsync = "rsync -av --delete"
    excludes = %w{Makefile extconf.h mkmf.log depend *.o *.so *.bundle}
    excludes.each { |name| rsync << " --exclude #{name}" }

    paths = [
      ["ext/openssl/", "ext/openssl/"],
      ["test/utils.rb", "test/openssl/"],
      ["test/ut_eof.rb", "test/openssl/"],
      ["test/test_*", "test/openssl/"],
      ["lib/", "ext/openssl/lib/"],
      ["sample/", "sample/openssl/"],
    ]
    paths.each do |src, dst|
      sh "#{rsync} #{src} #{trunk_path}/#{dst}"
    end

    gemspec_file = File.expand_path("../openssl.gemspec", __FILE__)
    gemspec = eval(File.read(gemspec_file), binding, gemspec_file)
    File.write("#{trunk_path}/ext/openssl/openssl.gemspec", gemspec.to_ruby)

    puts "Don't forget to update ext/openssl/depend"
  end
end
