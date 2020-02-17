require 'rake'
require 'rake/testtask'
require 'rdoc/task'

begin
  require 'rake/extensiontask'
  Rake::ExtensionTask.new('openssl')
rescue LoadError
  warn "rake-compiler not installed. Run 'rake install_dependencies' to " \
    "install testing dependency gems."
end

Rake::TestTask.new do |t|
  t.libs << 'test/openssl'
  t.test_files = FileList["test/**/test_*.rb"]
  t.warning = true
end

RDoc::Task.new do |rdoc|
  rdoc.main = "README.md"
  rdoc.rdoc_files.include("*.md", "lib/**/*.rb", "ext/**/*.c")
end

task :test => [:compile, :debug]
task :debug do
  ruby "-I./lib -ropenssl -ve'puts OpenSSL::OPENSSL_VERSION, OpenSSL::OPENSSL_LIBRARY_VERSION'"
end

task :install_dependencies do
  if ENV["USE_HTTP_RUBYGEMS_ORG"] == "1"
    Gem.sources.replace([Gem::Source.new("http://rubygems.org")])
  end

  Gem.configuration.verbose = false
  gemspec = Gem::Specification.load('openssl.gemspec')

  gemspec.development_dependencies.each do |dep|
    print "Installing #{dep.name} (#{dep.requirement}) ... "
    installed = dep.matching_specs
    if installed.empty?
      installed = Gem.install(dep.name, dep.requirement)
      puts "#{installed[0].version}"
    else
      puts "(found #{installed[0].version})"
    end
  end
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
      ["lib/", "ext/openssl/lib/"],
      ["sample/", "sample/openssl/"],
      ["test/fixtures/", "test/openssl/fixtures/"],
      ["test/utils.rb", "test/openssl/"],
      ["test/ut_eof.rb", "test/openssl/"],
      ["test/test_*", "test/openssl/"],
      ["History.md", "ext/openssl/"],
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

task :default => :test
