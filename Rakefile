require 'rake/testtask'
require 'rdoc/task'
require 'bundler/gem_tasks'

begin
  require 'rake/extensiontask'
  Rake::ExtensionTask.new('openssl')
  # Run the debug_compiler task before the compile task.
  Rake::Task['compile'].prerequisites.unshift :debug_compiler
rescue LoadError
  warn "rake-compiler not installed. Run 'bundle install' to " \
    "install testing dependency gems."
end

Rake::TestTask.new do |t|
  t.libs << 'test/openssl'
  t.test_files = FileList["test/**/test_*.rb"]
  t.warning = true
end

desc 'Run tests for fips'
task :test_fips do
  ENV['TEST_RUBY_OPENSSL_FIPS_ENABLED'] = 'true'
  Rake::Task['test_fips_internal'].invoke
end

Rake::TestTask.new(:test_fips_internal) do |t|
  t.libs << 'test/openssl'
  t.test_files = FileList[
    'test/openssl/test_fips.rb',
    'test/openssl/test_pkey.rb',
    'test/openssl/test_pkey_ec.rb',
  ]
  t.warning = true
end

RDoc::Task.new do |rdoc|
  rdoc.main = "README.md"
  rdoc.rdoc_files.include("*.md", "lib/**/*.rb", "ext/**/*.c")
end

task :test => [:compile, :debug]
task :test_fips => [:compile, :debug]

# Print Ruby and compiler info for debugging purpose.
task :debug_compiler do
  ruby '-v'
  compiler = RbConfig::CONFIG['CC']
  case compiler
  when 'gcc', 'clang'
    sh "#{compiler} --version"
  else
    Rake.rake_output_message "Compiler: #{RbConfig::CONFIG['CC']}"
  end
end

task :debug do
  ruby_code = <<~'EOF'
    openssl_version_number_str = OpenSSL::OPENSSL_VERSION_NUMBER.to_s(16)
    libressl_version_number_str = (defined? OpenSSL::LIBRESSL_VERSION_NUMBER) ?
      OpenSSL::LIBRESSL_VERSION_NUMBER.to_s(16) : "undefined"
    providers_str = (defined? OpenSSL::Provider) ?
      OpenSSL::Provider.provider_names.join(", ") : "undefined"
    puts <<~MESSAGE
      OpenSSL::OPENSSL_VERSION: #{OpenSSL::OPENSSL_VERSION}
      OpenSSL::OPENSSL_LIBRARY_VERSION: #{OpenSSL::OPENSSL_LIBRARY_VERSION}
      OpenSSL::OPENSSL_VERSION_NUMBER: #{openssl_version_number_str}
      OpenSSL::LIBRESSL_VERSION_NUMBER: #{libressl_version_number_str}
      FIPS enabled: #{OpenSSL.fips_mode}
      Providers: #{providers_str}
    MESSAGE
  EOF
  ruby %Q(-I./lib -ropenssl -ve'#{ruby_code}')
end

task :default => :test
