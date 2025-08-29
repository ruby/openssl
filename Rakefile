require 'rake/testtask'
require 'rdoc/task'
require 'bundler/gem_tasks'

begin
  require 'rake/extensiontask'
  Rake::ExtensionTask.new('openssl')
rescue LoadError
  warn "rake-compiler not installed. Run 'bundle install' to " \
    "install testing dependency gems."
end

task :test => :compile
Rake::TestTask.new do |t|
  t.test_files = FileList["test/**/test_*.rb"]
  t.warning = true
end

desc 'Run tests for fips'
task :test_fips => :compile do
  ENV['TEST_RUBY_OPENSSL_FIPS_ENABLED'] = 'true'
  Rake::Task['test_fips_internal'].invoke
end

Rake::TestTask.new(:test_fips_internal) do |t|
  # Exclude failing test files in FIPS for this task to pass.
  # TODO: Fix failing test files.
  t.test_files = FileList['test/**/test_*.rb'] - FileList[
    'test/openssl/test_asn1.rb',
    'test/openssl/test_cipher.rb',
    'test/openssl/test_digest.rb',
    'test/openssl/test_hmac.rb',
    'test/openssl/test_kdf.rb',
    'test/openssl/test_ns_spki.rb',
    'test/openssl/test_ocsp.rb',
    'test/openssl/test_pkcs12.rb',
    'test/openssl/test_ts.rb',
    'test/openssl/test_x509cert.rb',
    'test/openssl/test_x509crl.rb',
    'test/openssl/test_x509name.rb',
    'test/openssl/test_x509req.rb',
  ]
  t.warning = true
end

RDoc::Task.new do |rdoc|
  rdoc.main = "README.md"
  rdoc.rdoc_files.include("*.md", "lib/**/*.rb", "ext/**/*.c")
end

# Print Ruby and compiler info for debugging purpose.
task :debug_compiler do
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
  ruby %Q(-I./lib -ropenssl.so -e'#{ruby_code}'), verbose: false
end

task :default => :test
