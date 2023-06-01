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

RDoc::Task.new do |rdoc|
  rdoc.main = "README.md"
  rdoc.rdoc_files.include("*.md", "lib/**/*.rb", "ext/**/*.c")
end

task :test => [:compile, :debug]

# Print Ruby and compiler info for debugging purpose.
task :debug_compiler do
  ruby '-v'
  compiler = RbConfig::CONFIG['CC']
  case compiler
  when 'gcc', 'clang'
    sh "#{compiler} --version"
  else
    puts "Compiler: #{RbConfig::CONFIG['CC']}"
  end
end

task :debug do
  ruby "-I./lib -ropenssl -ve'puts OpenSSL::OPENSSL_VERSION, OpenSSL::OPENSSL_LIBRARY_VERSION'"
end

task :default => :test
