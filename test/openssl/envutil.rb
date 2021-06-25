# -*- coding: us-ascii -*-
require "timeout"
require "rbconfig"
require "pp"

module EnvUtil
  def rubybin
    ENV["RUBY"] || RbConfig.ruby
  end
  module_function :rubybin

  LANG_ENVS = %w"LANG LC_ALL LC_CTYPE"

  def invoke_ruby(args, stdin_data = "", capture_stdout = false, capture_stderr = false,
                  encoding: nil, timeout: 10, reprieve: 1,
                  stdout_filter: nil, stderr_filter: nil,
                  rubybin: EnvUtil.rubybin,
                  **opt)
    in_c, in_p = IO.pipe
    out_p, out_c = IO.pipe if capture_stdout
    err_p, err_c = IO.pipe if capture_stderr && capture_stderr != :merge_to_stdout
    opt[:in] = in_c
    opt[:out] = out_c if capture_stdout
    opt[:err] = capture_stderr == :merge_to_stdout ? out_c : err_c if capture_stderr
    if encoding
      out_p.set_encoding(encoding) if out_p
      err_p.set_encoding(encoding) if err_p
    end
    c = "C"
    child_env = {}
    LANG_ENVS.each {|lc| child_env[lc] = c}
    if Array === args and Hash === args.first
      child_env.update(args.shift)
    end
    args = [args] if args.kind_of?(String)
    pid = spawn(child_env, rubybin, *args, **opt)
    in_c.close
    out_c.close if capture_stdout
    err_c.close if capture_stderr && capture_stderr != :merge_to_stdout
    if block_given?
      return yield in_p, out_p, err_p, pid
    else
      th_stdout = Thread.new { out_p.read } if capture_stdout
      th_stderr = Thread.new { err_p.read } if capture_stderr && capture_stderr != :merge_to_stdout
      in_p.write stdin_data.to_str unless stdin_data.empty?
      in_p.close
      if (!th_stdout || th_stdout.join(timeout)) && (!th_stderr || th_stderr.join(timeout))
        stdout = th_stdout.value if capture_stdout
        stderr = th_stderr.value if capture_stderr && capture_stderr != :merge_to_stdout
      else
        signal = /mswin|mingw/ =~ RUBY_PLATFORM ? :KILL : :TERM
        case pgroup = opt[:pgroup]
        when 0, true
          pgroup = -pid
        when nil, false
          pgroup = pid
        end
        begin
          Process.kill signal, pgroup
          Timeout.timeout((reprieve unless signal == :KILL)) do
            Process.wait(pid)
          end
        rescue Errno::ESRCH
          break
        rescue Timeout::Error
          raise if signal == :KILL
          signal = :KILL
        else
          break
        end while true
        bt = caller_locations
        raise Timeout::Error, "execution of #{bt.shift.label} expired", bt.map(&:to_s)
      end
      out_p.close if capture_stdout
      err_p.close if capture_stderr && capture_stderr != :merge_to_stdout
      Process.wait pid
      status = $?
      stdout = stdout_filter.call(stdout) if stdout_filter
      stderr = stderr_filter.call(stderr) if stderr_filter
      return stdout, stderr, status
    end
  ensure
    [th_stdout, th_stderr].each do |th|
      th.kill if th
    end
    [in_c, in_p, out_c, out_p, err_c, err_p].each do |io|
      io.close if io && !io.closed?
    end
    [th_stdout, th_stderr].each do |th|
      th.join if th
    end
  end
  module_function :invoke_ruby

  def verbose_warning
    class << (stderr = "".dup)
      alias write <<
    end
    stderr, $stderr, verbose, $VERBOSE = $stderr, stderr, $VERBOSE, true
    yield stderr
    return $stderr
  ensure
    stderr, $stderr, $VERBOSE = $stderr, stderr, verbose
  end
  module_function :verbose_warning

  def suppress_warning
    verbose, $VERBOSE = $VERBOSE, nil
    yield
  ensure
    $VERBOSE = verbose
  end
  module_function :suppress_warning

  if /darwin/ =~ RUBY_PLATFORM
    DIAGNOSTIC_REPORTS_PATH = File.expand_path("~/Library/Logs/DiagnosticReports")
    DIAGNOSTIC_REPORTS_TIMEFORMAT = '%Y-%m-%d-%H%M%S'
    def self.diagnostic_reports(signame, cmd, pid, now)
      return unless %w[ABRT QUIT SEGV ILL].include?(signame)
      cmd = File.basename(cmd)
      path = DIAGNOSTIC_REPORTS_PATH
      timeformat = DIAGNOSTIC_REPORTS_TIMEFORMAT
      pat = "#{path}/#{cmd}_#{now.strftime(timeformat)}[-_]*.crash"
      first = true
      30.times do
        first ? (first = false) : sleep(0.1)
        Dir.glob(pat) do |name|
          log = File.read(name) rescue next
          if /\AProcess:\s+#{cmd} \[#{pid}\]$/ =~ log
            File.unlink(name)
            File.unlink("#{path}/.#{File.basename(name)}.plist") rescue nil
            return log
          end
        end
      end
      nil
    end
  else
    def self.diagnostic_reports(signame, cmd, pid, now)
    end
  end
end

module Test
  module Unit
    module Assertions
      FailDesc = proc do |status, message = "", out = ""|
        pid = status.pid
        now = Time.now
        faildesc = proc do
          if signo = status.termsig
            signame = Signal.signame(signo)
            sigdesc = "signal #{signo}"
          end
          log = EnvUtil.diagnostic_reports(signame, EnvUtil.rubybin, pid, now)
          if signame
            sigdesc = "SIG#{signame} (#{sigdesc})"
          end
          if status.coredump?
            sigdesc << " (core dumped)"
          end
          full_message = ''
          if message and !message.empty?
            full_message << message << "\n"
          end
          full_message << "pid #{pid} killed by #{sigdesc}"
          if out and !out.empty?
            full_message << "\n#{out.gsub(/^/, '| ')}"
            full_message << "\n" if /\n\z/ !~ full_message
          end
          if log
            full_message << "\n#{log.gsub(/^/, '| ')}"
          end
          full_message
        end
        faildesc
      end

      ABORT_SIGNALS = Signal.list.values_at(*%w"ILL ABRT BUS SEGV")

      def assert_separately(args, file = nil, line = nil, src, ignore_stderr: nil, **opt)
        unless file and line
          loc, = caller_locations(1,1)
          file ||= loc.path
          line ||= loc.lineno
        end
        line -= 6 # lines until src
        src = <<eom
# -*- coding: #{src.encoding}; -*-
  require 'test/unit';include Test::Unit::Assertions
  END {
    puts [Marshal.dump($!)].pack('m')#, "assertions=\#{self._assertions}"
    exit
  }
  def pend(msg = nil) $stdout.syswrite [Marshal.dump(msg.to_s)].pack("m"); exit! 0 end
#{src}
  class Test::Unit::Runner
    @@stop_auto_run = true
  end
eom
        args = args.dup
        args.insert((Hash === args.first ? 1 : 0), "--disable=gems", *$:.map {|l| "-I#{l}"})
        stdout, stderr, status = EnvUtil.invoke_ruby(args, src, true, true, **opt)
        abort = status.coredump? || (status.signaled? && ABORT_SIGNALS.include?(status.termsig))
        assert(!abort, FailDesc[status, nil, stderr])
        #self._assertions += stdout[/^assertions=(\d+)/, 1].to_i
        begin
          res = Marshal.load(stdout.unpack("m")[0])
        rescue => marshal_error
          ignore_stderr = nil
        end
        if res.is_a?(String)
          pend res
        elsif res
          if bt = res.backtrace
            bt.each do |l|
              l.sub!(/\A-:(\d+)/){"#{file}:#{line + $1.to_i}"}
            end
            bt.concat(caller)
          else
            res.set_backtrace(caller)
          end
          raise res
        end

        # really is it succeed?
        unless ignore_stderr
          # the body of assert_separately must not output anything to detect error
          assert_equal("", stderr, "assert_separately failed with error message")
        end
        assert_equal(0, status, "assert_separately failed: '#{stderr}'")
        raise marshal_error if marshal_error
      end

      def assert_warning(pat, msg = nil)
        stderr = EnvUtil.verbose_warning {
          yield
        }
        if Regexp === pat
          assert_match pat, stderr, msg
        else
          assert_equal pat, stderr, msg
        end
      end

      def message msg = nil, ending = ".", &default
        proc {
          msg = msg.call.chomp(".") if Proc === msg
          custom_message = "#{msg}.\n" unless msg.nil? or msg.to_s.empty?
          "#{custom_message}#{default.call}#{ending}"
        }
      end

      # threads should respond to shift method.
      # Array can be used.
      def assert_join_threads(threads, message = nil)
        errs = []
        values = []
        while th = threads.shift
          begin
            values << th.value
          rescue Exception
            errs << [th, $!]
          end
        end
        if !errs.empty?
          msg = "exceptions on #{errs.length} threads:\n" +
            errs.map {|t, err|
            "#{t.inspect}:\n" +
            err.backtrace.map.with_index {|line, i|
              if i == 0
                "#{line}: #{err.message} (#{err.class})"
              else
                "\tfrom #{line}"
              end
            }.join("\n")
          }.join("\n---\n")
          if message
            msg = "#{message}\n#{msg}"
          end
          raise Test::Unit::AssertionFailedError, msg
        end
        values
      end
    end
  end
end
