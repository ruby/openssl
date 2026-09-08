# coding: binary
# frozen_string_literal: true
#--
#= Info
#  'OpenSSL for Ruby 2' project
#  Copyright (C) 2001 GOTOU YUUZOU <gotoyuzo@notwork.org>
#  All rights reserved.
#
#= Licence
#  This program is licensed under the same licence as Ruby.
#  (See the file 'COPYING'.)
#++

##
# OpenSSL IO buffering mix-in module.
#
# This module allows an OpenSSL::SSL::SSLSocket to behave like an IO.
#
# You typically won't use this module directly, you can see it implemented in
# OpenSSL::SSL::SSLSocket.

module OpenSSL::Buffering
  include Enumerable

  class Buffer < String # :nodoc:
    unless String.method_defined?(:append_as_bytes)
      alias_method :_append, :<<
      def append_as_bytes(string)
        if string.encoding == Encoding::BINARY
          _append(string)
        else
          _append(string.b)
        end

        self
      end
    end

    undef_method :concat
    undef_method :<<
  end

  ##
  # The "sync mode" of the SSLSocket.
  #
  # See IO#sync for full details.

  attr_accessor :sync

  ##
  # Default size to read from or write to the SSLSocket for buffer operations.

  BLOCK_SIZE = 1024*16

  ##
  # Creates an instance of OpenSSL's buffering IO module.

  def initialize(*)
    super
    @eof = false
    @rbuffer = Buffer.new
    @sync = @io.sync
  end

  #
  # for reading.
  #
  private

  ##
  # Fills the buffer from the underlying SSLSocket

  def fill_rbuff
    begin
      @rbuffer.append_as_bytes(self.sysread(BLOCK_SIZE))
    rescue Errno::EAGAIN
      retry
    rescue EOFError
      @eof = true
    end
  end

  ##
  # Consumes _size_ bytes from the buffer

  def consume_rbuff(size=nil)
    if @rbuffer.empty?
      nil
    else
      size = @rbuffer.size unless size
      @rbuffer.slice!(0, size)
    end
  end

  public

  # call-seq:
  #   ssl.getbyte => 81
  #
  # Get the next 8bit byte from `ssl`.  Returns `nil` on EOF
  def getbyte
    read(1)&.ord
  end

  # Get the next 8bit byte. Raises EOFError on EOF
  def readbyte
    raise EOFError if eof?
    getbyte
  end

  ##
  # Reads _size_ bytes from the stream.  If _buf_ is provided it must
  # reference a string which will receive the data.
  #
  # See IO#read for full details.

  def read(size=nil, buf=nil)
    if size == 0
      if buf
        buf.clear
        return buf
      else
        return ""
      end
    end
    until @eof
      break if size && size <= @rbuffer.size
      fill_rbuff
    end
    ret = consume_rbuff(size) || ""
    if buf
      buf.replace(ret)
      ret = buf
    end
    (size && ret.empty?) ? nil : ret
  end

  ##
  # Reads at most _maxlen_ bytes from the stream.  If _buf_ is provided it
  # must reference a string which will receive the data.
  #
  # See IO#readpartial for full details.

  def readpartial(maxlen, buf=nil)
    if maxlen == 0
      if buf
        buf.clear
        return buf
      else
        return ""
      end
    end
    if @rbuffer.empty?
      begin
        return sysread(maxlen, buf)
      rescue Errno::EAGAIN
        retry
      end
    end
    ret = consume_rbuff(maxlen)
    if buf
      buf.replace(ret)
      ret = buf
    end
    ret
  end

  ##
  # Reads at most _maxlen_ bytes in the non-blocking manner.
  #
  # When no data can be read without blocking it raises
  # OpenSSL::SSL::SSLError extended by IO::WaitReadable or IO::WaitWritable.
  #
  # IO::WaitReadable means SSL needs to read internally so read_nonblock
  # should be called again when the underlying IO is readable.
  #
  # IO::WaitWritable means SSL needs to write internally so read_nonblock
  # should be called again after the underlying IO is writable.
  #
  # OpenSSL::Buffering#read_nonblock needs two rescue clause as follows:
  #
  #   # emulates blocking read (readpartial).
  #   begin
  #     result = ssl.read_nonblock(maxlen)
  #   rescue IO::WaitReadable
  #     IO.select([io])
  #     retry
  #   rescue IO::WaitWritable
  #     IO.select(nil, [io])
  #     retry
  #   end
  #
  # Note that one reason that read_nonblock writes to the underlying IO is
  # when the peer requests a new TLS/SSL handshake.  See openssl the FAQ for
  # more details.  http://www.openssl.org/support/faq.html
  #
  # By specifying a keyword argument _exception_ to +false+, you can indicate
  # that read_nonblock should not raise an IO::Wait*able exception, but
  # return the symbol +:wait_writable+ or +:wait_readable+ instead. At EOF,
  # it will return +nil+ instead of raising EOFError.

  def read_nonblock(maxlen, buf=nil, exception: true)
    if maxlen == 0
      if buf
        buf.clear
        return buf
      else
        return ""
      end
    end
    if @rbuffer.empty?
      return sysread_nonblock(maxlen, buf, exception: exception)
    end
    ret = consume_rbuff(maxlen)
    if buf
      buf.replace(ret)
      ret = buf
    end
    ret
  end

  ##
  # Reads the next "line" from the stream.  Lines are separated by _eol_.  If
  # _limit_ is provided the result will not be longer than the given number of
  # bytes.
  #
  # _eol_ may be a String or Regexp. _eol_ defaults to +$/+.
  #
  # Note that Regexp _eol_ is an extension to the standard IO#gets. This mode
  # is incompatible with _chomp_ option.
  #
  # Unlike IO#gets, the line read will not be assigned to +$_+.

  def gets(eol = $/, limit = nil, chomp: false)
    if limit.nil? && Integer === eol
      eol, limit = $/, eol
    end
    limit = nil if limit && limit < 0
    return String.new if limit == 0

    case eol
    when nil
      gets_slurp(limit)
    when Regexp
      gets_regexp(eol, limit)
    when ""
      swallow_newlines
      ret = gets_string("\n\n", limit, chomp)
      swallow_newlines
      ret
    else
      gets_string(eol, limit, chomp)
    end
  end

  private def gets_string(eol, limit, chomp)
    pos = 0
    while true
      break if idx = @rbuffer.index(eol, pos)
      break if limit && @rbuffer.bytesize >= limit
      pos = [0, @rbuffer.bytesize - eol.bytesize + 1].max
      break if @eof
      fill_rbuff
    end
    if idx
      size = idx + eol.bytesize
      size = [size, limit].min if limit
    else
      size = limit
    end
    line = consume_rbuff(size)
    if chomp && idx
      line.chomp!(eol)
    end
    line
  end

  private def gets_regexp(eol, limit)
    while true
      break if idx = @rbuffer.index(eol)
      break if limit && @rbuffer.bytesize >= limit
      break if @eof
      fill_rbuff
    end
    if idx
      size = idx + $&.size
      size = [size, limit].min if limit
    else
      size = limit
    end
    consume_rbuff(size)
  end

  private def gets_slurp(limit)
    ret = read(limit)
    return nil if ret && ret.empty?
    ret
  end

  private def swallow_newlines
    while true
      @rbuffer.sub!(/\A\n+/, "")
      break if @eof || !@rbuffer.empty?
      fill_rbuff
    end
  end

  ##
  # Executes the block for every line in the stream where lines are separated
  # by _eol_.
  #
  # See also #gets

  def each(eol = $/, limit = nil, chomp: false)
    return to_enum(__method__, eol, limit, chomp: chomp) unless block_given?
    while line = gets(eol, limit, chomp: chomp)
      yield line
    end
    self
  end
  alias each_line each

  ##
  # Reads lines from the stream which are separated by _eol_.
  #
  # See also #gets

  def readlines(eol = $/, limit = nil, chomp: false)
    ary = []
    while line = gets(eol, limit, chomp: chomp)
      ary << line
    end
    ary
  end

  ##
  # Reads a line from the stream which is separated by _eol_.
  #
  # Raises EOFError if at end of file.

  def readline(eol = $/, limit = nil, chomp: false)
    gets(eol, limit, chomp: chomp) or raise EOFError
  end

  ##
  # Reads one character from the stream.  Returns nil if called at end of
  # file.

  def getc
    read(1)
  end

  ##
  # Calls the given block once for each character in the stream.

  def each_char
    return to_enum(__method__) unless block_given?
    while c = getc
      yield c
    end
    self
  end

  ##
  # Calls the given block once for each byte in the stream.

  def each_byte # :yields: byte
    return to_enum(__method__) unless block_given?
    while c = getbyte
      yield c
    end
    self
  end

  ##
  # Reads a one-character string from the stream.  Raises an EOFError at end
  # of file.

  def readchar
    raise EOFError if eof?
    getc
  end

  ##
  # Pushes character _c_ back onto the stream such that a subsequent buffered
  # character read will return it.
  #
  # Unlike IO#getc multiple bytes may be pushed back onto the stream.
  #
  # Has no effect on unbuffered reads (such as #sysread).

  def ungetc(c)
    @rbuffer[0, 0] = Integer === c ? c.chr : c
    @rbuffer.force_encoding(Encoding::BINARY)
    nil
  end

  ##
  # Pushes byte _c_ back onto the stream such that a subsequent buffered byte
  # read will return it.
  def ungetbyte(c)
    @rbuffer[0, 0] = Integer === c ? (c & 0xff).chr : c
    @rbuffer.force_encoding(Encoding::BINARY)
    nil
  end

  ##
  # Returns true if the stream is at file which means there is no more data to
  # be read.

  def eof?
    fill_rbuff if !@eof && @rbuffer.empty?
    @eof && @rbuffer.empty?
  end
  alias eof eof?

  #
  # for writing.
  #
  private

  ##
  # Writes _s_ to the buffer.  When the buffer is full or #sync is true the
  # buffer is flushed to the underlying socket.

  def do_write(s)
    @wbuffer = Buffer.new unless defined? @wbuffer
    @wbuffer.append_as_bytes(s)

    @sync ||= false
    buffer_size = @wbuffer.bytesize
    if @sync or buffer_size > BLOCK_SIZE
      nwrote = 0
      begin
        while nwrote < buffer_size do
          begin
            chunk = if nwrote > 0
              @wbuffer.byteslice(nwrote, @wbuffer.bytesize)
            else
              @wbuffer
            end

            nwrote += syswrite(chunk)
          rescue Errno::EAGAIN
            retry
          end
        end
      ensure
        if nwrote < @wbuffer.bytesize
          @wbuffer[0, nwrote] = ""
        else
          @wbuffer.clear
        end
      end
    end
  end

  public

  ##
  # Writes _s_ to the stream.  If the argument is not a String it will be
  # converted using +.to_s+ method.  Returns the number of bytes written.

  def write(*s)
    s.inject(0) do |written, str|
      str = str.to_s
      do_write(str)
      written + str.bytesize
    end
  end

  ##
  # Writes _s_ in the non-blocking manner.
  #
  # If there is buffered data, it is flushed first.  This may block.
  #
  # write_nonblock returns number of bytes written to the SSL connection.
  #
  # When no data can be written without blocking it raises
  # OpenSSL::SSL::SSLError extended by IO::WaitReadable or IO::WaitWritable.
  #
  # IO::WaitReadable means SSL needs to read internally so write_nonblock
  # should be called again after the underlying IO is readable.
  #
  # IO::WaitWritable means SSL needs to write internally so write_nonblock
  # should be called again after underlying IO is writable.
  #
  # So OpenSSL::Buffering#write_nonblock needs two rescue clause as follows.
  #
  #   # emulates blocking write.
  #   begin
  #     result = ssl.write_nonblock(str)
  #   rescue IO::WaitReadable
  #     IO.select([io])
  #     retry
  #   rescue IO::WaitWritable
  #     IO.select(nil, [io])
  #     retry
  #   end
  #
  # Note that one reason that write_nonblock reads from the underlying IO
  # is when the peer requests a new TLS/SSL handshake.  See the openssl FAQ
  # for more details.  http://www.openssl.org/support/faq.html
  #
  # By specifying a keyword argument _exception_ to +false+, you can indicate
  # that write_nonblock should not raise an IO::Wait*able exception, but
  # return the symbol +:wait_writable+ or +:wait_readable+ instead.

  def write_nonblock(s, exception: true)
    flush
    syswrite_nonblock(s, exception: exception)
  end

  ##
  # Writes _s_ to the stream.  _s_ will be converted to a String using
  # +.to_s+ method.

  def <<(s)
    do_write(s.to_s)
    self
  end

  ##
  # Writes _args_ to the stream along with a newline.
  #
  # See IO#puts for full details.

  def puts(*args)
    if args.empty?
      do_write("\n")
      return nil
    end
    s = Buffer.new
    args.each{|arg|
      if String === arg || !arg.respond_to?(:to_ary)
        b = arg.to_s
        s.append_as_bytes(b)
        s.append_as_bytes("\n") unless b.byteslice(-1) == "\n"
      else
        ary = arg.to_ary
        # IO#puts writes "[...]" when it encounters a recursion (undocumented).
        # We ignore that for now. Array#flatten may raise ArgumentError.
        ary.flatten.each do |e|
          b = e.to_s
          s.append_as_bytes(b)
          s.append_as_bytes("\n") unless b.byteslice(-1) == "\n"
        end
      end
    }
    do_write(s)
    nil
  end

  ##
  # Writes character _ch_ to the stream.
  #
  # See IO#putc for full details.

  def putc(ch)
    if String === ch
      # Can be empty or more than 1 byte
      do_write(ch[0, 1])
    else
      do_write((ch & 0xff).chr)
    end
    ch
  end

  ##
  # Writes _args_ to the stream.
  #
  # See IO#print for full details.

  def print(*args)
    s = Buffer.new
    args.each{ |arg| s.append_as_bytes(arg.to_s) }
    do_write(s)
    nil
  end

  ##
  # Formats and writes to the stream converting parameters under control of
  # the format string.
  #
  # See Kernel#sprintf for format string details.

  def printf(s, *args)
    do_write(s % args)
    nil
  end

  ##
  # Flushes buffered data to the SSLSocket.

  def flush
    osync = @sync
    @sync = true
    do_write ""
    return self
  ensure
    @sync = osync
  end

  ##
  # Closes the SSLSocket and flushes any unwritten data.

  def close
    flush rescue nil
    sysclose
  end
end
