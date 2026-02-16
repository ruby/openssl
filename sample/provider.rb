require 'openssl'
require 'pathname'
require 'fileutils'

# note that this assumes that commands like:
# tpm2_createak --tcti=swtpm:port=4523 -C 0x81010001 -G rsa -g sha256 -s rsassa -c ak_rsa.ctxi -u ak_rsa.pub -n ak_rsa.name
# tpm2_evictcontrol --tcti=swtpm:port=4523 -C o -c ak_rsa.ctx 0x81010003
# have been run

cwd=Pathname.new(FileUtils.pwd())

tpmstatedir = cwd + "tpmstate"
FileUtils.mkdir_p(tpmstatedir)
ENV['TPM2OPENSSL_TCTI']="swtpm:port=4523"
if !File.exist?(tpmstatedir + "tpm2-00.permall")
  system("swtpm_setup --tpm-state #{tpmstatedir} --tpm2 --createek")
end

#  startup-clear implies not-need-init, and otherwise swtpm returns error 0x101.
#  and the provider won't even load.
#system("swtpm socket --daemon --server type=tcp,port=4523 --ctrl type=tcp,port=4524 --tpmstate dir=#{tpmstatedir} --tpm2 --log file=/var/tmp/tpm2.log --flags startup-clear")
sleep(1)
prov01=OpenSSL::Provider.load("tpm2")
print "Loaded #{OpenSSL::VERSION}\n"
#print OpenSSL::PKey.methods.sort; print "\n"
#ENV['TSS2_LOG']="all+ERROR,marshal+TRACE,tcti+DEBUG"
pkey = OpenSSL::PKey.load_from_handle("handle:0x81010003")
#pkey=prov01.pkey
print pkey
print pkey.inspect
print "Done\n"



