
In order to get DTLS to work, you need a patched copy of Openssl.
Get it here:
   https://github.com/mcr/openssl/tree/dtls-listen-refactor

build and install it.  You might want to compile without DSO support, as that will
make it easier for the ruby-openssl module to link in the right code. To do
that you can do:
     ./Configure no-shared --prefix=/sandel/3rd/openssl --debug linux-x86_64

(--debug being optional)

The resulting openssl.so will be significantly bigger, btw:
    %size tmp/x86_64-linux/openssl/2.4.1/openssl.so
       text    data     bss     dec     hex filename
    3889567  261788   16856 4168211  3f9a13 tmp/x86_64-linux/openssl/2.4.1/openssl.so


Pick a --prefix which is not on your regular paths.  Probably gem can be
persuaded to do all of this, but hopefully the code will upstreamed sooner
and the problem will go away.

If DTLSv1_accept() is not available, then the DTLS support will not include
server side code, only client side code.  No patches are necessary to make
client-side DTLS work.  To be sure that the patch has been found is enabled
check for:

    checking for DTLSv1_accept()... yes


Then build with:

    rake compile -- --with-openssl-dir=/sandel/3rd/openssl

I don't know how to add the extra arguments required to your Gemfile so that
it will be built properly during bundle processing. I'm sure that there is a way,
patches welcome. I do:
    gem build openssl
    gem install ./openssl-2.2.0.pre.mcr1.gem

BTW: the pull request is at:
    https://github.com/openssl/openssl/pull/5024
and comments would be welcome.
