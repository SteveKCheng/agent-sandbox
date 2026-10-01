# vim: noet nosta sw=8
#
# Assuming the host system is Fedora Linux, this Makefile makes a copy of /etc/pki
# to ./etc/pki, allowing you to make modifications to it, e.g. adding the certificate 
# for a man-in-the-middle HTTP(S) proxy.  Then it can run update-ca-trust so that 
# ./etc/pki is ready to drop into a sandbox, and all system applications will know
# about the new certificates.
#
# Normally, update-ca-trust on Fedora Linux is hard-coded to work on system paths
# (and thus requires root access).  With bwrap overlaying ./etc/pki over /etc/pki
# in a "fake" root filesystem, update-ca-trust can then run without root privileges.
#
update-ca-trust: | etc/pki
	bwrap --ro-bind / / \
	      --dev-bind /dev /dev \
	      --proc /proc \
	      --bind etc/pki /etc/pki \
	      update-ca-trust

etc/pki:
	rm -rf etc/pki
	cp -a /etc/pki etc/pki
	chown -r $(id -ru):$(id -rg) etc/pki


.PHONY: update-ca-trust
