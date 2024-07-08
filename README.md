# ima-policy-creation

This project provides a tool for creating an IMA policy with BPRM_CHECK, MMAP_CHECK, and FILE_CHECK rules on
an SELinux-enabled system.

# Getting started

Creating and running an IMA appraisal policy currently only works on Fedora Rawhide since only there all files
are properly signed and the Fedora signing keys can be loaded into the Linux kernel.

Installation of dependencies on Fedora.
```
dnf -y install \
  glib2-devel \
  ima-evm-utils \
  openssl-devel
```

If you are running on a secure-boot enabled UEFI system (or PowerVM) system you may want to create a local IMA file signing key. It's CA will need to be imported into the UEFI MOK DB (or PowerVM equivalent). Instructions for how to generate the CA and local IMA file signing key and import it into the MOK DB can be found [here](https://ima-doc.readthedocs.io/en/latest/ima-utilities.html#ima-ca-key-and-certificate).

# Build

```
make
```

# Have Dracut load all keys onto the keyring

```
dracut -a integrity --force
```

# Creating a policy

This tool implements a method 'filesystem' to create a policy. This method is known to work on a
(lightly used) Fedora Rawhide system. Please follow the instructions on the help screen.
```
./gen-ima-policy -h
```

Command lines that I am currently using:

Initial signing of all files that don't have a proper signature:

```
PATH=.:${PATH} ./gen-ima-policy filesystem \
  -k /etc/keys/ima/fedora-42-ima.der \
  -k /etc/keys/ima/fedora-41-ima.der \
  -k /etc/keys/ima/fedora-40-ima.der \
  -k /etc/keys/ima/fedora-39-ima.der \
  -k ~/local-ima-sign-key/imacertecc.der \
  -S ~/local-ima-sign-key/imakeyecc.pem
```

For creating of an IMA appraisal policy (after using system for a while and a reboot):
```
PATH=.:${PATH} ./gen-ima-policy filesystem \
  -k /etc/keys/ima/fedora-42-ima.der \
  -k /etc/keys/ima/fedora-41-ima.der \
  -k /etc/keys/ima/fedora-40-ima.der \
  -k /etc/keys/ima/fedora-39-ima.der \
  -k ~/local-ima-sign-key/imacertecc.der \
  -a \
  -o my-ima-policy
```

Install and sign the IMA policy:

```
cp my-ima-policy /etc/ima/ima-policy
evmctl ima_sign --key ~/local-ima-sign-key/imakeyecc.pem /etc/ima/ima-policy
```

If the currently running policy did not allow you to sign the file then try
the following:

```
evmctl ima_sign --key ~/local-ima-sign-key/imakeyecc.pem my-ima-policy
cp my-ima-policy /etc/ima/ima-policy
restorecon /etc/ima/ima-policy

```

# Notes

- When cpontainer runtimes (like docker or podman) are installed an IMA
  appraisal policy requires SELinux label based exceptions otherwise 
  containers will not start. Due to the exceptions for BPRM_CHECK and
  MMAP_CHECK the resulting appraisal policy is not as "strong".
