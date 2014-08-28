# SHA-3 and SHAKE for Go

Updated version of "code.gooogle.com/p/go.crypto/sha3".

(Intended to be upstreamed.)

Some dogfooding:

  cmd/shake256sum: Computes a 64-byte Shake256 digest of
  files (or standard input). Accepts a -mackey parameter
  to make a MAC.

  a6: A package that implements a type A6 generic composition
  of Shake256 and XSalsa20
