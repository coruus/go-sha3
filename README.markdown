# SHA-3 and SHAKE for Go

Updated version of "code.gooogle.com/p/go.crypto/sha3".

(Intended to be upstreamed.)

Design decisions:

  - Endianness is the responsibility of the permutation.
  - The "sponge" code operates on byte slices only.

