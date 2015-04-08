package a6x

import (
	"crypto/subtle"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/sha3"
)

func Open(k, c []byte) []byte {
	if len(c) < 40 {
		return nil
	}
	p := make([]byte, len(c)-40)
	h := sha3.NewShake256()

	var t, tx [32]byte
	n, nx := make([]byte, 8), make([]byte, 8)

	h.Write(k)
	h.Write(c[40:])
	h.Read(tx[:])
	h.Read(nx)

	for i := range tx {
		tx[i] ^= c[i]
	}
	for i := range nx {
		nx[i] ^= c[i+len(t)]
	}

	salsa20.XORKeyStream(p, c[40:], n, &t)

	h.Write(k)
	h.Write(p)
	h.Read(t[:])
	h.Read(n)

	if 1 == subtle.ConstantTimeCompare(t[:], c[:32])&subtle.ConstantTimeCompare(n, c[32:40]) {
		return p
	}
	return nil
}

func Seal(k, p []byte) []byte {
	c := make([]byte, len(p)+40)
	h := sha3.NewShake256()

	var t, tx [32]byte
	n, nx := make([]byte, 8), make([]byte, 8)

	h.Write(k)
	h.Write(p)
	h.Read(t[:])
	h.Read(n)

	salsa20.XORKeyStream(c[40:], p, n, &t)

	h.Reset()
	h.Write(k)
	h.Write(c[40:])
	h.Read(tx[:])
	h.Read(nx)

	for i, v := range t {
		tx[i] ^= v
	}
	for i, v := range n {
		nx[i] ^= v
	}
	copy(c[:32], tx[:])
	copy(c[32:40], n)
	return c
}
