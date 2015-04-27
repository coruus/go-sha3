package aont

import (
	"crypto/rand"
	"fmt"
	"github.com/coruus/go-sha3/sha3"
	"golang.org/x/crypto/salsa20"
)

const PackageKeyLen = 32

var defaultPackageKey = make([]byte, PackageKeyLen)

func stretch(k *[32]byte, n, key []byte) {
	kn := make([]byte, 40)
	sha3.ShakeSum256(kn, key)
	copy(k[:], kn[0:32])
	n = kn[32:40]
}

func stream(c []byte, m []byte, key []byte) {
	var k [32]byte
	n := make([]byte, 8)
	stretch(&k, n, key)
	salsa20.XORKeyStream(c, m, n, &k)
}

func xor(d, s []byte) {
	for i, v := range s {
		d[i] ^= v
	}
}

func vecmac(mac []byte, inputs [][]byte, k []byte) (err error) {
	if len(inputs) > 95 {
		return fmt.Errorf("this vecmac instance can only handle up to 95 inputs...")
	}
	h := sha3.NewShake256()
	h.Write(k)
	ds := byte(0x3f)
	for _, input := range inputs {
		h.Pad(ds)
		ds += 2
		h.Write(input)
	}
	h.Read(mac)
	h.Reset()
	return
}

func KeyedPackage(c []byte, t []byte, m []byte, k []byte) (err error) {
	switch {
	case len(t) < 32:
		return fmt.Errorf("the tag length is too short to mask the AONT key")
	case len(t) > 255:
		return fmt.Errorf("the tag length won't fit into a single byte...")
	}
	iv := make([]byte, len(t))
	_, err = rand.Read(iv[:32])
	if err != nil {
		return err
	}

	// This is somewhat unnecessary, but ensures that even if our RNG
	// is broken, the difficulty of unpackaging is no less than:
	//   min(entropy(m), entropy(iv))
	if err = vecmac(iv, [][]byte{
		[]byte{byte(len(t))},
		iv,
		m,
	}, k); err != nil {
		return err
	}

	// Encipher the plaintext.
	stream(c, m, iv)
	// Compute the hash of the ciphertext.
	if err = vecmac(iv, [][]byte{
		[]byte{byte(len(t))},
		c,
	}, k); err != nil {
		return err
	}
	// Mask the key with the hash.
	for i, v := range iv {
		t[i] ^= v
	}
	return
}

func KeyedUnpackage(m, c, t, k []byte) (err error) {
	iv := make([]byte, len(t))
	// Compute the hash of the ciphertext.
	if err = vecmac(iv, [][]byte{
		[]byte{byte(len(t))},
		c,
	}, k); err != nil {
		return err
	}
	// Unmask the IV.
	for i, v := range t {
		iv[i] ^= v
	}
	// Decipher the plaintext.
	stream(m, c, iv)
	return
}

func Package(m []byte) (c []byte, err error) {
	c = make([]byte, len(m)+32)
	err = KeyedPackage(c[0:len(m)], c[len(m):], m, defaultPackageKey)
	return
}

func Unpackage(ct []byte) (m []byte, err error) {
	m = make([]byte, len(ct)-32)
	c, t := ct[0:len(ct)-32], ct[len(ct)-32:]
	err = KeyedUnpackage(m, c, t, defaultPackageKey)
	return
}
