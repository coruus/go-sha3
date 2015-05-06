// Package a4 implements the AEAD scheme NRS A4.
//
// (It is roughly equivalent to SIV mode.)
//
// Note on the implementation:
//
//    F_L is implemented by the tag function
//    as a VecMac keyed by k.
//
//    E(k, iv, m) is implemented by deriving
//    a key from k and the tag. (This avoids
//    taking a security hit from AES-CTR's
//    short IV.)
package a4

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/sha3"
)

const (
	// TagLen is the length of the output tag
	TagLen = 24
)

// Some very simple domain separators.
var (
	dsNonce = []byte("n")
	dsAd    = []byte("a")
	dsM     = []byte("m")
	dsTag   = []byte("t")
)

func tag(k, n, ad, m []byte) (t []byte) {
	h := sha3.NewShake256()
	h.Write(k)
	h.Write(dsNonce)
	h.Write(n)
	h.Write(dsAd)
	h.Write(ad)
	h.Write(dsM)
	h.Write(m)
	t = make([]byte, TagLen)
	h.Read(t)
	h.Reset()
	return
}

func kn(k, tag []byte) (kn []byte) {
	h := sha3.NewShake256()
	h.Write(k)
	h.Write(dsTag)
	h.Write(tag)
	kn = make([]byte, 48)
	h.Read(kn)
	h.Reset()
	return
}

// Seal a message and associated data using
func Seal(k, n, ad, m []byte) (c, t []byte) {
	t = tag(k, n, ad, m)
	// Derive the key and iv for the stream cipher from
	// the tag.
	kn := kn(k, t)
	block, err := aes.NewCipher(kn[0:32])
	if err != nil {
		panic(fmt.Sprintf("%s", err))
	}
	stream := cipher.NewCTR(block, kn[32:48])

	c = make([]byte, len(m))
	stream.XORKeyStream(c, m)
	return
}

// SealSerialized generates a random nonce, and serializes
// the result (including AD).
func SealSerialized(k, ad, m []byte) (sealed []byte, err error) {
	adLen := make([]byte, 10)
	l := binary.PutUvarint(adLen, uint64(len(ad)))
	adLen = adLen[:l]

	n := make([]byte, 24)
	_, err = rand.Read(n)
	if err != nil {
		return
	}
	c, t := Seal(k, n, ad, m)

	return
}

func Unseal(k, n, ad, c, t []byte) (m []byte) {
	if len(t) != TagLen {
		return nil
	}
	kn := kn(k, t)
	block, err := aes.NewCipher(kn[0:32])
	if err != nil {
		panic(fmt.Sprintf("%s", err))
	}
	stream := cipher.NewCTR(block, kn[32:48])

	m = make([]byte, len(c))
	stream.XORKeyStream(m, c)

	expected := tag(k, n, ad, m)
	if subtle.ConstantTimeCompare(expected, t) != 1 {
		return nil
	}
	return
}
