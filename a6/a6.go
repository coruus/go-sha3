// Package a6 implements an NRS.A6 AEAD scheme using Shake256
// and XSalsa20. See https://eprint.iacr.org/2014/206
package a6

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"code.google.com/p/go.crypto/salsa20"
	"code.google.com/p/go.crypto/sha3"
)

type Aead interface {
	Overhead() int

	AuthEnc(plaintext, data []byte) []byte
	AuthDec(ciphertext, data []byte) ([]byte, error)
}

type state struct {
	hashKey   [keyLen]byte
	cipherKey [keyLen]byte
}

const (
	tagLen   = 32
	keyLen   = 32
	nonceLen = 24
)

func (s *state) NonceSize() int {
	return 32
}

func (s *state) Overhead() int {
	return tagLen + nonceLen
}

func (s *state) AuthEnc(plaintext, data []byte) []byte {
	nonce := make([]byte, nonceLen)
	_, err := rand.Read(nonce)
	if err != nil {
		panic("RNG failed")
	}
	sp := sha3.NewShake256()
	sp.Write(s.hashKey[:])
	sp.Write(nonce)
	sp.Write(data)
	iv := make([]byte, 24)
	sp.Read(iv)

	buf := bytes.NewBuffer(nonce)
	buf.Write(data)
	ciphertext := make([]byte, len(plaintext))
	salsa20.XORKeyStream(ciphertext, plaintext, iv, &s.cipherKey)

	sp = sha3.NewShake256()
	sp.Write(s.hashKey[:])
	sp.Write(nonce)
	sp.Write(data)

	sp.Write(ciphertext)
	tag := make([]byte, tagLen)
	sp.Read(tag)
	ciphertext = append(tag, ciphertext...)
	return append(nonce, ciphertext...)
}

func (s *state) AuthDec(c, data []byte) ([]byte, error) {
	n, c := c[:nonceLen], c[nonceLen:]
	t, c := c[:tagLen], c[tagLen:]

	sp := sha3.NewShake256()
	sp.Write(s.hashKey[:])
	sp.Write(n)
	sp.Write(data)

	iv := make([]byte, 24)
	sp.Read(iv)

	sp = sha3.NewShake256()
	sp.Write(s.hashKey[:])
	sp.Write(n)
	sp.Write(data)
	sp.Write(c)
	tag := make([]byte, tagLen)
	sp.Read(tag)
	if subtle.ConstantTimeCompare(t, tag) != 1 {
		return nil, errors.New(fmt.Sprintf("purported: %v, tag: %v", t, tag))
	}
	plaintext := make([]byte, len(c))
	salsa20.XORKeyStream(plaintext, c, iv, &s.cipherKey)
	return plaintext, nil
}

func New(key []byte, nonce []byte) Aead {
	var s state
	sp := sha3.NewShake256()
	sp.Write(key)
	sp.Write(nonce)
	sp.Read(s.hashKey[:])
	sp.Read(s.cipherKey[:])
	return &s
}
