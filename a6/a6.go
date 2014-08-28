// Package a6 implements an NRS.A6 AEAD scheme using Shake256
// and XSalsa20. See https://eprint.iacr.org/2014/206
package a6

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"code.google.com/p/go.crypto/salsa20"
	"code.google.com/p/go.crypto/sha3"
)

type A6 interface {
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
	ciphertext := make([]byte, len(plaintext))
	salsa20.XORKeyStream(ciphertext,
		plaintext, iv, &s.cipherKey)
	sp.Write(ciphertext)
	tag := make([]byte, tagLen)
	sp.Read(tag)
	ciphertext = append(tag, ciphertext...)
	return append(nonce, ciphertext...)
}

func (s *state) AuthDec(ciphertext, data []byte) ([]byte, error) {
	nonce := ciphertext[:nonceLen]
	ciphertext = ciphertext[nonceLen:]
	purportedTag := ciphertext[:tagLen]
	ciphertext = ciphertext[tagLen:]
	sp := sha3.NewShake256()
	sp.Write(s.hashKey[:])
	sp.Write(nonce)
	sp.Write(data)
	iv := make([]byte, 24)
	sp.Read(iv)
	sp.Write(ciphertext)
	tag := make([]byte, tagLen)
	sp.Read(tag)
	if subtle.ConstantTimeCompare(purportedTag, tag) != 1 {
		return nil, errors.New(fmt.Sprintf("purported: %v, tag: %v", purportedTag, tag))
	}
	plaintext := make([]byte, len(ciphertext))
	salsa20.XORKeyStream(plaintext, ciphertext, iv, &s.cipherKey)
	return plaintext, nil
}

func NewA6(key []byte, nonce []byte) A6 {
	var s state
	sp := sha3.NewShake256()
	sp.Read(key)
	sp.Read(nonce)
	sp.Write(s.hashKey[:])
	sp.Write(s.cipherKey[:])
	return &s
}
