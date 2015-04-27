// Package a4 implements an NRS.A4 AEAD scheme using Shake256
// and AES-256. See https://eprint.iacr.org/2014/206
//
package a4

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"github.com/coruus/go-sha3/sha3"
	"io/ioutil"
)

type A4 struct {
	AdLen int
	K     []byte
}

// Encrypt
func (ctx *A4) AuthEnc(ad, p []byte) (c []byte) {
	h := sha3.NewShake256()
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		panic("rand failed")
	}
	h.Reset()
	h.Write(nonce)
	h.Write([]byte("make nonce opaque"))
	h.Read(nonce)

	h.Reset()
	h.Write(ctx.K)
	h.Write(nonce)
	h.Write(ad)
	h.Write([]byte("end of authenticated data"))
	h.Write(p)
	iv := make([]byte, 32)
	h.Read(iv)

	h.Reset()
	h.Write(ctx.K)
	h.Write(iv)
	h.Write([]byte("derive Rijndael[Nw=4,Nk=8] key and IV"))
	ck := make([]byte, 48)
	h.Read(ck)
	h.Reset()

	block, err := aes.NewCipher(ck[:32])
	s := cipher.NewCTR(block, ck[32:])
	buf := bytes.NewBuffer(nonce)
	buf.Write(iv)
	buf.Write(ad)
	sw := cipher.StreamWriter{s, buf, err}
	sw.Write(p)
	c, err = ioutil.ReadAll(buf)

	return
}

func (ctx *A4) AuthDec(c []byte) (vad, p []byte, err error) {
	h := sha3.NewShake256()

	nonce := c[:32]
	c = c[32:]
	iv := c[:32]
	c = c[32:]
	ad := c[:ctx.AdLen]
	c = c[ctx.AdLen:]

	h.Reset()
	h.Write(ctx.K)
	h.Write(iv)
	h.Write([]byte("derive Rijndael[Nw=4,Nk=8] key and IV"))
	ck := make([]byte, 48)
	h.Read(ck)

	block, _ := aes.NewCipher(ck[:32])
	s := cipher.NewCTR(block, ck[32:])
	maybep := make([]byte, len(c))
	s.XORKeyStream(maybep, c)

	h.Reset()
	h.Write(ctx.K)
	h.Write(nonce)
	h.Write(ad)
	h.Write([]byte("end of authenticated data"))
	h.Write(maybep)
	tag := make([]byte, 32)
	h.Read(tag)

	h.Reset()

	if subtle.ConstantTimeCompare(tag, iv) != 1 {
		return nil, nil, errors.New("Authentication failure.")
	}
	return ad, maybep, nil
}
