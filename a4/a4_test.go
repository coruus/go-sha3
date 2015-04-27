package a4

import (
	"bytes"
	"testing"
)

var (
	p  = []byte("this is a test")
	d  = []byte("217")
	k  = []byte("test key")
	ad = []byte("associated data")
)

func TestA4(t *testing.T) {
	a := A4{len(ad), k}
	c := a.AuthEnc([]byte("associated data"), p)
	t.Logf("len(c) = %d\n", len(c))
	vad, vp, err := a.AuthDec(c)
	if err != nil {
		t.Errorf("%s\n", err)
	}
	if !(bytes.Equal(vp, p) && bytes.Equal(vad, ad)) {
		t.Errorf("Decryption was not successful.")
	}
	t.Logf("used:\n%s\n%s\n", p, ad)
	t.Logf("got:\n%v\n%s\n%s\n", c, vp, vad)
}
