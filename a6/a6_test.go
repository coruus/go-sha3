package a6

import (
	"testing"

	"github.com/coruus/go-sha3/a6"
)

var (
	testBytes = []byte("this is a test")
	testData  = []byte("217")
)

func TestA6(t *testing.T) {
	ae := a6.New([]byte("test key"), []byte("test nonce"))
	c := ae.AuthEnc(testBytes, testData)
	t.Logf("len(c) = %d\n", len(c))
	p, err := ae.AuthDec(c, testData)
	if err != nil {
		t.Errorf("%s", err)
	}
	t.Logf("got %v\n%s\n", c, p)
}
