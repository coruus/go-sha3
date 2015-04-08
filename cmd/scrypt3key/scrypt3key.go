package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"os"

	"code.google.com/p/gopass"
	"github.com/coruus/go-sha3/scrypt3"
	"github.com/golang/glog"
)

var N int
var r int
var p int
var keyLen int
var b64 bool

func init() {
	flag.IntVar(&N, "N", 1<<16, "N")
	flag.IntVar(&r, "r", 32, "r")
	flag.IntVar(&p, "p", 1, "p")
	flag.IntVar(&keyLen, "len", 63, "key length")
	flag.BoolVar(&b64, "b64", true, "base64 output")
}

func main() {
	flag.Parse()
	match := false
	var password string
	for !match {
		password, err := gopass.GetPass("password: ")
		if err != nil {
			glog.Errorf("%s", err)
		}
		password2, err := gopass.GetPass("confirm: ")
		if err != nil {
			glog.Errorf("%s", err)
		}
		if password == password2 {
			match = true
		}
	}
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		glog.Errorf("%s", err)
	}
	key, err := scrypt3.Key([]byte(password), salt, N, r, p, keyLen)
	if b64 {
		os.Stdout.Write([]byte(base64.URLEncoding.EncodeToString(key)))
	} else {
		os.Stdout.Write(key)
	}
	return
}
