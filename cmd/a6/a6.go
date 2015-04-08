package main

import (
	"crypto/rand"
	"flag"
	"io/ioutil"
	"os"

	"github.com/golang/glog"
)

var keyFilename string

const (
	nonceLen      = 32
	defaultKeyLen = 32
)

func init() {
	flag.StringVar(&keyFilename, "key", "", "key file")
}

func main() {
	flag.Parse()

	var err error
	var in *os.File

	if flag.NArg() > 0 {
		inFilename := flag.Arg(0)
		in, err = os.Open(inFilename)
		if err != nil {
			glog.Errorf("Couldn't open %s for reading.", inFilename)
		}
	} else {
		in = os.Stdin
	}

	var out *os.File

	if flag.NArg() > 2 {
		outFilename := flag.Arg(1)
		out, err = os.Create(outFilename)
		if err != nil {
			glog.Errorf("Couldn't create %s.", outFilename)
		}
	} else {
		out = os.Stdout
	}

	if keyFilename == "" {
		f, err := ioutil.TempFile(".", "keyfile")
		if err != nil {
			glog.Errorf("error creating keyfile: %a", err)
		}
		keyFilename = f.Name()
		glog.Infof("Created a new keyfile: %s", keyFilename)
		key := make([]byte, defaultKeyLen)
		rand.Read(key)
		f.Write(key)
		f.Close()
	}

	f, err := os.Open(keyFilename)
	if err != nil {
		glog.Errorf("%s", err)
	}
	key, err := ioutil.ReadAll(f)
	if len(key) < 32 {
		glog.Errorf("key in file %s is too short", keyFilename)
	}
	nonce := make([]byte, nonceLen)
	_, err = rand.Read(nonce)

	out.Write(nonce)
	out.Close()
}
