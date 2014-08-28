// shake256sum is a very basic checksum command
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"

	"code.google.com/p/go.crypto/sha3"
)

const (
	rate = 136
)

var macKey string

func init() {
	flag.StringVar(&macKey, "mackey", "", "an ASCII MAC key")
}

func sumFile(filename string) (checksum string, err error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	sp := sha3.NewShake256()
	sp.Write([]byte(macKey))
	_, err = io.Copy(sp, f)
	if err != nil {
		return "", err
	}
	digest := make([]byte, 64)
	sp.Read(digest)
	checksum = base64.URLEncoding.EncodeToString(digest)
	return checksum, nil
}

func sumReader(r io.Reader) (checksum string) {
	sp := sha3.NewShake256()
	sp.Write([]byte(macKey))
	_, err := io.Copy(sp, r)
	if err != nil {
		fmt.Errorf("error reading %v: %s\n", r, err)
	}
	digest := make([]byte, 64)
	sp.Read(digest)
	checksum = base64.URLEncoding.EncodeToString(digest)
	return
}

func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		// Read from stdin
		checksum := sumReader(os.Stdin)
		fmt.Println(checksum)
	} else {
		for _, filename := range flag.Args() {
			checksum, err := sumFile(filename)
			if err != nil {
				fmt.Errorf("error %s on %s", err, filename)
			}
			fmt.Printf("SHAKE256(%s) = %s\n", filename, checksum)
		}
	}
	return
}
