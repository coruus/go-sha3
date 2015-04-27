package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
)

var (
	rspRe = regexp.MustCompile("^([^=#]+) = ([A-Z0-9]+)")
)

type kat struct {
	bitlen uint64
	input  []byte
	output []byte
}

func main() {
	f, _ := os.Open("ShortMsgKAT_SHA3-256.txt")
	s, _ := ioutil.ReadAll(f)
	lines := bytes.Split(s, []byte("\n"))
	kats := make([]kat, len(lines)/3)
	for i, line := range lines {
		rsp := rspRe.FindSubmatch(line)
		if rsp == nil {
			continue
		}
		switch i % 3 {
		case 0:
			kats[i/3].bitlen, _ = strconv.ParseUint(string(rsp[2]), 10, 32)
		case 1:
			fmt.Println(kats[i/3])
			fmt.Println(rsp[2])
			_, err := hex.Decode(kats[i/3].input, rsp[2])
			if err != nil {
				fmt.Errorf("%s", err)
			}
		case 2:
			fmt.Println(kats[i/3])
			fmt.Println(rsp[2])
			hex.Decode(kats[i/3].output, rsp[2])
		}
	}
	fmt.Println(kats[1])
}
