package feistel

import (
	"fmt"

	"github.com/coruus/go-sha3/sha3"
)

type state struct {
	hk   sha3.ShakeHash
	x    [4][]byte
	hlen int
}

const qrounds = 19

func NewIro(k []byte) (*state, error) {

	hk := sha3.NewShake256()
	hk.Write(k)
	hk.Pad(byte(0x3f))

	s := &state{
		hk: hk,
	}
	return s, nil
}

func (s *state) F(y []byte, x []byte, i byte) {
	h := s.hk.Clone()
	h.Write(x)
	h.Write([]byte{i})
	h.Read(y)
	h.Reset()
}

func xoreq(dst, s []byte) {
	for i := range dst {
		dst[i] ^= s[i]
	}
}

func (s *state) Encrypt(c []byte, m []byte) (err error) {
	l := len(m)
	if (l & 1) != 0 {
		return fmt.Errorf("len(m) is not even: %v", len(m))
	}
	n, x := l/2, s.x
	for i := range x {
		if x[i] != nil && cap(s.x[i]) >= n {
			x[i] = x[i][:n]
		} else {
			x[i] = make([]byte, l/2)
		}
	}

	copy(x[0], m[:n])
	copy(x[1], m[n:])
	for i := 0; i < qrounds; i += 1 {
		// x2 = x0 ^ F1(x1)
		s.F(x[2], x[1], byte(i*4+1))
		xoreq(x[2], x[0])

		// x3 = x1 ^ F2(x2)
		s.F(x[3], x[2], byte(i*4+2))
		xoreq(x[3], x[1])

		// x4 = x2 ^ F3(x3)
		// x0 = x2 ^ F3(x3)
		s.F(x[0], x[3], byte(i*4+3))
		xoreq(x[0], x[2])

		// x5 = x3 ^ F4(x4)
		// x1 = x3 ^ F4(x0)
		s.F(x[1], x[0], byte(i*4+4))
		xoreq(x[1], x[3])
	}
	copy(c[:n], x[0])
	copy(c[n:], x[1])
	return
}
