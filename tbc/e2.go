package tbc

/*
x1 = A1(k, t, [], m)
l1 = B1(k, t, [])
y1 = E(l1, x1)
x2 = A2(k, t, [y1], m)
l2 = B2(k, t, [y1])
y2 = E(l2, x1)
c = A3(k, t, [y1, y2], m)
*/

import (
	"github.com/coruus/go-sha3/rijndael"
)

const BlockLen = 32

func enc(c, k, p *[BlockLen]byte) {
	rijndael.NewCipher(k).Encrypt(c, p)
}

func dec(p, k, c *[BlockLen]byte) {
	rijndael.NewCipher(k).Decrypt(c, p)
}

func xor(dst, s1, s2 *[BlockLen]byte) {
	for i := range dst {
		dst[i] = s1[i] ^ s2[i]
	}
}

func encryptBlock(c, m, t, k *[BlockLen]byte) {
	var z, kp, mp [BlockLen]byte
	enc(&z, k, t)    // z = E(k)(t)
	xor(&kp, k, t)   // kp = k ^ t
	xor(&mp, m, &z)  // mp = m ^ z
	enc(c, &kp, &mp) // c = E(k^t)(m^z)
	xor(c, c, &z)    // c ^= z
}

func decryptBlock(m, c, t, k *[BlockLen]byte) {
	var z, kp, cp [BlockLen]byte
	enc(&z, k, t)    // Z = E(k)(t)
	xor(&kp, k, t)   // k' = k ^ t
	xor(&cp, &z, c)  // c' = z ^ c
	dec(m, &kp, &cp) // m = D(k')(c')
}

type NewABPair func(k, t *[BlockLen]byte) ABPair

type ABPair interface {
	A(i int, x *[BlockLen]byte, y [][BlockLen]byte, m *[BlockLen]byte)
	B(i int, x *[BlockLen]byte, y [][BlockLen]byte)
}

func genericE(c, m, k, t *[BlockLen]byte, rho int, f NewABPair) {
	var yy [][BlockLen]byte
	var x [BlockLen]byte
	var l [BlockLen]byte
	var y [BlockLen]byte

	ab := f(k, t)

	for i := 0; i < rho; i++ {
		ab.A(i, &x, yy, m)
		ab.B(i, &l, yy)
		enc(&y, &l, &x)
		yy = append(yy, y)
	}
	ab.A(rho, c, yy, m)
}
