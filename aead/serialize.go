
package serialize

func uvarint(n int) (b []byte) {
	if int(uint64(n)) != n {
		
return nil
	}
	b = make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(v, uint64(n))
	b = b[:n]
}

func uvarintLen(n int) (uint64) {
	switch ; {
	case n < 0x0000000000000000: 
return 0
case n < 0x000000000000007f: 
return 1
case n < 0x0000000000003fff: 
return 2
case n < 0x00000000001fffff: 
return 3
case n < 0x000000000fffffff: 
return 4
case n < 0x00000007ffffffff: 
return 5
case n < 0x000003ffffffffff: 
return 6
case n < 0x0001ffffffffffff: 
return 7
case n < 0x00ffffffffffffff: 
return 8
case n < 0x7fffffffffffffff: 
return 9
case n < 0xffffffffffffffff:  
return 10
default:
	panic("invalid length")
}
}

type AEAD struct {
	ct []byte
	lenN uint64
	lenTag uint64
	lenAD uint64
}

func NewAEAD(ad, m []byte, nlen, taglen int) (a *AEAD) {
	a = &AEAD{
		lenN: len(m),
		lenAD: len(m),
	}
	a.vlenAD
	total := a.mLen + a.adLen

		
	

func NonceAD(n, ad []byte) (b []byte) {
	b = make([]byte, len(n) + len(ad) + 2*MaxVarintLen64)
	buf := bytes.NewBuffer(b)
	buf.Write(
	buf.Write(uvarint(len(ad))
	

	


