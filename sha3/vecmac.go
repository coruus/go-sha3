package sha3

type mac struct {
	s *state
	a [25]uint64
}

type VecMac interface {
	VecMac([]byte, [][]byte) error
	ResetMac()
}

func (h *mac) ResetMac() {
	h.s.Reset()
	for i, v := range h.a {
		h.s.a[i] = v
	}
}

// VecMac implements a trivial vector-input MAC based on Keccak-f.
func (h *mac) VecMac(hash []byte, parts [][]byte) (err error) {
	if err != nil {
		return
	}
	// BUG(dlg): Check that there aren't too many parts for
	// a single byte domain separator.
	pad := byte(0xff - 2)
	for _, part := range parts {
		h.s.Write(part)
		h.s.Pad(pad)
		pad -= 2
	}
	_, err = h.s.Read(hash)
	h.ResetMac()
	return
}

func NewVecMac(key []byte, rate int) (m VecMac, err error) {
	h, err := NewShake(rate)
	h.Write(key)
	h.Pad(0xff)
	var a [25]uint64
	for i, v := range h.(*state).a {
		a[i] = v
	}
	m = &mac{
		s: h.(*state),
		a: a,
	}
	return
}
