package sha3

// SHAKE variable-output-length hash functions.

// NewShake128 creates a new SHAKE128 variable-output-length Sponge.
// Its generic security strength is 128 bits against all attacks if at
// least 32 bytes of its output are used.
func NewShake128() Sponge {
	return &state{
		fixedOutput: false,
		outputSize:  512,
		rate:        200 - (2 * 128 / 8),
		dsbyte:      0x1f}
}

// NewShake256 creates a new SHAKE128 variable-output-length Sponge.
// Its generic security strength is 256 bits against all attacks if
// at least 64 bytes of its output are used.
func NewShake256() Sponge {
	return &state{
		fixedOutput: false,
		outputSize:  512,
		rate:        200 - (2 * 256 / 8),
		dsbyte:      0x1f}
}

// NewSponge creates a new Keccak-based sponge instance of any
// desired rate > 0 and < bytebufLen. Note that the resulting
// function is *not* a SHAKE function, unless rate is 168 or 136,
// and dsbyte == 0x1f
//
// By default the output size is equal to the rate minus - 1. Any
// amount of output can be requested.
func NewSponge(rate int, dsbyte byte) Sponge {
	if rate > bufferLen || rate <= 0 {
		return nil
	}
	return &state{
		fixedOutput: false,
		outputSize:  int(rate - 8),
		rate:        int(rate),
		dsbyte:      dsbyte}
}
