package sha3

// This file defines a vecMac based on SHAKE.
// It caches the absorbed key.

type VecMac interface {
	Mac func(inputs [][]byte)
}

type v struct {
	h0 ShakeHash
}

func NewVecMac(k []byte, ShakeHash h) (VecMac) {
	h.Write(k)
	h.Pad(
	return &v{

