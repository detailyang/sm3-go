// Package sm3 implements the SM3 hash algorithms as defined in
// http://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf.
package sm3

import "hash"

// Size indicates the Size of a SM3 checksum in bytes.
const Size = 32

// BlockSize indicates the blocksize of a SM3 checksum.
const BlockSize = 64

const (
	chunk = 64
	// IV = 7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e
	init0 = 0x7380166F
	init1 = 0x4914B2B9
	init2 = 0x172442D7
	init3 = 0xDA8A0600
	init4 = 0xA96F30BC
	init5 = 0x163138AA
	init6 = 0xE38DEE4D
	init7 = 0xB0FB0E4E
)

// Digest represents the partial evaluation of a checksum.
type Digest struct {
	h   [8]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

// New returns a new hash.Hash computing the SM3 checksum.
func New() hash.Hash {
	d := new(Digest)
	d.Reset()
	return d
}

// Reset resets the digest.
func (d *Digest) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.h[5] = init5
	d.h[6] = init6
	d.h[7] = init7

	d.nx = 0
	d.len = 0
}

// Size return the size of SM3 in bytes.
func (d *Digest) Size() int { return Size }

// BlockSize return the blocksize of SM3.
func (d *Digest) BlockSize() int { return BlockSize }

// Write write the p to digest.
func (d *Digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)

	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}

	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		block(d, p[:n])
		p = p[n:]
	}

	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}

	return
}

// Sum calculate the data of sm3 checmsum.
func (d *Digest) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	d0 := *d
	hash := d0.checkSum()
	return append(in, hash[:]...)
}

func (d *Digest) checkSum() [Size]byte {
	len := d.len
	// Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}

	// Length in bits.
	len <<= 3
	putUint64(tmp[:], len)
	d.Write(tmp[0:8])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [Size]byte

	putUint32(digest[0:], d.h[0])
	putUint32(digest[4:], d.h[1])
	putUint32(digest[8:], d.h[2])
	putUint32(digest[12:], d.h[3])
	putUint32(digest[16:], d.h[4])
	putUint32(digest[20:], d.h[5])
	putUint32(digest[24:], d.h[6])
	putUint32(digest[28:], d.h[7])

	return digest
}

// Sum returns the SM3 checksum of the data.
func Sum(data []byte) [Size]byte {
	var d Digest
	d.Reset()
	d.Write(data)
	return d.checkSum()
}
