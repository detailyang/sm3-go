package sm3

var _K = [64]uint32{
	0x79cc4519,
	0xf3988a32,
	0xe7311465,
	0xce6228cb,
	0x9cc45197,
	0x3988a32f,
	0x7311465e,
	0xe6228cbc,
	0xcc451979,
	0x988a32f3,
	0x311465e7,
	0x6228cbce,
	0xc451979c,
	0x88a32f39,
	0x11465e73,
	0x228cbce6,
	0x9d8a7a87,
	0x3b14f50f,
	0x7629ea1e,
	0xec53d43c,
	0xd8a7a879,
	0xb14f50f3,
	0x629ea1e7,
	0xc53d43ce,
	0x8a7a879d,
	0x14f50f3b,
	0x29ea1e76,
	0x53d43cec,
	0xa7a879d8,
	0x4f50f3b1,
	0x9ea1e762,
	0x3d43cec5,
	0x7a879d8a,
	0xf50f3b14,
	0xea1e7629,
	0xd43cec53,
	0xa879d8a7,
	0x50f3b14f,
	0xa1e7629e,
	0x43cec53d,
	0x879d8a7a,
	0x0f3b14f5,
	0x1e7629ea,
	0x3cec53d4,
	0x79d8a7a8,
	0xf3b14f50,
	0xe7629ea1,
	0xcec53d43,
	0x9d8a7a87,
	0x3b14f50f,
	0x7629ea1e,
	0xec53d43c,
	0xd8a7a879,
	0xb14f50f3,
	0x629ea1e7,
	0xc53d43ce,
	0x8a7a879d,
	0x14f50f3b,
	0x29ea1e76,
	0x53d43cec,
	0xa7a879d8,
	0x4f50f3b1,
	0x9ea1e762,
	0x3d43cec5,
}

func block(dig *Digest, p []byte) {
	blockGeneric(dig, p)
}

func blockGeneric(dig *Digest, p []byte) {
	var w [68]uint32

	h0, h1, h2, h3, h4, h5, h6, h7 := dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4], dig.h[5], dig.h[6], dig.h[7]
	for len(p) >= chunk {
		// Can interlace the computation of w with the
		// rounds below if needed for speed.
		for i := 0; i < 16; i++ {
			j := i * 4
			w[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
		}

		// FOR j=16 TO 67
		// Wj ← P1(Wj−16 ⊕ Wj−9 ⊕ (Wj−3 ≪ 15)) ⊕ (Wj−13 ≪ 7) ⊕ Wj−6
		// ENDFOR
		for i := 16; i < 68; i++ {
			v1 := w[i-16] ^ w[i-9] ^ (w[i-3]<<15 | w[i-3]>>(32-15))
			w[i] = v1 ^ (v1<<15 | v1>>(32-15)) ^ (v1<<23 | v1>>(32-23)) ^ (w[i-13]<<7 | w[i-13]>>(32-7)) ^ w[i-6]
		}

		a, b, c, d, e, f, g, h := h0, h1, h2, h3, h4, h5, h6, h7

		// FOR j=0 TO 63
		// SS1 ← ((A ≪ 12) + E + (Tj ≪ j)) ≪ 7
		// SS2 ← SS1 ⊕ (A ≪ 12)
		// T T1 ← F Fj (A, B, C) + D + SS2 + Wj'
		// T T2 ← GGj (E, F, G) + H + SS1 + Wj
		// ENDFOR
		// Tj =
		// {
		// 		79cc4519 0 ≤ j ≤ 15
		// 		7a879d8a 16 ≤ j ≤ 63
		// }
		// F
		// Fj (X, Y, Z)=
		// {
		// 	 X ⊕ Y ⊕ Z 0 ≤ j ≤ 15
		// 	 (X ∧ Y ) ∨ (X ∧ Z) ∨ (Y ∧ Z ) 16 ≤ j ≤ 63
		// }
		// GG
		// GGj (X, Y, Z) =
		// {
		// 	X ⊕ Y ⊕ Z 0 ≤ j ≤ 15
		// 	(X ∧ Y ) ∨ ( ¬X∧ Z) 16 ≤ j ≤ 63
		// }
		// P0(X) = X ⊕ (X ≪ 9) ⊕ (X ≪ 17)
		// P1(X) = X ⊕ (X ≪ 15) ⊕ (X ≪ 23)
		//
		// FOR j=0 TO 63
		// Wj' = Wj ⊕ Wj+4
		// ENDFOR

		j := uint32(0)
		for ; j < 16; j++ {
			ss0 := (a<<12 | a>>(32-12)) + e + _K[j]
			ss1 := ss0<<7 | ss0>>(32-7)
			ss2 := ss1 ^ (a<<12 | a>>(32-12))
			tt1 := a ^ b ^ c + d + ss2 + (w[j] ^ w[j+4])
			tt2 := e ^ f ^ g + h + ss1 + w[j]
			d = c
			c = b<<9 | b>>(32-9)
			b = a
			a = tt1
			h = g
			g = f<<19 | f>>(32-19)
			f = e
			e = tt2 ^ (tt2<<9 | tt2>>(32-9)) ^ (tt2<<17 | tt2>>(32-17))
		}

		for ; j < 64; j++ {
			ss0 := (a<<12 | a>>(32-12)) + e + _K[j]
			ss1 := ss0<<7 | ss0>>(32-7)
			ss2 := ss1 ^ (a<<12 | a>>(32-12))
			tt1 := ((a | b) & (a | c) & (b | c)) + d + ss2 + (w[j] ^ w[j+4])
			tt2 := ((e & f) | ((^e) & g)) + h + ss1 + w[j]
			d = c
			c = b<<9 | b>>(32-9)
			b = a
			a = tt1
			h = g
			g = f<<19 | f>>(32-19)
			f = e
			e = tt2 ^ (tt2<<9 | tt2>>(32-9)) ^ (tt2<<17 | tt2>>(32-17))
		}

		h0 ^= a
		h1 ^= b
		h2 ^= c
		h3 ^= d
		h4 ^= e
		h5 ^= f
		h6 ^= g
		h7 ^= h

		p = p[chunk:]
	}

	dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4], dig.h[5], dig.h[6], dig.h[7] = h0, h1, h2, h3, h4, h5, h6, h7
}
