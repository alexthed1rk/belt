#+build amd64
package belt

/* STB 34.101.31-2020                                    */
/* Information technology and security                   */
/* Encryption and integrity control algorithms           */
/* https://apmi.bsu.by/assets/files/std/belt-spec371.pdf */

import "core:simd/x86"
import "core:sys/info"

Simd_Block128 :: x86.__m128i
is_hardware_accelerated :: proc "contextless" () -> bool {
	req_features :: info.CPU_Features{
		.pclmulqdq,
		.sse2,
	}
	return info.cpu_features() >= req_features
}

/* Intel Carry-Less Multiplication Instruction */
/* and its Usage for Computing the GCM Mode    */
@(require_results, enable_target_feature="sse2,pclmul")
gf128mulhw :: proc "contextless" (a, b: x86.__m128i) -> x86.__m128i {
	block0, block1, block2, block3, block4: x86.__m128i
	block5, block6, block7, block8, block9: x86.__m128i
	mask := x86._mm_setr_epi32(-1, 0, 0, 0)
	block0 = x86._mm_clmulepi64_si128(a, b, 0x00)
	block3 = x86._mm_clmulepi64_si128(a, b, 0x11)
	block1 = x86._mm_shuffle_epi32(a, 78)
	block2 = x86._mm_shuffle_epi32(b, 78)
	block1 = x86._mm_xor_si128(block1, a)
	block2 = x86._mm_xor_si128(block2, b)
	block1 = x86._mm_clmulepi64_si128(block1, block2, 0x00)
	block1 = x86._mm_xor_si128(block1, block0)
	block1 = x86._mm_xor_si128(block1, block3)
	block2 = x86._mm_slli_si128(block1, 8)
	block1 = x86._mm_srli_si128(block1, 8)
	block0 = x86._mm_xor_si128(block0, block2)
	block3 = x86._mm_xor_si128(block3, block1)
	block4 = x86._mm_srli_epi32(block3, 31)
	block5 = x86._mm_srli_epi32(block3, 30)
	block6 = x86._mm_srli_epi32(block3, 25)
	block4 = x86._mm_xor_si128(block4, block5)
	block4 = x86._mm_xor_si128(block4, block6)
	block5 = x86._mm_shuffle_epi32(block4, 147)
	block4 = x86._mm_and_si128(mask, block5)
	block5 = x86._mm_andnot_si128(mask, block5)
	block0 = x86._mm_xor_si128(block0, block5)
	block3 = x86._mm_xor_si128(block3, block4)
	block7 = x86._mm_slli_epi32(block3, 1)
	block0 = x86._mm_xor_si128(block0, block7)
	block8 = x86._mm_slli_epi32(block3, 2)
	block0 = x86._mm_xor_si128(block0, block8)
	block9 = x86._mm_slli_epi32(block3, 7)
	block0 = x86._mm_xor_si128(block0, block9)
	return x86._mm_xor_si128(block0, block3)
}
