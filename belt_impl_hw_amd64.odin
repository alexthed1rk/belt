#+build amd64
package belt

/* STB 34.101.31-2020                                    */
/* Information technology and security                   */
/* Encryption and integrity control algorithms           */
/* https://apmi.bsu.by/assets/files/std/belt-spec371.pdf */

import "base:intrinsics"
import "core:simd/x86"
import "core:sys/info"

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
gf128mul :: proc "contextless" (a, b: x86.__m128i) -> x86.__m128i {
	temp0, temp1, temp2, temp3, temp4: x86.__m128i
	temp5, temp6, temp7, temp8, temp9: x86.__m128i
	mask := x86._mm_setr_epi32(-1, 0, 0, 0)
	temp0 = x86._mm_clmulepi64_si128(a, b, 0x00)
	temp3 = x86._mm_clmulepi64_si128(a, b, 0x11)
	temp1 = x86._mm_shuffle_epi32(a, 78)
	temp2 = x86._mm_shuffle_epi32(b, 78)
	temp1 = x86._mm_xor_si128(temp1, a)
	temp2 = x86._mm_xor_si128(temp2, b)
	temp1 = x86._mm_clmulepi64_si128(temp1, temp2, 0x00)
	temp1 = x86._mm_xor_si128(temp1, temp0)
	temp1 = x86._mm_xor_si128(temp1, temp3)
	temp2 = x86._mm_slli_si128(temp1, 8)
	temp1 = x86._mm_srli_si128(temp1, 8)
	temp0 = x86._mm_xor_si128(temp0, temp2)
	temp3 = x86._mm_xor_si128(temp3, temp1)
	temp4 = x86._mm_srli_epi32(temp3, 31)
	temp5 = x86._mm_srli_epi32(temp3, 30)
	temp6 = x86._mm_srli_epi32(temp3, 25)
	temp4 = x86._mm_xor_si128(temp4, temp5)
	temp4 = x86._mm_xor_si128(temp4, temp6)
	temp5 = x86._mm_shuffle_epi32(temp4, 147)
	temp4 = x86._mm_and_si128(mask, temp5)
	temp5 = x86._mm_andnot_si128(mask, temp5)
	temp0 = x86._mm_xor_si128(temp0, temp5)
	temp3 = x86._mm_xor_si128(temp3, temp4)
	temp7 = x86._mm_slli_epi32(temp3, 1)
	temp0 = x86._mm_xor_si128(temp0, temp7)
	temp8 = x86._mm_slli_epi32(temp3, 2)
	temp0 = x86._mm_xor_si128(temp0, temp8)
	temp9 = x86._mm_slli_epi32(temp3, 7)
	temp0 = x86._mm_xor_si128(temp0, temp9)
	return x86._mm_xor_si128(temp0, temp3)
}

@(private = "package")
mul_block :: proc "contextless" (dst, src: []byte) {
	assert_contextless(len(dst) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DST size")
	assert_contextless(len(src) == BLOCK_SIZE_128_U8, "crypto/belt: invalid SRC size")

	if is_hardware_accelerated() {
		dst_m128i := intrinsics.unaligned_load((^x86.__m128i)(raw_data(dst)))
		src_m128i := intrinsics.unaligned_load((^x86.__m128i)(raw_data(src)))
		dst_m128i  = gf128mul(dst_m128i, src_m128i)
		intrinsics.unaligned_store((^x86.__m128i)(raw_data(dst)), dst_m128i)
	} else {
		ensure_contextless(false, "crypto/belt: hardware is not supported")
	}
}
