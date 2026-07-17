#+build arm64
package belt

/* STB 34.101.31-2020                                    */
/* Information technology and security                   */
/* Encryption and integrity control algorithms           */
/* https://apmi.bsu.by/assets/files/std/belt-spec371.pdf */

import "base:intrinsics"
import "core:simd"
import "core:sys/info"

is_hardware_accelerated :: proc "contextless" () -> bool {
	req_features :: info.CPU_Features{
		.asimd,
		.aes,
		.pmull,
	}
	return info.cpu_features() >= req_features
}

poly64x2_t :: simd.u64x2
poly64_t   :: u64
poly128_t  :: simd.u8x16

/* Alternative to _mm_clmulepi64_si128(a, b, 0x00) */
@(require_results, enable_target_feature = "neon,aes")
simd_vmull_low_p64 :: #force_inline proc "c" (a, b: simd.u32x4) -> simd.u32x4 {
	return transmute(simd.u32x4)vmull_p64(vget_low_p64(transmute(poly64x2_t)a), vget_low_p64(transmute(poly64x2_t)b))
}

/* Alternative to _mm_clmulepi64_si128(a, b, 0x11) */
@(require_results, enable_target_feature = "neon,aes")
simd_vmull_high_p64 :: #force_inline proc "c" (a, b: simd.u32x4) -> simd.u32x4 {
	return transmute(simd.u32x4)vmull_p64(vget_high_p64(transmute(poly64x2_t)a), vget_high_p64(transmute(poly64x2_t)b))
}

/* Polynomial multiply long */
/* [Arm's documentation](https://developer.arm.com/architectures/instruction-sets/intrinsics/vmull_p64) */
@(require_results, enable_target_feature = "neon,aes")
vmull_p64 :: #force_inline proc "c" (a, b: poly64_t) -> poly128_t {
	return _vmull_p64(a, b)
}

/* Duplicate vector element to vector or scalar */
/* [Arm's documentation](https://developer.arm.com/architectures/instruction-sets/intrinsics/vget_low_p64) */
@(require_results, enable_target_feature = "neon")
vget_low_p64 :: #force_inline proc "c" (a: poly64x2_t) -> poly64_t {
	when ODIN_ENDIAN == .Little {
		return simd.extract(a, 0)
	} else {
		return simd.extract(simd.swizzle(a, 1, 0), 0)
	}
}

/* Duplicate vector element to vector or scalar */
/* [Arm's documentation](https://developer.arm.com/architectures/instruction-sets/intrinsics/vget_high_p64) */
@(require_results, enable_target_feature = "neon")
vget_high_p64 :: #force_inline proc "c" (a: poly64x2_t) -> poly64_t {
	when ODIN_ENDIAN == .Little {
		return simd.extract(a, 1)
	} else {
		return simd.extract(simd.swizzle(a, 1, 0), 1)
	}
}

@(private, default_calling_convention = "none")
foreign _ {
	@(link_name = "llvm.aarch64.neon.pmull64")
	_vmull_p64 :: proc (a, b: poly64_t) -> poly128_t ---
}

/* Intel Carry-Less Multiplication Instruction */
/* and its Usage for Computing the GCM Mode    */
@(require_results, enable_target_feature="neon,aes")
gf128mul :: proc "contextless" (a, b: simd.u32x4) -> simd.u32x4 {
	temp0, temp1, temp2, temp3, temp4: simd.u32x4
	temp5, temp6, temp7, temp8, temp9: simd.u32x4
	mask := simd.u32x4 {max(u32), 0, 0, 0}
	temp0 = simd_vmull_low_p64(a, b)
	temp3 = simd_vmull_high_p64(a, b)
	temp1 = simd.swizzle(a, 2, 3, 0, 1)
	temp2 = simd.swizzle(b, 2, 3, 0, 1)
	temp1 = simd.bit_xor(temp1, a)
	temp2 = simd.bit_xor(temp2, b)
	temp1 = simd_vmull_low_p64(temp1, temp2)
	temp1 = simd.bit_xor(temp1, temp0)
	temp1 = simd.bit_xor(temp1, temp3)
	temp2 = simd.shuffle(temp1, simd.u32x4{}, 4, 5, 0, 1)
	temp1 = simd.shuffle(simd.u32x4{}, temp1, 6, 7, 0, 1)
	temp0 = simd.bit_xor(temp0, temp2)
	temp3 = simd.bit_xor(temp3, temp1)
	temp4 = simd.shr(temp3, 31)
	temp5 = simd.shr(temp3, 30)
	temp6 = simd.shr(temp3, 25)
	temp4 = simd.bit_xor(temp4, temp5)
	temp4 = simd.bit_xor(temp4, temp6)
	temp5 = simd.swizzle(temp4, 3, 0, 1, 2)
	temp4 = simd.bit_and(mask, temp5)
	temp5 = simd.bit_and_not(temp5, mask)
	temp0 = simd.bit_xor(temp0, temp5)
	temp3 = simd.bit_xor(temp3, temp4)
	temp7 = simd.shl(temp3, 1)
	temp0 = simd.bit_xor(temp0, temp7)
	temp8 = simd.shl(temp3, 2)
	temp0 = simd.bit_xor(temp0, temp8)
	temp9 = simd.shl(temp3, 7)
	temp0 = simd.bit_xor(temp0, temp9)
	return simd.bit_xor(temp0, temp3)
}

@(private = "package")
mul_block :: proc "contextless" (dst, src: []byte) {
	assert_contextless(len(dst) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DST size")
	assert_contextless(len(src) == BLOCK_SIZE_128_U8, "crypto/belt: invalid SRC size")

	when ODIN_ENDIAN == .Little {
		if is_hardware_accelerated() {
			dst_u32x4 := intrinsics.unaligned_load((^simd.u32x4)(raw_data(dst)))
			src_u32x4 := intrinsics.unaligned_load((^simd.u32x4)(raw_data(src)))
			dst_u32x4  = gf128mul(dst_u32x4, src_u32x4)
			intrinsics.unaligned_store((^simd.u32x4)(raw_data(dst)), dst_u32x4)
		} else {
			ensure_contextless(false, "crypto/belt: hardware is not supported")
		}
	} else {
		ensure_contextless(false, "crypto/belt: hardware is not supported")
	}
}
