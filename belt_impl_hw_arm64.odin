#+build arm64
package belt

/* STB 34.101.31-2020                                    */
/* Information technology and security                   */
/* Encryption and integrity control algorithms           */
/* https://apmi.bsu.by/assets/files/std/belt-spec371.pdf */

import "core:simd"
import "core:sys/info"

Simd_Block128 :: simd.u32x4
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
simd_clmul_low :: #force_inline proc "c" (a, b: simd.u32x4) -> simd.u32x4 {
	return transmute(simd.u32x4)vmull_p64(vget_low_p64(transmute(poly64x2_t)a), vget_low_p64(transmute(poly64x2_t)b))
}

/* Alternative to _mm_clmulepi64_si128(a, b, 0x11) */
@(require_results, enable_target_feature = "neon,aes")
simd_clmul_high :: #force_inline proc "c" (a, b: simd.u32x4) -> simd.u32x4 {
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
gf128mulhw :: proc "contextless" (a, b: simd.u32x4) -> simd.u32x4 {
	block0, block1, block2, block3, block4: simd.u32x4
	block5, block6, block7, block8, block9: simd.u32x4
	mask := simd.u32x4 {max(u32), 0, 0, 0}
	block0 = simd_clmul_low(a, b)
	block3 = simd_clmul_high(a, b)
	block1 = simd.swizzle(a, 2, 3, 0, 1)
	block2 = simd.swizzle(b, 2, 3, 0, 1)
	block1 = simd.bit_xor(block1, a)
	block2 = simd.bit_xor(block2, b)
	block1 = simd_clmul_low(block1, block2)
	block1 = simd.bit_xor(block1, block0)
	block1 = simd.bit_xor(block1, block3)
	block2 = simd.shuffle(block1, simd.u32x4{}, 4, 5, 0, 1)
	block1 = simd.shuffle(simd.u32x4{}, block1, 6, 7, 0, 1)
	block0 = simd.bit_xor(block0, block2)
	block3 = simd.bit_xor(block3, block1)
	block4 = simd.shr(block3, 31)
	block5 = simd.shr(block3, 30)
	block6 = simd.shr(block3, 25)
	block4 = simd.bit_xor(block4, block5)
	block4 = simd.bit_xor(block4, block6)
	block5 = simd.swizzle(block4, 3, 0, 1, 2)
	block4 = simd.bit_and(mask, block5)
	block5 = simd.bit_and_not(block5, mask)
	block0 = simd.bit_xor(block0, block5)
	block3 = simd.bit_xor(block3, block4)
	block7 = simd.shl(block3, 1)
	block0 = simd.bit_xor(block0, block7)
	block8 = simd.shl(block3, 2)
	block0 = simd.bit_xor(block0, block8)
	block9 = simd.shl(block3, 7)
	block0 = simd.bit_xor(block0, block9)
	return simd.bit_xor(block0, block3)
}
