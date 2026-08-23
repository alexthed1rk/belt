#+build arm64
package belt

/* STB 34.101.31-2020                                    */
/* Information technology and security                   */
/* Encryption and integrity control algorithms           */
/* https://apmi.bsu.by/assets/files/std/belt-spec371.pdf */

import "base:intrinsics"
import "base:runtime"
import "core:simd"
import "core:simd/arm"
import "core:sys/info"

is_hardware_accelerated :: proc "contextless" () -> bool {
	req_features :: info.CPU_Features{
		.asimd,
		.aes,
		.pmull,
	}
	return ODIN_ENDIAN == .Little && info.cpu_features() >= req_features
}

@(require_results, private = "file", enable_target_feature = "neon,aes")
arm_vmull_low_p64 :: #force_inline proc "c" (a, b: arm.uint32x4_t) -> arm.uint32x4_t {
	a := arm.vgetq_lane_p64(transmute(arm.poly64x2_t)a, 0)
	b := arm.vgetq_lane_p64(transmute(arm.poly64x2_t)b, 0)
	return transmute(arm.uint32x4_t)arm.vmull_p64(a, b)
}

@(require_results, private = "file", enable_target_feature = "neon,aes")
arm_vmull_high_p64 :: #force_inline proc "c" (a, b: arm.uint32x4_t) -> arm.uint32x4_t {
	a := arm.vgetq_lane_p64(transmute(arm.poly64x2_t)a, 1)
	b := arm.vgetq_lane_p64(transmute(arm.poly64x2_t)b, 1)
	return transmute(arm.uint32x4_t)arm.vmull_p64(a, b)
}

/* Intel Carry-Less Multiplication Instruction */
/* and its Usage for Computing the GCM Mode    */
@(require_results, private = "file", enable_target_feature="neon,aes")
gf128mul_raw_hw :: proc "contextless" (a, b: arm.uint32x4_t) -> arm.uint32x4_t {
	block0, block1, block2, block3, block4: arm.uint32x4_t
	block5, block6, block7, block8, block9: arm.uint32x4_t
	mask := arm.uint32x4_t {max(u32), 0, 0, 0}
	block0 = arm_vmull_low_p64(a, b)
	block3 = arm_vmull_high_p64(a, b)
	block1 = simd.swizzle(a, 2, 3, 0, 1)
	block2 = simd.swizzle(b, 2, 3, 0, 1)
	block1 = arm.veorq_u32(block1, a)
	block2 = arm.veorq_u32(block2, b)
	block1 = arm_vmull_low_p64(block1, block2)
	block1 = arm.veorq_u32(block1, block0)
	block1 = arm.veorq_u32(block1, block3)
	block2 = simd.shuffle(block1, arm.uint32x4_t{}, 4, 5, 0, 1)
	block1 = simd.shuffle(arm.uint32x4_t{}, block1, 6, 7, 0, 1)
	block0 = arm.veorq_u32(block0, block2)
	block3 = arm.veorq_u32(block3, block1)
	block4 = simd.shr(block3, 31)
	block5 = simd.shr(block3, 30)
	block6 = simd.shr(block3, 25)
	block4 = arm.veorq_u32(block4, block5)
	block4 = arm.veorq_u32(block4, block6)
	block5 = simd.swizzle(block4, 3, 0, 1, 2)
	block4 = arm.vandq_u32(mask, block5)
	block5 = arm.vbicq_u32(block5, mask)
	block0 = arm.veorq_u32(block0, block5)
	block3 = arm.veorq_u32(block3, block4)
	block7 = simd.shl(block3, 1)
	block0 = arm.veorq_u32(block0, block7)
	block8 = simd.shl(block3, 2)
	block0 = arm.veorq_u32(block0, block8)
	block9 = simd.shl(block3, 7)
	block0 = arm.veorq_u32(block0, block9)
	return arm.veorq_u32(block0, block3)
}

@(private = "package", enable_target_feature="neon,aes")
gf128mul_hw :: proc "contextless" (dst, src: []byte) #no_bounds_check {
	assert_contextless(len(dst) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DST size")
	assert_contextless(len(src) == BLOCK_SIZE_128_U8, "crypto/belt: invalid SRC size")

	block1: arm.uint32x4_t = ---
	block2: arm.uint32x4_t = ---

	intrinsics.mem_copy_non_overlapping(
		&block1,
		raw_data(dst),
		BLOCK_SIZE_128_U8,
	)

	intrinsics.mem_copy_non_overlapping(
		&block2,
		raw_data(src),
		BLOCK_SIZE_128_U8,
	)

	block1 = gf128mul_raw_hw(block1, block2)
	intrinsics.mem_copy_non_overlapping(
		raw_data(dst),
		&block1,
		BLOCK_SIZE_128_U8,
	)
}

/* Block cipher: belt-encrypt-block */
@(enable_target_feature="neon")
encrypt_block_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	assert_contextless(len(data) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	stream: arm.uint32x4_t
	intrinsics.mem_copy_non_overlapping(
		&stream,
		raw_data(data),
		BLOCK_SIZE_128_U8,
	)

	stream = encrypt_block_raw_hw(ctx, stream)
	intrinsics.mem_copy_non_overlapping(
		raw_data(data),
		&stream,
		BLOCK_SIZE_128_U8,
	)
}

@(require_results, private = "file", enable_target_feature="neon")
encrypt_block_raw_hw :: proc "contextless" (ctx: Context, block: arm.uint32x4_t) -> arm.uint32x4_t #no_bounds_check {
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_block_ := block
	stream: Block128_U32

	a :: 0; b :: 1; c :: 2; d :: 3
	#unroll for round in 0..<8 {
		stream = transmute(Block128_U32)_block_

		stream[b] ~= table_g05(stream[a] + ctx.key[7 * round])
		stream[c] ~= table_g21(stream[d] + ctx.key[7 * round + 1])
		stream[a] -= table_g13(stream[b] + ctx.key[7 * round + 2])

		stream[c] += stream[b]
		stream[b] += table_g21(stream[c] + ctx.key[7 * round + 3]) ~ u32(1 + round)
		stream[c] -= stream[b]

		stream[d] += table_g13(stream[c] + ctx.key[7 * round + 4])
		stream[b] ~= table_g21(stream[a] + ctx.key[7 * round + 5])
		stream[c] ~= table_g05(stream[d] + ctx.key[7 * round + 6])

		_block_ = transmute(arm.uint32x4_t)stream
		_block_ = simd.shuffle(_block_, _block_, 1, 3, 0, 2)
	}

	return simd.shuffle(_block_, _block_, 1, 3, 0, 2)
}

/* Block cipher: belt-decrypt-block */
@(enable_target_feature="neon")
decrypt_block_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	assert_contextless(len(data) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	stream: arm.uint32x4_t
	intrinsics.mem_copy_non_overlapping(
		&stream,
		raw_data(data),
		BLOCK_SIZE_128_U8,
	)

	stream = decrypt_block_raw_hw(ctx, stream)
	intrinsics.mem_copy_non_overlapping(
		raw_data(data),
		&stream,
		BLOCK_SIZE_128_U8,
	)
}

@(require_results, private = "file", enable_target_feature="neon")
decrypt_block_raw_hw :: proc "contextless" (ctx: Context, block: arm.uint32x4_t) -> arm.uint32x4_t #no_bounds_check {
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_block_ := block
	stream: Block128_U32

	a :: 0; b :: 1; c :: 2; d :: 3
	#unroll for round in 0..<8 {
		stream = transmute(Block128_U32)_block_

		stream[b] ~= table_g05(stream[a] + ctx.key[55 - 7 * round])
		stream[c] ~= table_g21(stream[d] + ctx.key[54 - 7 * round])
		stream[a] -= table_g13(stream[b] + ctx.key[53 - 7 * round])

		stream[c] += stream[b]
		stream[b] += table_g21(stream[c] + ctx.key[52 - 7 * round]) ~ u32(8 - round)
		stream[c] -= stream[b]

		stream[d] += table_g13(stream[c] + ctx.key[51 - 7 * round])
		stream[b] ~= table_g21(stream[a] + ctx.key[50 - 7 * round])
		stream[c] ~= table_g05(stream[d] + ctx.key[49 - 7 * round])

		_block_ = transmute(arm.uint32x4_t)stream
		_block_ = simd.shuffle(_block_, _block_, 2, 0, 3, 1)
	}

	return simd.shuffle(_block_, _block_, 2, 0, 3, 1)
}

/* Wide block cipher: belt-encrypt-wide-block */
@(enable_target_feature="neon")
encrypt_wide_block_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	data_size := len(data)

	assert_contextless(data_size >= BLOCK_SIZE_256_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_stream_: arm.uint32x4_t

	block1: arm.uint32x4_t = ---
	block2: arm.uint32x4_t = ---

	num_rounds := 2 * ((uint(data_size) + BLOCK_SIZE_128_U8 - 1) / BLOCK_SIZE_128_U8)
	for round := uint(1); round <= num_rounds; round += 1 {

		stream := data
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block1 = _stream_
		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size := data_size - BLOCK_SIZE_128_U8

		for stream_size > BLOCK_SIZE_128_U8 {
			intrinsics.mem_copy_non_overlapping(
				&_stream_,
				raw_data(stream),
				BLOCK_SIZE_128_U8,
			)

			block1 = arm.veorq_u32(block1, _stream_)

			stream = stream[BLOCK_SIZE_128_U8:]
			stream_size -= BLOCK_SIZE_128_U8
		}

		intrinsics.mem_copy(
			raw_data(data),
			raw_data(data[BLOCK_SIZE_128_U8:]),
			data_size - BLOCK_SIZE_128_U8,
		)

		stream = data[data_size - BLOCK_SIZE_128_U8:]
		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block1,
			BLOCK_SIZE_128_U8,
		)

		stream = data[data_size - BLOCK_SIZE_256_U8: data_size - BLOCK_SIZE_128_U8]
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block1 = encrypt_block_raw_hw(ctx, block1)
		block2 = transmute(arm.uint32x4_t)u128(round)

		block1 = arm.veorq_u32(block1, block2)
		block1 = arm.veorq_u32(block1, _stream_)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block1,
			BLOCK_SIZE_128_U8,
		)
	}
}

/* Wide block cipher: belt-decrypt-wide-block */
@(enable_target_feature="neon")
decrypt_wide_block_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	data_size := len(data)

	assert_contextless(data_size >= BLOCK_SIZE_256_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_stream_: arm.uint32x4_t

	block1: arm.uint32x4_t = ---
	block2: arm.uint32x4_t = ---

	num_rounds := 2 * ((uint(data_size) + BLOCK_SIZE_128_U8 - 1) / BLOCK_SIZE_128_U8)
	for round := num_rounds; round >= 1; round -= 1 {

		stream := data[data_size - BLOCK_SIZE_128_U8:]
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		intrinsics.mem_copy(
			raw_data(data[BLOCK_SIZE_128_U8:]),
			raw_data(data),
			data_size - BLOCK_SIZE_128_U8,
		)

		block1 = encrypt_block_raw_hw(ctx, _stream_)
		block2 = transmute(arm.uint32x4_t)u128(round)
		block1 = arm.veorq_u32(block1, block2)

		stream = data[data_size - BLOCK_SIZE_128_U8:]
		intrinsics.mem_copy_non_overlapping(
			&block2,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block2 = arm.veorq_u32(block2, block1)
		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block2,
			BLOCK_SIZE_128_U8,
		)

		stream = data[BLOCK_SIZE_128_U8:]
		stream_size := data_size - BLOCK_SIZE_128_U8
		for stream_size > BLOCK_SIZE_128_U8 {
			intrinsics.mem_copy_non_overlapping(
				&block1,
				raw_data(stream),
				BLOCK_SIZE_128_U8,
			)

			_stream_ = arm.veorq_u32(_stream_, block1)

			stream = stream[BLOCK_SIZE_128_U8:]
			stream_size -= BLOCK_SIZE_128_U8
		}

		stream = data
		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&_stream_,
			BLOCK_SIZE_128_U8,
		)
	}
}

/* Electronic codebook encryption: belt-encrypt-ecb */
@(enable_target_feature="neon")
encrypt_ecb_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(data_size >= BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		encrypt_block_hw(ctx, stream[:BLOCK_SIZE_128_U8])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		block: Block128_U8 = ---

		stream = data[data_size - stream_size - BLOCK_SIZE_128_U8:]

		intrinsics.mem_copy_non_overlapping(
			raw_data(block[:stream_size]),
			raw_data(stream[BLOCK_SIZE_128_U8:]),
			stream_size,
		)

		intrinsics.mem_copy_non_overlapping(
			raw_data(block[stream_size:]),
			raw_data(stream[stream_size: BLOCK_SIZE_128_U8]),
			BLOCK_SIZE_128_U8 - stream_size,
		)

		encrypt_block_hw(ctx, block[:])

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream[BLOCK_SIZE_128_U8:]),
			raw_data(stream[:stream_size]),
			stream_size,
		)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream[:BLOCK_SIZE_128_U8]),
			&block,
			BLOCK_SIZE_128_U8,
		)
	}
}

/* Electronic codebook encryption: belt-decrypt-ecb */
@(enable_target_feature="neon")
decrypt_ecb_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(data_size >= BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		decrypt_block_hw(ctx, stream[:BLOCK_SIZE_128_U8])

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		block: Block128_U8 = ---

		stream = data[data_size - stream_size - BLOCK_SIZE_128_U8:]

		intrinsics.mem_copy_non_overlapping(
			raw_data(block[:stream_size]),
			raw_data(stream[BLOCK_SIZE_128_U8:]),
			stream_size,
		)

		intrinsics.mem_copy_non_overlapping(
			raw_data(block[stream_size:]),
			raw_data(stream[stream_size: BLOCK_SIZE_128_U8]),
			BLOCK_SIZE_128_U8 - stream_size,
		)

		decrypt_block_hw(ctx, block[:])

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream[BLOCK_SIZE_128_U8:]),
			raw_data(stream[:stream_size]),
			stream_size,
		)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream[:BLOCK_SIZE_128_U8]),
			&block,
			BLOCK_SIZE_128_U8,
		)
	}
}

/* Cipher block chaining encryption: belt-encrypt-cbc */
@(enable_target_feature="neon")
encrypt_cbc_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size >= BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_stream_: arm.uint32x4_t

	block: arm.uint32x4_t = ---

	intrinsics.mem_copy_non_overlapping(
		&block,
		raw_data(iv),
		BLOCK_SIZE_128_U8,
	)

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block = arm.veorq_u32(block, _stream_)
		block = encrypt_block_raw_hw(ctx, block)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block,
			BLOCK_SIZE_128_U8,
		)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		_bytes_: Block128_U8
		_stream_ = arm.uint32x4_t{}

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			stream_size,
		)

		block = arm.veorq_u32(block, _stream_)

		intrinsics.mem_copy_non_overlapping(
			&_bytes_,
			&block,
			stream_size,
		)

		stream = data[data_size - stream_size - BLOCK_SIZE_128_U8:]
		intrinsics.mem_copy_non_overlapping(
			raw_data(_bytes_[stream_size:]),
			raw_data(stream[stream_size: BLOCK_SIZE_128_U8]),
			BLOCK_SIZE_128_U8 - stream_size,
		)

		encrypt_block_hw(ctx, _bytes_[:])

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream[BLOCK_SIZE_128_U8:]),
			raw_data(stream),
			stream_size,
		)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&_bytes_,
			BLOCK_SIZE_128_U8,
		)
	}
}

/* Cipher block chaining encryption: belt-decrypt-cbc */
@(enable_target_feature="neon")
decrypt_cbc_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size >= BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_stream_: arm.uint32x4_t

	block1: arm.uint32x4_t = ---
	block2: arm.uint32x4_t = ---

	intrinsics.mem_copy_non_overlapping(
		&block2,
		raw_data(iv),
		BLOCK_SIZE_128_U8,
	)

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_256_U8 || stream_size == BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block1 = decrypt_block_raw_hw(ctx, _stream_)
		block1 = arm.veorq_u32(block1, block2)
		block2 = _stream_

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block1,
			BLOCK_SIZE_128_U8,
		)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		_bytes_: Block128_U8
		_stream_ = arm.uint32x4_t{}

		intrinsics.mem_copy_non_overlapping(
			&_bytes_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		decrypt_block_hw(ctx, _bytes_[:])

		intrinsics.mem_copy_non_overlapping(
			&block1,
			&_bytes_,
			stream_size - BLOCK_SIZE_128_U8,
		)

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream[BLOCK_SIZE_128_U8: stream_size]),
			stream_size - BLOCK_SIZE_128_U8,
		)

		block1 = arm.veorq_u32(block1, _stream_)
		_stream_ = arm.veorq_u32(_stream_, block1)
		block1 = arm.veorq_u32(block1, _stream_)
		_stream_ = arm.veorq_u32(_stream_, block1)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream[BLOCK_SIZE_128_U8: stream_size]),
			&_stream_,
			stream_size - BLOCK_SIZE_128_U8,
		)

		intrinsics.mem_copy_non_overlapping(
			&_bytes_,
			&block1,
			stream_size - BLOCK_SIZE_128_U8,
		)

		intrinsics.mem_copy_non_overlapping(
			&block1,
			&_bytes_,
			BLOCK_SIZE_128_U8,
		)

		block1 = decrypt_block_raw_hw(ctx, block1)
		block1 = arm.veorq_u32(block1, block2)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block1,
			BLOCK_SIZE_128_U8,
		)
	}
}

/* Cipher feedback encryption: belt-encrypt-cfb */
@(enable_target_feature="neon")
encrypt_cfb_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_stream_: arm.uint32x4_t

	block: arm.uint32x4_t = ---

	intrinsics.mem_copy_non_overlapping(
		&block,
		raw_data(iv),
		BLOCK_SIZE_128_U8,
	)

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block = encrypt_block_raw_hw(ctx, block)
		block = arm.veorq_u32(block, _stream_)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block,
			BLOCK_SIZE_128_U8,
		)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		_stream_ = arm.uint32x4_t{}

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			stream_size,
		)

		block = encrypt_block_raw_hw(ctx, block)
		block = arm.veorq_u32(block, _stream_)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block,
			stream_size,
		)
	}
}

/* Cipher feedback encryption: belt-decrypt-cfb */
@(enable_target_feature="neon")
decrypt_cfb_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_stream_: arm.uint32x4_t

	block: arm.uint32x4_t = ---

	intrinsics.mem_copy_non_overlapping(
		&block,
		raw_data(iv),
		BLOCK_SIZE_128_U8,
	)

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block = encrypt_block_raw_hw(ctx, block)
		block = arm.veorq_u32(block, _stream_)

		_stream_ = arm.veorq_u32(_stream_, block)
		block = arm.veorq_u32(block, _stream_)
		_stream_ = arm.veorq_u32(_stream_, block)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&_stream_,
			BLOCK_SIZE_128_U8,
		)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		_stream_ = arm.uint32x4_t{}

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			stream_size,
		)

		block = encrypt_block_raw_hw(ctx, block)
		block = arm.veorq_u32(block, _stream_)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block,
			stream_size,
		)
	}
}

/* Counter encryption: belt-encrypt-ctr */
@(enable_target_feature="neon")
encrypt_ctr_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_stream_: arm.uint32x4_t

	block1: arm.uint32x4_t = ---
	block2: arm.uint32x4_t = ---

	intrinsics.mem_copy_non_overlapping(
		&block2,
		raw_data(iv),
		BLOCK_SIZE_128_U8,
	)

	block2 = encrypt_block_raw_hw(ctx, block2)

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block2 = transmute(arm.uint32x4_t)(transmute(u128)block2 + 1)
		block1 = encrypt_block_raw_hw(ctx, block2)
		block1 = arm.veorq_u32(block1, _stream_)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block1,
			BLOCK_SIZE_128_U8,
		)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		_stream_ = arm.uint32x4_t{}

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			stream_size,
		)

		block2 = transmute(arm.uint32x4_t)(transmute(u128)block2 + 1)
		block1 = encrypt_block_raw_hw(ctx, block2)
		block1 = arm.veorq_u32(block1, _stream_)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block1,
			stream_size,
		)
	}
}

/* Counter encryption: belt-decrypt-ctr */
decrypt_ctr_hw :: encrypt_ctr_hw

@(require_results, private = "file", enable_target_feature="neon")
table_φ1_hw :: #force_inline proc "contextless" (data: arm.uint32x4_t) -> arm.uint32x4_t {
	block1, block2: arm.uint32x4_t
	block1 = simd.shuffle(data, data, 1, 2, 3, 0)
	block2 = simd.shuffle(block1, arm.uint32x4_t{}, 4, 5, 6, 0)
	return arm.veorq_u32(block1, block2)
}

@(require_results, private = "file", enable_target_feature="neon")
table_φ2_hw :: #force_inline proc "contextless" (data: arm.uint32x4_t) -> arm.uint32x4_t {
	block1, block2: arm.uint32x4_t
	block1 = simd.shuffle(data, data, 3, 0, 1, 2)
	block2 = arm.uint32x4_t {max(u32), 0, 0, 0}
	block2 = arm.vandq_u32(data, block2)
	return arm.veorq_u32(block1, block2)
}

/* Message authentication code derivation: belt-derive-mac */
@(enable_target_feature="neon")
derive_mac_hw :: proc "contextless" (ctx: Context, mac, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(mac) == MAC_SIZE_64_U8, "crypto/belt: invalid MAC size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_bytes_: Block128_U8
	_stream_: arm.uint32x4_t

	block1: arm.uint32x4_t
	block2: arm.uint32x4_t

	stream := data
	stream_size := data_size

	block1 = encrypt_block_raw_hw(ctx, block1)
	for stream_size > BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block2 = arm.veorq_u32(block2, _stream_)
		block2 = encrypt_block_raw_hw(ctx, block2)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size == BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block1 = table_φ1_hw(block1)
		block2 = arm.veorq_u32(block2, block1)
		block2 = arm.veorq_u32(block2, _stream_)
	} else {
		intrinsics.mem_copy_non_overlapping(
			&_bytes_,
			raw_data(stream),
			stream_size,
		)

		ψ_unit :: 0x80
		_bytes_[stream_size] = ψ_unit
		_stream_ = transmute(arm.uint32x4_t)_bytes_

		block1 = table_φ2_hw(block1)
		block2 = arm.veorq_u32(block2, block1)
		block2 = arm.veorq_u32(block2, _stream_)
	}

	block2 = encrypt_block_raw_hw(ctx, block2)
	_bytes_ = transmute(Block128_U8)block2

	intrinsics.mem_copy_non_overlapping(
		raw_data(mac),
		&_bytes_,
		MAC_SIZE_64_U8,
	)
}

/* Authenticated encryption: belt-seal-dwp */
@(enable_target_feature="neon,aes")
seal_dwp_hw :: proc "contextless" (ctx: Context, iv, aad, mac, data: []byte) #no_bounds_check {
	data_size := len(data); aad_size := len(aad); mac_size := len(mac)

	ensure_contextless(mac_size != 0 && mac_size <= MAC_SIZE_64_U8, "crypto/belt: invalid MAC size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")

	_stream_: arm.uint32x4_t

	block1: arm.uint32x4_t = ---
	block2: arm.uint32x4_t = ---
	block3: arm.uint32x4_t = ---
	block4: arm.uint32x4_t = ---
	block5: arm.uint32x4_t = ---

	modulus1 := u64((BITS_PER_BYTE * u128(aad_size))  & u128(max(u64)))
	modulus2 := u64((BITS_PER_BYTE * u128(data_size)) & u128(max(u64)))

	intrinsics.mem_copy_non_overlapping(
		&block3,
		raw_data(iv),
		BLOCK_SIZE_128_U8,
	)

	block4 = transmute(arm.uint32x4_t) arm.uint64x2_t {modulus1, modulus2}
	block5 = transmute(arm.uint32x4_t)BLOCK_T

	block3 = encrypt_block_raw_hw(ctx, block3)
	block2 = encrypt_block_raw_hw(ctx, block3)

	stream := aad
	stream_size := aad_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block5 = arm.veorq_u32(block5, _stream_)
		block5 = gf128mul_raw_hw(block5, block2)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		_stream_ = arm.uint32x4_t{}

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			stream_size,
		)

		block5 = arm.veorq_u32(block5, _stream_)
		block5 = gf128mul_raw_hw(block5, block2)
	}

	stream = data
	stream_size = data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&block1,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block3 = transmute(arm.uint32x4_t)(transmute(u128)block3 + 1)
		_stream_ = encrypt_block_raw_hw(ctx, block3)
		_stream_ = arm.veorq_u32(_stream_, block1)

		block5 = arm.veorq_u32(block5, _stream_)
		block5 = gf128mul_raw_hw(block5, block2)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&_stream_,
			BLOCK_SIZE_128_U8,
		)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		block1 = arm.uint32x4_t{}

		intrinsics.mem_copy_non_overlapping(
			&block1,
			raw_data(stream),
			stream_size,
		)

		block3 = transmute(arm.uint32x4_t)(transmute(u128)block3 + 1)
		_stream_ = encrypt_block_raw_hw(ctx, block3)
		_stream_ = arm.veorq_u32(_stream_, block1)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&_stream_,
			stream_size,
		)

		_stream_ = arm.uint32x4_t{}

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			stream_size,
		)

		block5 = arm.veorq_u32(block5, _stream_)
		block5 = gf128mul_raw_hw(block5, block2)
	}

	block5 = arm.veorq_u32(block5, block4)
	block5 = gf128mul_raw_hw(block5, block2)
	block5 = encrypt_block_raw_hw(ctx, block5)

	intrinsics.mem_copy_non_overlapping(
		raw_data(mac),
		&block5,
		mac_size,
	)
}

/* Authenticated encryption: belt-open-dwp */
@(enable_target_feature="neon,aes")
open_dwp_hw :: proc "contextless" (ctx: Context, iv, aad, mac, data: []byte) -> bool #no_bounds_check {
	data_size := len(data); aad_size := len(aad); mac_size := len(mac)

	ensure_contextless(mac_size != 0 && mac_size <= MAC_SIZE_64_U8, "crypto/belt: invalid MAC size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")

	_stream_: arm.uint32x4_t

	block1: arm.uint32x4_t = ---
	block2: arm.uint32x4_t = ---
	block3: arm.uint32x4_t = ---
	block4: arm.uint32x4_t = ---
	block5: arm.uint32x4_t = ---

	modulus1 := u64((BITS_PER_BYTE * u128(aad_size))  & u128(max(u64)))
	modulus2 := u64((BITS_PER_BYTE * u128(data_size)) & u128(max(u64)))

	intrinsics.mem_copy_non_overlapping(
		&block3,
		raw_data(iv),
		BLOCK_SIZE_128_U8,
	)

	block4 = transmute(arm.uint32x4_t) arm.uint64x2_t {modulus1, modulus2}
	block5 = transmute(arm.uint32x4_t)BLOCK_T

	block3 = encrypt_block_raw_hw(ctx, block3)
	block2 = encrypt_block_raw_hw(ctx, block3)

	stream := aad
	stream_size := aad_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block5 = arm.veorq_u32(block5, _stream_)
		block5 = gf128mul_raw_hw(block5, block2)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		_stream_ = arm.uint32x4_t{}

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			stream_size,
		)

		block5 = arm.veorq_u32(block5, _stream_)
		block5 = gf128mul_raw_hw(block5, block2)
	}

	stream = data
	stream_size = data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block5 = arm.veorq_u32(block5, _stream_)
		block5 = gf128mul_raw_hw(block5, block2)

		block3 = transmute(arm.uint32x4_t)(transmute(u128)block3 + 1)
		block1 = encrypt_block_raw_hw(ctx, block3)
		block1 = arm.veorq_u32(block1, _stream_)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block1,
			BLOCK_SIZE_128_U8,
		)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		_stream_ = arm.uint32x4_t{}

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			stream_size,
		)

		block5 = arm.veorq_u32(block5, _stream_)
		block5 = gf128mul_raw_hw(block5, block2)

		block3 = transmute(arm.uint32x4_t)(transmute(u128)block3 + 1)
		block1 = encrypt_block_raw_hw(ctx, block3)
		block1 = arm.veorq_u32(block1, _stream_)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block1,
			stream_size,
		)
	}

	block5 = arm.veorq_u32(block5, block4)
	block5 = gf128mul_raw_hw(block5, block2)
	block5 = encrypt_block_raw_hw(ctx, block5)

	if runtime.memory_compare(
		raw_data(mac),
		&block5,
		mac_size,
	) == 0 {
		return true
	} else {
		intrinsics.mem_zero(raw_data(mac), mac_size)
		intrinsics.mem_zero(raw_data(data), data_size)
		return false
	}
}

/* Authenticated encryption: belt-seal-che */
@(enable_target_feature="neon,aes")
seal_che_hw :: proc "contextless" (ctx: Context, iv, aad, mac, data: []byte) #no_bounds_check {
	data_size := len(data); aad_size := len(aad); mac_size := len(mac)

	ensure_contextless(mac_size != 0 && mac_size <= MAC_SIZE_64_U8, "crypto/belt: invalid MAC size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")

	_stream_: arm.uint32x4_t

	block1: arm.uint32x4_t = ---
	block2: arm.uint32x4_t = ---
	block3: arm.uint32x4_t = ---
	block4: arm.uint32x4_t = ---
	block5: arm.uint32x4_t = ---
	block6: arm.uint32x4_t = ---

	modulus1 := u64((BITS_PER_BYTE * u128(aad_size))  & u128(max(u64)))
	modulus2 := u64((BITS_PER_BYTE * u128(data_size)) & u128(max(u64)))

	intrinsics.mem_copy_non_overlapping(
		&block3,
		raw_data(iv),
		BLOCK_SIZE_128_U8,
	)

	block4 = transmute(arm.uint32x4_t) arm.uint64x2_t {modulus1, modulus2}
	block5 = transmute(arm.uint32x4_t)BLOCK_C
	block6 = transmute(arm.uint32x4_t)BLOCK_T

	block3 = encrypt_block_raw_hw(ctx, block3)
	block2 = block3

	stream := aad
	stream_size := aad_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block6 = arm.veorq_u32(block6, _stream_)
		block6 = gf128mul_raw_hw(block6, block2)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		_stream_ = arm.uint32x4_t{}

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			stream_size,
		)

		block6 = arm.veorq_u32(block6, _stream_)
		block6 = gf128mul_raw_hw(block6, block2)
	}

	stream = data
	stream_size = data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&block1,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block3 = gf128mul_raw_hw(block3, block5)
		_stream_ = transmute(arm.uint32x4_t)u128(1)
		block3 = arm.veorq_u32(block3, _stream_)

		_stream_ = encrypt_block_raw_hw(ctx, block3)
		_stream_ = arm.veorq_u32(_stream_, block1)

		block6 = arm.veorq_u32(block6, _stream_)
		block6 = gf128mul_raw_hw(block6, block2)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&_stream_,
			BLOCK_SIZE_128_U8,
		)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		block1 = arm.uint32x4_t{}

		intrinsics.mem_copy_non_overlapping(
			&block1,
			raw_data(stream),
			stream_size,
		)

		block3 = gf128mul_raw_hw(block3, block5)
		_stream_ = transmute(arm.uint32x4_t)u128(1)
		block3 = arm.veorq_u32(block3, _stream_)

		_stream_ = encrypt_block_raw_hw(ctx, block3)
		_stream_ = arm.veorq_u32(_stream_, block1)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&_stream_,
			stream_size,
		)

		_stream_ = arm.uint32x4_t{}

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			stream_size,
		)

		block6 = arm.veorq_u32(block6, _stream_)
		block6 = gf128mul_raw_hw(block6, block2)
	}

	block6 = arm.veorq_u32(block6, block4)
	block6 = gf128mul_raw_hw(block6, block2)
	block6 = encrypt_block_raw_hw(ctx, block6)

	intrinsics.mem_copy_non_overlapping(
		raw_data(mac),
		&block6,
		mac_size,
	)
}

/* Authenticated encryption: belt-open-che */
@(enable_target_feature="neon,aes")
open_che_hw :: proc "contextless" (ctx: Context, iv, aad, mac, data: []byte) -> bool #no_bounds_check {
	data_size := len(data); aad_size := len(aad); mac_size := len(mac)

	ensure_contextless(mac_size != 0 && mac_size <= MAC_SIZE_64_U8, "crypto/belt: invalid MAC size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")

	_stream_: arm.uint32x4_t

	block1: arm.uint32x4_t = ---
	block2: arm.uint32x4_t = ---
	block3: arm.uint32x4_t = ---
	block4: arm.uint32x4_t = ---
	block5: arm.uint32x4_t = ---
	block6: arm.uint32x4_t = ---

	modulus1 := u64((BITS_PER_BYTE * u128(aad_size))  & u128(max(u64)))
	modulus2 := u64((BITS_PER_BYTE * u128(data_size)) & u128(max(u64)))

	intrinsics.mem_copy_non_overlapping(
		&block3,
		raw_data(iv),
		BLOCK_SIZE_128_U8,
	)

	block4 = transmute(arm.uint32x4_t) arm.uint64x2_t {modulus1, modulus2}
	block5 = transmute(arm.uint32x4_t)BLOCK_C
	block6 = transmute(arm.uint32x4_t)BLOCK_T

	block3 = encrypt_block_raw_hw(ctx, block3)
	block2 = block3

	stream := aad
	stream_size := aad_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block6 = arm.veorq_u32(block6, _stream_)
		block6 = gf128mul_raw_hw(block6, block2)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		_stream_ = arm.uint32x4_t{}

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			stream_size,
		)

		block6 = arm.veorq_u32(block6, _stream_)
		block6 = gf128mul_raw_hw(block6, block2)
	}

	stream = data
	stream_size = data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block6 = arm.veorq_u32(block6, _stream_)
		block6 = gf128mul_raw_hw(block6, block2)

		block3 = gf128mul_raw_hw(block3, block5)
		block1 = transmute(arm.uint32x4_t)u128(1)
		block3 = arm.veorq_u32(block3, block1)

		block1 = encrypt_block_raw_hw(ctx, block3)
		block1 = arm.veorq_u32(block1, _stream_)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block1,
			BLOCK_SIZE_128_U8,
		)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		_stream_ = arm.uint32x4_t{}

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			stream_size,
		)

		block6 = arm.veorq_u32(block6, _stream_)
		block6 = gf128mul_raw_hw(block6, block2)

		block3 = gf128mul_raw_hw(block3, block5)
		block1 = transmute(arm.uint32x4_t)u128(1)
		block3 = arm.veorq_u32(block3, block1)

		block1 = encrypt_block_raw_hw(ctx, block3)
		block1 = arm.veorq_u32(block1, _stream_)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block1,
			stream_size,
		)
	}

	block6 = arm.veorq_u32(block6, block4)
	block6 = gf128mul_raw_hw(block6, block2)
	block6 = encrypt_block_raw_hw(ctx, block6)

	if runtime.memory_compare(
		raw_data(mac),
		&block6,
		mac_size,
	) == 0 {
		return true
	} else {
		intrinsics.mem_zero(raw_data(mac), mac_size)
		intrinsics.mem_zero(raw_data(data), data_size)
		return false
	}
}

/* Key wrap encryption: belt-seal-kwp */
@(enable_target_feature="neon")
seal_kwp_hw :: proc "contextless" (ctx: Context, cipher, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(cipher) == data_size + BLOCK_SIZE_128_U8, "crypto/belt: invalid CIPHER size")
	ensure_contextless(data_size >= BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	intrinsics.mem_copy(
		raw_data(cipher[:data_size]),
		raw_data(data),
		data_size,
	)

	intrinsics.mem_copy(
		raw_data(cipher[data_size:]),
		raw_data(iv),
		BLOCK_SIZE_128_U8,
	)

	encrypt_wide_block_hw(ctx, cipher)
}

/* Key wrap encryption: belt-open-kwp */
@(enable_target_feature="neon")
open_kwp_hw :: proc "contextless" (ctx: Context, cipher, iv, data: []byte) -> bool #no_bounds_check {
	data_size := len(data); cipher_size := len(cipher)

	ensure_contextless(cipher_size == data_size + BLOCK_SIZE_128_U8, "crypto/belt: invalid CIPHER size")
	ensure_contextless(data_size >= BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	decrypt_wide_block_hw(ctx, cipher)

	if runtime.memory_compare(
		raw_data(iv),
		raw_data(cipher[data_size:]),
		BLOCK_SIZE_128_U8,
	) == 0 {
		intrinsics.mem_copy(
			raw_data(data),
			raw_data(cipher[:data_size]),
			data_size,
		)

		return true
	} else {
		intrinsics.mem_zero(raw_data(iv), BLOCK_SIZE_128_U8)
		intrinsics.mem_zero(raw_data(data), data_size)
		intrinsics.mem_zero(raw_data(cipher), cipher_size)

		return false
	}
}

@(private = "package", enable_target_feature="neon")
compress_hw :: proc "contextless" (dummy, compr, data: []byte) #no_bounds_check {
	assert_contextless(len(dummy) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DUMMY size")
	assert_contextless(len(compr) == BLOCK_SIZE_256_U8, "crypto/belt: invalid COMPR size")
	assert_contextless(len(data)  == BLOCK_SIZE_256_U8, "crypto/belt: invalid DATA size")

	a :: 0; b :: 1
	block: arm.uint32x4_t
	data1, data2: [2]arm.uint32x4_t

	intrinsics.mem_copy_non_overlapping(
		&data1,
		raw_data(data),
		BLOCK_SIZE_256_U8,
	)

	intrinsics.mem_copy_non_overlapping(
		&data2,
		raw_data(compr),
		BLOCK_SIZE_256_U8,
	)

	block, data2 = compress_raw_hw(data1, data2)

	intrinsics.mem_copy_non_overlapping(
		raw_data(compr),
		&data2,
		BLOCK_SIZE_256_U8,
	)

	intrinsics.mem_copy_non_overlapping(
		raw_data(dummy),
		&block,
		BLOCK_SIZE_256_U8,
	)
}

@(private = "package", enable_target_feature="neon")
compress_raw_hw :: proc "contextless" (data1, data2: [2]arm.uint32x4_t) -> (dummy: arm.uint32x4_t, compr: [2]arm.uint32x4_t) #no_bounds_check {
	ctx: Context = ---
	stream: arm.uint32x4_t
	a :: 0; b :: 1

	init_raw(
		&ctx,
		transmute(Block128_U32)data1[a],
		transmute(Block128_U32)data1[b],
	)

	stream = arm.veorq_u32(data2[a], data2[b])
	dummy = encrypt_block_raw_hw(ctx, stream)
	dummy = arm.veorq_u32(dummy, stream)

	init_raw(
		&ctx,
		transmute(Block128_U32)dummy,
		transmute(Block128_U32)data2[b],
	)

	compr[a] = encrypt_block_raw_hw(ctx, data1[a])
	compr[a] = arm.veorq_u32(compr[a], data1[a])
	stream = arm.vmvnq_u32(dummy)

	init_raw(
		&ctx,
		transmute(Block128_U32)stream,
		transmute(Block128_U32)data2[a],
	)

	compr[b] = encrypt_block_raw_hw(ctx, data1[b])
	compr[b] = arm.veorq_u32(compr[b], data1[b])
	return
}

/* Hash derivation: belt-derive-hash */
@(enable_target_feature="neon")
derive_hash_hw :: proc "contextless" (hash, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(hash) == BLOCK_SIZE_256_U8, "crypto/belt: invalid HASH size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")

	a :: 0; b :: 1
	_stream_: [2]arm.uint32x4_t

	block1: [2]arm.uint32x4_t
	block2: [2]arm.uint32x4_t
	dummy: arm.uint32x4_t

	block1[a] = transmute(arm.uint32x4_t)BLOCK_H1
	block1[b] = transmute(arm.uint32x4_t)BLOCK_H2
	block2[a] = transmute(arm.uint32x4_t)(BITS_PER_BYTE * u128(data_size))

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_256_U8 {
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_256_U8,
		)

		dummy, block1 = compress_raw_hw(_stream_, block1)
		block2[b] = arm.veorq_u32(block2[b], dummy)

		stream = stream[BLOCK_SIZE_256_U8:]
		stream_size -= BLOCK_SIZE_256_U8
	}

	if stream_size > 0 {
		_stream_ = [2]arm.uint32x4_t{}

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			stream_size,
		)

		dummy, block1 = compress_raw_hw(_stream_, block1)
		block2[b] = arm.veorq_u32(block2[b], dummy)
	}

	dummy, block1 = compress_raw_hw(block2, block1)

	intrinsics.mem_copy_non_overlapping(
		raw_data(hash),
		&block1,
		BLOCK_SIZE_256_U8,
	)
}

/* Block level encryption: belt-encrypt-bde */
@(enable_target_feature="neon,aes")
encrypt_bde_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(
		data_size >= BLOCK_SIZE_128_U8 &&
		data_size & (BLOCK_SIZE_128_U8 - 1) == 0,
		"crypto/belt: invalid DATA size",
	)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_stream_: arm.uint32x4_t

	block1: arm.uint32x4_t = ---
	block2: arm.uint32x4_t = ---

	intrinsics.mem_copy_non_overlapping(
		&block1,
		raw_data(iv),
		BLOCK_SIZE_128_U8,
	)

	block2 = transmute(arm.uint32x4_t)BLOCK_C
	block1 = encrypt_block_raw_hw(ctx, block1)

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block1 = gf128mul_raw_hw(block1, block2)
		_stream_ = arm.veorq_u32(_stream_, block1)
		_stream_ = encrypt_block_raw_hw(ctx, _stream_)
		_stream_ = arm.veorq_u32(_stream_, block1)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&_stream_,
			BLOCK_SIZE_128_U8,
		)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}
}

/* Block level encryption: belt-decrypt-bde */
@(enable_target_feature="neon,aes")
decrypt_bde_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(
		data_size >= BLOCK_SIZE_128_U8 &&
		data_size & (BLOCK_SIZE_128_U8 - 1) == 0,
		"crypto/belt: invalid DATA size",
	)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_stream_: arm.uint32x4_t

	block1: arm.uint32x4_t = ---
	block2: arm.uint32x4_t = ---

	intrinsics.mem_copy_non_overlapping(
		&block1,
		raw_data(iv),
		BLOCK_SIZE_128_U8,
	)

	block2 = transmute(arm.uint32x4_t)BLOCK_C
	block1 = encrypt_block_raw_hw(ctx, block1)

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block1 = gf128mul_raw_hw(block1, block2)
		_stream_ = arm.veorq_u32(_stream_, block1)
		_stream_ = decrypt_block_raw_hw(ctx, _stream_)
		_stream_ = arm.veorq_u32(_stream_, block1)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&_stream_,
			BLOCK_SIZE_128_U8,
		)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}
}

/* Sector level encryption: belt-encrypt-sde */
@(enable_target_feature="neon")
encrypt_sde_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(
		data_size >= BLOCK_SIZE_256_U8 &&
		data_size & (BLOCK_SIZE_128_U8 - 1) == 0,
		"crypto/belt: invalid DATA size",
	)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_stream_: arm.uint32x4_t

	block: arm.uint32x4_t = ---

	intrinsics.mem_copy_non_overlapping(
		&block,
		raw_data(iv),
		BLOCK_SIZE_128_U8,
	)

	block = encrypt_block_raw_hw(ctx, block)

	intrinsics.mem_copy_non_overlapping(
		&_stream_,
		raw_data(data),
		BLOCK_SIZE_128_U8,
	)

	_stream_ = arm.veorq_u32(_stream_, block)

	intrinsics.mem_copy_non_overlapping(
		raw_data(data),
		&_stream_,
		BLOCK_SIZE_128_U8,
	)

	encrypt_wide_block_hw(ctx, data)

	intrinsics.mem_copy_non_overlapping(
		&_stream_,
		raw_data(data),
		BLOCK_SIZE_128_U8,
	)

	_stream_ = arm.veorq_u32(_stream_, block)

	intrinsics.mem_copy_non_overlapping(
		raw_data(data),
		&_stream_,
		BLOCK_SIZE_128_U8,
	)
}

/* Sector level encryption: belt-decrypt-sde */
@(enable_target_feature="neon")
decrypt_sde_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(
		data_size >= BLOCK_SIZE_256_U8 &&
		data_size & (BLOCK_SIZE_128_U8 - 1) == 0,
		"crypto/belt: invalid DATA size",
	)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_stream_: arm.uint32x4_t

	block: arm.uint32x4_t = ---

	intrinsics.mem_copy_non_overlapping(
		&block,
		raw_data(iv),
		BLOCK_SIZE_128_U8,
	)

	block = encrypt_block_raw_hw(ctx, block)

	intrinsics.mem_copy_non_overlapping(
		&_stream_,
		raw_data(data),
		BLOCK_SIZE_128_U8,
	)

	_stream_ = arm.veorq_u32(_stream_, block)

	intrinsics.mem_copy_non_overlapping(
		raw_data(data),
		&_stream_,
		BLOCK_SIZE_128_U8,
	)

	decrypt_wide_block_hw(ctx, data)

	intrinsics.mem_copy_non_overlapping(
		&_stream_,
		raw_data(data),
		BLOCK_SIZE_128_U8,
	)

	_stream_ = arm.veorq_u32(_stream_, block)

	intrinsics.mem_copy_non_overlapping(
		raw_data(data),
		&_stream_,
		BLOCK_SIZE_128_U8,
	)
}

/* Derive key {128, 192, 256} from key {128, 192, 256}: belt-derive-key */
@(enable_target_feature="neon")
derive_key_hw :: proc "contextless" (depth, iv, dst, src: []byte) #no_bounds_check {
	dst_size := len(dst); src_size := len(src)

	ensure_contextless(
		src_size == KEY_SIZE_128_U8 ||
		src_size == KEY_SIZE_192_U8 ||
		src_size == KEY_SIZE_256_U8,
		"crypto/belt: invalid SRC size",
	)

	ensure_contextless(
		dst_size == KEY_SIZE_128_U8 ||
		dst_size == KEY_SIZE_192_U8 ||
		dst_size == KEY_SIZE_256_U8,
		"crypto/belt: invalid DST size",
	)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(len(depth) == BLOCK_SIZE_96_U8, "crypto/belt: invalid DEPTH size")

	dummy: Block128_U8 = ---
	key: Key256_U8 = ---
	stream: Block256_U8 = ---

	if src_size == KEY_SIZE_128_U8 && dst_size == KEY_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&stream,
			&BLOCK_R1,
			BLOCK_SIZE_32_U8,
		)
	} else if src_size == KEY_SIZE_192_U8 && dst_size == KEY_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&stream,
			&BLOCK_R2,
			BLOCK_SIZE_32_U8,
		)
	} else if src_size == KEY_SIZE_192_U8 && dst_size == KEY_SIZE_192_U8 {
		intrinsics.mem_copy_non_overlapping(
			&stream,
			&BLOCK_R3,
			BLOCK_SIZE_32_U8,
		)
	} else if src_size == KEY_SIZE_256_U8 && dst_size == KEY_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&stream,
			&BLOCK_R4,
			BLOCK_SIZE_32_U8,
		)
	} else if src_size == KEY_SIZE_256_U8 && dst_size == KEY_SIZE_192_U8 {
		intrinsics.mem_copy_non_overlapping(
			&stream,
			&BLOCK_R5,
			BLOCK_SIZE_32_U8,
		)
	} else if src_size == KEY_SIZE_256_U8 && dst_size == KEY_SIZE_256_U8 {
		intrinsics.mem_copy_non_overlapping(
			&stream,
			&BLOCK_R6,
			BLOCK_SIZE_32_U8,
		)
	}

	intrinsics.mem_copy_non_overlapping(
		raw_data(stream[BLOCK_SIZE_32_U8: BLOCK_SIZE_128_U8]),
		raw_data(depth),
		BLOCK_SIZE_96_U8,
	)

	intrinsics.mem_copy_non_overlapping(
		raw_data(stream[BLOCK_SIZE_128_U8:]),
		raw_data(iv),
		BLOCK_SIZE_128_U8,
	)

	expand_key(key[:], src)
	compress_hw(dummy[:], key[:], stream[:])

	intrinsics.mem_copy(
		raw_data(dst),
		&key,
		dst_size,
	)
}

@(private = "file", enable_target_feature="neon")
encrypt_block32_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	assert_contextless(len(data) == BLOCK_SIZE_192_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block: arm.uint32x4_t
	stream1: arm.uint32x4_t
	stream2: arm.uint32x4_t

	intrinsics.mem_copy_non_overlapping(
		&stream1,
		raw_data(data),
		BLOCK_SIZE_64_U8,
	)

	stream := data[BLOCK_SIZE_64_U8:]
	intrinsics.mem_copy_non_overlapping(
		&stream2,
		raw_data(stream),
		BLOCK_SIZE_128_U8,
	)

	#unroll for round in 1..=3 {
		block = transmute(arm.uint32x4_t)u128(round)
		stream2 = encrypt_block_raw_hw(ctx, stream2)
		stream2 = arm.veorq_u32(stream2, block)

		block = arm.uint32x4_t {max(u32), max(u32), 0, 0}
		block = arm.vandq_u32(stream2, block)

		stream2 = arm.veorq_u32(stream2, stream1)
		stream2 = simd.shuffle(stream2, stream2, 2, 3, 0, 1)
		stream1 = block
	}

	intrinsics.mem_copy_non_overlapping(
		raw_data(data),
		&stream1,
		BLOCK_SIZE_64_U8,
	)

	intrinsics.mem_copy_non_overlapping(
		raw_data(stream),
		&stream2,
		BLOCK_SIZE_128_U8,
	)
}

@(private = "file", enable_target_feature="neon")
roundf_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	data_size := len(data)

	assert_contextless(
		data_size >= BLOCK_SIZE_128_U8 &&
		data_size & (BLOCK_SIZE_64_U8 - 1) == 0,
		"crypto/belt: invalid DATA size",
	)

	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	if data_size == BLOCK_SIZE_128_U8 {
		encrypt_block_hw(ctx, data)
	} else if data_size == BLOCK_SIZE_192_U8 {
		encrypt_block32_hw(ctx, data)
	} else if data_size >= BLOCK_SIZE_256_U8 {
		encrypt_wide_block_hw(ctx, data)
	}
}

/* Format preserving encryption: belt-encrypt-fmt */
@(enable_target_feature="neon")
encrypt_fmt_hw :: proc "contextless" (ctx: Context, m: int, iv: []byte, data: []u16) #no_bounds_check {
	data_size := len(data); iv_size := len(iv)

	ensure_contextless(data_size >= M_MIN_INT && data_size <= M_MAX_INT, "crypto/belt: invalid DATA size")
	ensure_contextless(m >= M_MIN_INT && m <= M_MAX_INT, "crypto/belt: invalid M value")
	ensure_contextless(iv_size == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	backbuff1: Backbuff_U8 = ---
	backbuff2: Backbuff_U8 = ---

	m1 := u16(m)
	m2 := u16(data_size)

	stream: Block32_U8 = ---
	intrinsics.mem_copy_non_overlapping(
		raw_data(stream[:BLOCK_SIZE_16_U8]),
		&m1,
		BLOCK_SIZE_16_U8,
	)

	intrinsics.mem_copy_non_overlapping(
		raw_data(stream[BLOCK_SIZE_16_U8:]),
		&m2,
		BLOCK_SIZE_16_U8,
	)

	table1 := [?][]byte {
		BLOCK_C1[:],
		BLOCK_C2[:],
		BLOCK_C3[:],
		BLOCK_C4[:],
		BLOCK_C5[:],
		BLOCK_C6[:],
	}

	table2 := [?][]byte {
		stream[:],
		iv[:BLOCK_SIZE_32_U8],
		iv[BLOCK_SIZE_32_U8:BLOCK_SIZE_64_U8],
		iv[BLOCK_SIZE_64_U8:BLOCK_SIZE_96_U8],
		iv[BLOCK_SIZE_96_U8:],
		stream[:],
	}

	n1 := int((uint(data_size) + 1) / 2)
	n2 := int(data_size / 2)

	data1 := data[:n1]
	data2 := data[n1:]

	b1 := find_b(m, n1)
	b2 := find_b(m, n2)

	block1_size := BITS_PER_BYTE * b1
	block2_size := BITS_PER_BYTE * b2

	block1 := backbuff1[:block1_size + BLOCK_SIZE_64_U8]
	block2 := backbuff2[:block2_size + BLOCK_SIZE_64_U8]

	#unroll for round in 0..=2 {
		str2bin(m, block2[:block2_size], data2)

		intrinsics.mem_copy_non_overlapping(
			raw_data(block2[block2_size + BLOCK_SIZE_32_U8:]),
			raw_data(table2[2 * round]),
			BLOCK_SIZE_32_U8,
		)

		intrinsics.mem_copy_non_overlapping(
			raw_data(block2[block2_size: block2_size + BLOCK_SIZE_32_U8]),
			raw_data(table1[2 * round]),
			BLOCK_SIZE_32_U8,
		)

		roundf_hw(ctx, block2[:])
		bin2str_add(m, data1, block2[:])

		str2bin(m, block1[:block1_size], data1)

		intrinsics.mem_copy_non_overlapping(
			raw_data(block1[block1_size + BLOCK_SIZE_32_U8:]),
			raw_data(table2[1 + 2 * round]),
			BLOCK_SIZE_32_U8,
		)

		intrinsics.mem_copy_non_overlapping(
			raw_data(block1[block1_size: block2_size + BLOCK_SIZE_32_U8]),
			raw_data(table1[1 + 2 * round]),
			BLOCK_SIZE_32_U8,
		)

		roundf_hw(ctx, block1[:])
		bin2str_add(m, data2, block1[:])
	}
}

/* Format preserving encryption: belt-decrypt-fmt */
@(enable_target_feature="neon")
decrypt_fmt_hw :: proc "contextless" (ctx: Context, m: int, iv: []byte, data: []u16) #no_bounds_check {
	data_size := len(data); iv_size := len(iv)

	ensure_contextless(data_size >= M_MIN_INT && data_size <= M_MAX_INT, "crypto/belt: invalid DATA size")
	ensure_contextless(m >= M_MIN_INT && m <= M_MAX_INT, "crypto/belt: invalid M value")
	ensure_contextless(iv_size == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	backbuff1: Backbuff_U8 = ---
	backbuff2: Backbuff_U8 = ---

	m1 := u16(m)
	m2 := u16(data_size)

	stream: Block32_U8 = ---
	intrinsics.mem_copy_non_overlapping(
		raw_data(stream[:BLOCK_SIZE_16_U8]),
		&m1,
		BLOCK_SIZE_16_U8,
	)

	intrinsics.mem_copy_non_overlapping(
		raw_data(stream[BLOCK_SIZE_16_U8:]),
		&m2,
		BLOCK_SIZE_16_U8,
	)

	table1 := [?][]byte {
		BLOCK_C1[:],
		BLOCK_C2[:],
		BLOCK_C3[:],
		BLOCK_C4[:],
		BLOCK_C5[:],
		BLOCK_C6[:],
	}

	table2 := [?][]byte {
		stream[:],
		iv[:BLOCK_SIZE_32_U8],
		iv[BLOCK_SIZE_32_U8:BLOCK_SIZE_64_U8],
		iv[BLOCK_SIZE_64_U8:BLOCK_SIZE_96_U8],
		iv[BLOCK_SIZE_96_U8:],
		stream[:],
	}

	n1 := int((uint(data_size) + 1) / 2)
	n2 := int(data_size / 2)

	data1 := data[:n1]
	data2 := data[n1:]

	b1 := find_b(m, n1)
	b2 := find_b(m, n2)

	block1_size := BITS_PER_BYTE * b1
	block2_size := BITS_PER_BYTE * b2

	block1 := backbuff1[:block1_size + BLOCK_SIZE_64_U8]
	block2 := backbuff2[:block2_size + BLOCK_SIZE_64_U8]

	#unroll for round in 0..=2 {
		str2bin(m, block1[:block1_size], data1)

		intrinsics.mem_copy_non_overlapping(
			raw_data(block1[block1_size + BLOCK_SIZE_32_U8:]),
			raw_data(table2[5 - 2 * round]),
			BLOCK_SIZE_32_U8,
		)

		intrinsics.mem_copy_non_overlapping(
			raw_data(block1[block1_size: block2_size + BLOCK_SIZE_32_U8]),
			raw_data(table1[5 - 2 * round]),
			BLOCK_SIZE_32_U8,
		)

		roundf_hw(ctx, block1[:])
		bin2str_sub(m, data2, block1[:])

		str2bin(m, block2[:block2_size], data2)

		intrinsics.mem_copy_non_overlapping(
			raw_data(block2[block2_size + BLOCK_SIZE_32_U8:]),
			raw_data(table2[4 - 2 * round]),
			BLOCK_SIZE_32_U8,
		)

		intrinsics.mem_copy_non_overlapping(
			raw_data(block2[block2_size: block2_size + BLOCK_SIZE_32_U8]),
			raw_data(table1[4 - 2 * round]),
			BLOCK_SIZE_32_U8,
		)

		roundf_hw(ctx, block2[:])
		bin2str_sub(m, data1, block2[:])
	}
}
