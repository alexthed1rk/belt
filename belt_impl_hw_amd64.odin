#+build amd64
package belt

/* STB 34.101.31-2020                                    */
/* Information technology and security                   */
/* Encryption and integrity control algorithms           */
/* https://apmi.bsu.by/assets/files/std/belt-spec371.pdf */

import "base:intrinsics"
import "base:runtime"
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
@(require_results, private = "file", enable_target_feature="sse2,pclmul")
gf128mul_raw_hw :: proc "contextless" (a, b: x86.__m128i) -> x86.__m128i #no_bounds_check {
	block0, block1, block2, block3, block4: x86.__m128i
	block5, block6, block7, block8, block9: x86.__m128i
	mask := x86._mm_set_epi32(0, 0, 0, -1)
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

@(enable_target_feature="sse2,pclmul")
gf128mul_hw :: proc "contextless" (dst, src: []byte) #no_bounds_check {
	assert_contextless(len(dst) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DST size")
	assert_contextless(len(src) == BLOCK_SIZE_128_U8, "crypto/belt: invalid SRC size")

	block1: x86.__m128i = ---
	block2: x86.__m128i = ---

	block1 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(dst)))
	block2 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(src)))
	block1 = gf128mul_raw_hw(block1, block2)
	intrinsics.unaligned_store((^x86.__m128i)(raw_data(dst)), block1)
}

/* Block cipher: belt-encrypt-block */
@(enable_target_feature="sse2")
encrypt_block_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	assert_contextless(len(data) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	stream: x86.__m128i = ---
	stream = intrinsics.unaligned_load((^x86.__m128i)(raw_data(data)))
	stream = encrypt_block_raw_hw(ctx, stream)
	intrinsics.unaligned_store((^x86.__m128i)(raw_data(data)), stream)
}

@(require_results, private = "file", enable_target_feature="sse2")
encrypt_block_raw_hw :: proc "contextless" (ctx: Context, block: x86.__m128i) -> x86.__m128i #no_bounds_check {
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	stream1: x86.__m128i = block
	stream2: Block128_U32 = ---

	a :: 0; b :: 1; c :: 2; d :: 3
	#unroll for round in 0..<8 {
		stream2 = transmute(Block128_U32)stream1

		stream2[b] ~= table_g05(stream2[a] + ctx.key[7 * round])
		stream2[c] ~= table_g21(stream2[d] + ctx.key[7 * round + 1])
		stream2[a] -= table_g13(stream2[b] + ctx.key[7 * round + 2])

		stream2[c] += stream2[b]
		stream2[b] += table_g21(stream2[c] + ctx.key[7 * round + 3]) ~ u32(1 + round)
		stream2[c] -= stream2[b]

		stream2[d] += table_g13(stream2[c] + ctx.key[7 * round + 4])
		stream2[b] ~= table_g21(stream2[a] + ctx.key[7 * round + 5])
		stream2[c] ~= table_g05(stream2[d] + ctx.key[7 * round + 6])

		stream1 = transmute(x86.__m128i)stream2
		stream1 = x86._mm_shuffle_epi32(stream1, 0x8d)
	}

	return x86._mm_shuffle_epi32(stream1, 0x8d)
}

/* Block cipher: belt-decrypt-block */
@(enable_target_feature="sse2")
decrypt_block_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	assert_contextless(len(data) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	stream: x86.__m128i = ---
	stream = intrinsics.unaligned_load((^x86.__m128i)(raw_data(data)))
	stream = decrypt_block_raw_hw(ctx, stream)
	intrinsics.unaligned_store((^x86.__m128i)(raw_data(data)), stream)
}

@(require_results, private = "file", enable_target_feature="sse2")
decrypt_block_raw_hw :: proc "contextless" (ctx: Context, block: x86.__m128i) -> x86.__m128i #no_bounds_check {
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	stream1: x86.__m128i = block
	stream2: Block128_U32 = ---

	a :: 0; b :: 1; c :: 2; d :: 3
	#unroll for round in 0..<8 {
		stream2 = transmute(Block128_U32)stream1

		stream2[b] ~= table_g05(stream2[a] + ctx.key[55 - 7 * round])
		stream2[c] ~= table_g21(stream2[d] + ctx.key[54 - 7 * round])
		stream2[a] -= table_g13(stream2[b] + ctx.key[53 - 7 * round])

		stream2[c] += stream2[b]
		stream2[b] += table_g21(stream2[c] + ctx.key[52 - 7 * round]) ~ u32(8 - round)
		stream2[c] -= stream2[b]

		stream2[d] += table_g13(stream2[c] + ctx.key[51 - 7 * round])
		stream2[b] ~= table_g21(stream2[a] + ctx.key[50 - 7 * round])
		stream2[c] ~= table_g05(stream2[d] + ctx.key[49 - 7 * round])

		stream1 = transmute(x86.__m128i)stream2
		stream1 = x86._mm_shuffle_epi32(stream1, 0x72)
	}

	return x86._mm_shuffle_epi32(stream1, 0x72)
}

/* Wide block cipher: belt-encrypt-wide-block */
@(enable_target_feature="sse2")
encrypt_wide_block_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	data_size := len(data)

	assert_contextless(data_size >= BLOCK_SIZE_256_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	stream: []byte = ---
	block1: x86.__m128i = ---
	block2: x86.__m128i = ---

	num_rounds := 2 * ((uint(data_size) + BLOCK_SIZE_128_U8 - 1) / BLOCK_SIZE_128_U8)
	for round := uint(1); round <= num_rounds; round += 1 {

		stream = data
		block1 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size := data_size - BLOCK_SIZE_128_U8

		for stream_size > BLOCK_SIZE_128_U8 {
			block2 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))
			block1 = x86._mm_xor_si128(block1, block2)

			stream = stream[BLOCK_SIZE_128_U8:]
			stream_size -= BLOCK_SIZE_128_U8
		}

		intrinsics.mem_copy(
			raw_data(data),
			raw_data(data[BLOCK_SIZE_128_U8:]),
			data_size - BLOCK_SIZE_128_U8,
		)

		stream = data[data_size - BLOCK_SIZE_128_U8:]
		intrinsics.unaligned_store((^x86.__m128i)(raw_data(stream)), block1)

		block1 = encrypt_block_raw_hw(ctx, block1)
		block2 = transmute(x86.__m128i)u128(round)
		block1 = x86._mm_xor_si128(block1, block2)

		stream = data[data_size - BLOCK_SIZE_256_U8:]
		block2 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))
		block1 = x86._mm_xor_si128(block1, block2)
		intrinsics.unaligned_store((^x86.__m128i)(raw_data(stream)), block1)
	}
}

/* Wide block cipher: belt-decrypt-wide-block */
@(enable_target_feature="sse2")
decrypt_wide_block_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	data_size := len(data)

	assert_contextless(data_size >= BLOCK_SIZE_256_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	stream: []byte = ---
	block0: x86.__m128i = ---
	block1: x86.__m128i = ---
	block2: x86.__m128i = ---

	num_rounds := 2 * ((uint(data_size) + BLOCK_SIZE_128_U8 - 1) / BLOCK_SIZE_128_U8)
	for round := num_rounds; round >= 1; round -= 1 {

		stream = data[data_size - BLOCK_SIZE_128_U8:]
		block0 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		intrinsics.mem_copy(
			raw_data(data[BLOCK_SIZE_128_U8:]),
			raw_data(data),
			data_size - BLOCK_SIZE_128_U8,
		)

		block1 = encrypt_block_raw_hw(ctx, block0)
		block2 = transmute(x86.__m128i)u128(round)
		block1 = x86._mm_xor_si128(block1, block2)

		block2 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))
		block1 = x86._mm_xor_si128(block1, block2)
		intrinsics.unaligned_store((^x86.__m128i)(raw_data(stream)), block1)

		stream = data[BLOCK_SIZE_128_U8:]
		stream_size := data_size - BLOCK_SIZE_128_U8

		for stream_size > BLOCK_SIZE_128_U8 {
			block2 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))
			block0 = x86._mm_xor_si128(block0, block2)

			stream = stream[BLOCK_SIZE_128_U8:]
			stream_size -= BLOCK_SIZE_128_U8
		}

		stream = data
		intrinsics.unaligned_store((^x86.__m128i)(raw_data(stream)), block0)
	}
}

/* Electronic codebook encryption: belt-encrypt-ecb */
@(enable_target_feature="sse2")
encrypt_ecb_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(data_size >= BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block: Block128_U8 = ---

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		encrypt_block_hw(ctx, stream)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		stream = data[data_size - stream_size - BLOCK_SIZE_128_U8:]

		intrinsics.mem_copy_non_overlapping(
			raw_data(block[:stream_size]),
			raw_data(stream[BLOCK_SIZE_128_U8:]),
			stream_size,
		)

		intrinsics.mem_copy_non_overlapping(
			raw_data(block[stream_size:]),
			raw_data(stream[stream_size:]),
			BLOCK_SIZE_128_U8 - stream_size,
		)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream[BLOCK_SIZE_128_U8:]),
			raw_data(stream[:stream_size]),
			stream_size,
		)

		encrypt_block_hw(ctx, block[:])
		intrinsics.unaligned_store((^Block128_U8)(raw_data(stream)), block)
	}
}

/* Electronic codebook encryption: belt-decrypt-ecb */
@(enable_target_feature="sse2")
decrypt_ecb_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(data_size >= BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block: Block128_U8 = ---

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		decrypt_block_hw(ctx, stream)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		stream = data[data_size - stream_size - BLOCK_SIZE_128_U8:]

		intrinsics.mem_copy_non_overlapping(
			raw_data(block[:stream_size]),
			raw_data(stream[BLOCK_SIZE_128_U8:]),
			stream_size,
		)

		intrinsics.mem_copy_non_overlapping(
			raw_data(block[stream_size:]),
			raw_data(stream[stream_size:]),
			BLOCK_SIZE_128_U8 - stream_size,
		)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream[BLOCK_SIZE_128_U8:]),
			raw_data(stream[:stream_size]),
			stream_size,
		)

		decrypt_block_hw(ctx, block[:])
		intrinsics.unaligned_store((^Block128_U8)(raw_data(stream)), block)
	}
}

/* Cipher block chaining encryption: belt-encrypt-cbc */
@(enable_target_feature="sse2")
encrypt_cbc_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size >= BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block0: Block128_U8 = ---
	block1: x86.__m128i = ---
	block2: x86.__m128i = ---

	block2 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(iv)))

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		block1 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		block2 = x86._mm_xor_si128(block2, block1)
		block2 = encrypt_block_raw_hw(ctx, block2)

		intrinsics.unaligned_store((^x86.__m128i)(raw_data(stream)), block2)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		intrinsics.mem_zero(&block1, BLOCK_SIZE_128_U8)

		intrinsics.mem_copy_non_overlapping(
			&block1,
			raw_data(stream),
			stream_size,
		)

		block2 = x86._mm_xor_si128(block2, block1)

		intrinsics.mem_copy_non_overlapping(
			&block0,
			&block2,
			stream_size,
		)

		stream = data[data_size - stream_size - BLOCK_SIZE_128_U8:]

		intrinsics.mem_copy_non_overlapping(
			raw_data(block0[stream_size:]),
			raw_data(stream[stream_size:]),
			BLOCK_SIZE_128_U8 - stream_size,
		)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream[BLOCK_SIZE_128_U8:]),
			raw_data(stream),
			stream_size,
		)

		encrypt_block_hw(ctx, block0[:])
		intrinsics.unaligned_store((^Block128_U8)(raw_data(stream)), block0)
	}
}

/* Cipher block chaining encryption: belt-decrypt-cbc */
@(enable_target_feature="sse2")
decrypt_cbc_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size >= BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block0: Block128_U8 = ---
	block1: x86.__m128i = ---
	block2: x86.__m128i = ---
	block3: x86.__m128i = ---

	block2 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(iv)))

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_256_U8 || stream_size == BLOCK_SIZE_128_U8 {
		block3 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		block1 = decrypt_block_raw_hw(ctx, block3)
		block1 = x86._mm_xor_si128(block1, block2)
		block2 = block3

		intrinsics.unaligned_store((^x86.__m128i)(raw_data(stream)), block1)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		intrinsics.mem_zero(&block3, BLOCK_SIZE_128_U8)

		block0 = intrinsics.unaligned_load((^Block128_U8)(raw_data(stream)))
		decrypt_block_hw(ctx, block0[:])

		intrinsics.mem_copy_non_overlapping(
			&block1,
			&block0,
			stream_size - BLOCK_SIZE_128_U8,
		)

		intrinsics.mem_copy_non_overlapping(
			&block3,
			raw_data(stream[BLOCK_SIZE_128_U8:]),
			stream_size - BLOCK_SIZE_128_U8,
		)

		block1 = x86._mm_xor_si128(block1, block3)
		block3 = x86._mm_xor_si128(block3, block1)
		block1 = x86._mm_xor_si128(block1, block3)
		block3 = x86._mm_xor_si128(block3, block1)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream[BLOCK_SIZE_128_U8:]),
			&block3,
			stream_size - BLOCK_SIZE_128_U8,
		)

		intrinsics.mem_copy_non_overlapping(
			&block0,
			&block1,
			stream_size - BLOCK_SIZE_128_U8,
		)

		block1 = transmute(x86.__m128i)block0
		block1 = decrypt_block_raw_hw(ctx, block1)
		block1 = x86._mm_xor_si128(block1, block2)

		intrinsics.unaligned_store((^x86.__m128i)(raw_data(stream)), block1)
	}
}

/* Cipher feedback encryption: belt-encrypt-cfb */
@(enable_target_feature="sse2")
encrypt_cfb_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block1: x86.__m128i = ---
	block2: x86.__m128i = ---

	block2 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(iv)))

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		block1 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		block2 = encrypt_block_raw_hw(ctx, block2)
		block2 = x86._mm_xor_si128(block2, block1)

		intrinsics.unaligned_store((^x86.__m128i)(raw_data(stream)), block2)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		intrinsics.mem_zero(&block1, BLOCK_SIZE_128_U8)

		intrinsics.mem_copy_non_overlapping(
			&block1,
			raw_data(stream),
			stream_size,
		)

		block2 = encrypt_block_raw_hw(ctx, block2)
		block2 = x86._mm_xor_si128(block2, block1)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block2,
			stream_size,
		)
	}
}

/* Cipher feedback encryption: belt-decrypt-cfb */
@(enable_target_feature="sse2")
decrypt_cfb_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block1: x86.__m128i = ---
	block2: x86.__m128i = ---

	block2 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(iv)))

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		block1 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		block2 = encrypt_block_raw_hw(ctx, block2)
		block2 = x86._mm_xor_si128(block2, block1)

		block1 = x86._mm_xor_si128(block1, block2)
		block2 = x86._mm_xor_si128(block2, block1)
		block1 = x86._mm_xor_si128(block1, block2)

		intrinsics.unaligned_store((^x86.__m128i)(raw_data(stream)), block1)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		intrinsics.mem_zero(&block1, BLOCK_SIZE_128_U8)

		intrinsics.mem_copy_non_overlapping(
			&block1,
			raw_data(stream),
			stream_size,
		)

		block2 = encrypt_block_raw_hw(ctx, block2)
		block2 = x86._mm_xor_si128(block2, block1)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block2,
			stream_size,
		)
	}
}

/* Counter encryption: belt-encrypt-ctr */
@(enable_target_feature="sse2")
encrypt_ctr_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block0: x86.__m128i = ---
	block1: x86.__m128i = ---
	block2: x86.__m128i = ---

	block2 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(iv)))
	block2 = encrypt_block_raw_hw(ctx, block2)

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		block0 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		block2 = transmute(x86.__m128i)(transmute(u128)block2 + 1)
		block1 = encrypt_block_raw_hw(ctx, block2)
		block1 = x86._mm_xor_si128(block1, block0)

		intrinsics.unaligned_store((^x86.__m128i)(raw_data(stream)), block1)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		intrinsics.mem_zero(&block0, BLOCK_SIZE_128_U8)

		intrinsics.mem_copy_non_overlapping(
			&block0,
			raw_data(stream),
			stream_size,
		)

		block2 = transmute(x86.__m128i)(transmute(u128)block2 + 1)
		block1 = encrypt_block_raw_hw(ctx, block2)
		block1 = x86._mm_xor_si128(block1, block0)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block1,
			stream_size,
		)
	}
}

/* Counter encryption: belt-decrypt-ctr */
decrypt_ctr_hw :: encrypt_ctr_hw

@(require_results, private = "file", enable_target_feature="sse2")
table_φ1_hw :: #force_inline proc "contextless" (data: x86.__m128i) -> x86.__m128i #no_bounds_check {
	block1, block2: x86.__m128i
	block1 = x86._mm_shuffle_epi32(data, 0x39)
	block2 = x86._mm_slli_si128(block1, 0x0c)
	return x86._mm_xor_si128(block1, block2)
}

@(require_results, private = "file", enable_target_feature="sse2")
table_φ2_hw :: #force_inline proc "contextless" (data: x86.__m128i) -> x86.__m128i #no_bounds_check {
	block1, block2: x86.__m128i
	block1 = x86._mm_shuffle_epi32(data, 0x93)
	block2 = x86._mm_set_epi32(0, 0, 0, -1)
	block2 = x86._mm_and_si128(data, block2)
	return x86._mm_xor_si128(block1, block2)
}

/* Message authentication code sum: belt-mac-sum */
@(enable_target_feature="sse2")
mac_sum_hw :: proc "contextless" (ctx: Context, dst, msg: []byte) #no_bounds_check {
	data_size := len(msg)

	ensure_contextless(len(dst) == BLOCK_SIZE_64_U8, "crypto/belt: invalid DST size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid MSG size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block0: Block128_U8
	block1: x86.__m128i
	block2: x86.__m128i
	block3: x86.__m128i

	stream := msg
	stream_size := data_size

	block2 = encrypt_block_raw_hw(ctx, block2)
	for stream_size > BLOCK_SIZE_128_U8 {
		block1 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		block3 = x86._mm_xor_si128(block3, block1)
		block3 = encrypt_block_raw_hw(ctx, block3)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size == BLOCK_SIZE_128_U8 {
		block1 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		block2 = table_φ1_hw(block2)
		block3 = x86._mm_xor_si128(block3, block2)
		block3 = x86._mm_xor_si128(block3, block1)
	} else {
		intrinsics.mem_copy_non_overlapping(
			&block0,
			raw_data(stream),
			stream_size,
		)

		ψ_unit :: 0x80
		block0[stream_size] = ψ_unit
		block1 = transmute(x86.__m128i)block0

		block2 = table_φ2_hw(block2)
		block3 = x86._mm_xor_si128(block3, block2)
		block3 = x86._mm_xor_si128(block3, block1)
	}

	block3 = encrypt_block_raw_hw(ctx, block3)
	block0 = transmute(Block128_U8)block3

	intrinsics.mem_copy_non_overlapping(
		raw_data(dst),
		&block0,
		BLOCK_SIZE_64_U8,
	)
}

/* Authenticated encryption: belt-seal-dwp */
@(enable_target_feature="sse2,pclmul")
seal_dwp_hw :: proc "contextless" (ctx: Context, tag, iv, aad, data: []byte) #no_bounds_check {
	data_size := len(data); aad_size := len(aad); tag_size := len(tag)

	ensure_contextless(tag_size != 0 && tag_size <= BLOCK_SIZE_64_U8, "crypto/belt: invalid TAG size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")

	block0: x86.__m128i = ---
	block1: x86.__m128i = ---
	block2: x86.__m128i = ---
	block3: x86.__m128i = ---
	block4: x86.__m128i = ---
	block5: x86.__m128i = ---

	BLOCK_T := Block128_U8 {
		0xb1, 0x94, 0xba, 0xc8, 0x0a, 0x08, 0xf5, 0x3b,
		0x36, 0x6d, 0x00, 0x8e, 0x58, 0x4a, 0x5d, 0xe4,
	}

	modulus1 := u64((BITS_PER_BYTE * u128(aad_size))  & u128(max(u64)))
	modulus2 := u64((BITS_PER_BYTE * u128(data_size)) & u128(max(u64)))

	block3 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(iv)))
	block4 = x86.__m128i {transmute(i64)modulus1, transmute(i64)modulus2}
	block5 = transmute(x86.__m128i)BLOCK_T

	block3 = encrypt_block_raw_hw(ctx, block3)
	block2 = encrypt_block_raw_hw(ctx, block3)

	stream := aad
	stream_size := aad_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		block0 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		block5 = x86._mm_xor_si128(block5, block0)
		block5 = gf128mul_raw_hw(block5, block2)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		intrinsics.mem_zero(&block0, BLOCK_SIZE_128_U8)

		intrinsics.mem_copy_non_overlapping(
			&block0,
			raw_data(stream),
			stream_size,
		)

		block5 = x86._mm_xor_si128(block5, block0)
		block5 = gf128mul_raw_hw(block5, block2)
	}

	stream = data
	stream_size = data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		block1 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		block3 = transmute(x86.__m128i)(transmute(u128)block3 + 1)
		block0 = encrypt_block_raw_hw(ctx, block3)
		block0 = x86._mm_xor_si128(block0, block1)

		block5 = x86._mm_xor_si128(block5, block0)
		block5 = gf128mul_raw_hw(block5, block2)

		intrinsics.unaligned_store((^x86.__m128i)(raw_data(stream)), block0)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		intrinsics.mem_zero(&block1, BLOCK_SIZE_128_U8)

		intrinsics.mem_copy_non_overlapping(
			&block1,
			raw_data(stream),
			stream_size,
		)

		block3 = transmute(x86.__m128i)(transmute(u128)block3 + 1)
		block0 = encrypt_block_raw_hw(ctx, block3)
		block0 = x86._mm_xor_si128(block0, block1)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block0,
			stream_size,
		)

		intrinsics.mem_zero(&block0, BLOCK_SIZE_128_U8)

		intrinsics.mem_copy_non_overlapping(
			&block0,
			raw_data(stream),
			stream_size,
		)

		block5 = x86._mm_xor_si128(block5, block0)
		block5 = gf128mul_raw_hw(block5, block2)
	}

	block5 = x86._mm_xor_si128(block5, block4)
	block5 = gf128mul_raw_hw(block5, block2)
	block5 = encrypt_block_raw_hw(ctx, block5)

	intrinsics.mem_copy_non_overlapping(
		raw_data(tag),
		&block5,
		tag_size,
	)
}

/* Authenticated encryption: belt-open-dwp */
@(enable_target_feature="sse2,pclmul")
open_dwp_hw :: proc "contextless" (ctx: Context, tag, iv, aad, data: []byte) -> bool #no_bounds_check {
	data_size := len(data); aad_size := len(aad); tag_size := len(tag)

	ensure_contextless(tag_size != 0 && tag_size <= BLOCK_SIZE_64_U8, "crypto/belt: invalid TAG size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")

	block0: x86.__m128i = ---
	block1: x86.__m128i = ---
	block2: x86.__m128i = ---
	block3: x86.__m128i = ---
	block4: x86.__m128i = ---
	block5: x86.__m128i = ---

	BLOCK_T := Block128_U8 {
		0xb1, 0x94, 0xba, 0xc8, 0x0a, 0x08, 0xf5, 0x3b,
		0x36, 0x6d, 0x00, 0x8e, 0x58, 0x4a, 0x5d, 0xe4,
	}

	modulus1 := u64((BITS_PER_BYTE * u128(aad_size))  & u128(max(u64)))
	modulus2 := u64((BITS_PER_BYTE * u128(data_size)) & u128(max(u64)))

	block3 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(iv)))
	block4 = x86.__m128i {transmute(i64)modulus1, transmute(i64)modulus2}
	block5 = transmute(x86.__m128i)BLOCK_T

	block3 = encrypt_block_raw_hw(ctx, block3)
	block2 = encrypt_block_raw_hw(ctx, block3)

	stream := aad
	stream_size := aad_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		block0 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		block5 = x86._mm_xor_si128(block5, block0)
		block5 = gf128mul_raw_hw(block5, block2)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		intrinsics.mem_zero(&block0, BLOCK_SIZE_128_U8)

		intrinsics.mem_copy_non_overlapping(
			&block0,
			raw_data(stream),
			stream_size,
		)

		block5 = x86._mm_xor_si128(block5, block0)
		block5 = gf128mul_raw_hw(block5, block2)
	}

	stream = data
	stream_size = data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		block0 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		block5 = x86._mm_xor_si128(block5, block0)
		block5 = gf128mul_raw_hw(block5, block2)

		block3 = transmute(x86.__m128i)(transmute(u128)block3 + 1)
		block1 = encrypt_block_raw_hw(ctx, block3)
		block1 = x86._mm_xor_si128(block1, block0)

		intrinsics.unaligned_store((^x86.__m128i)(raw_data(stream)), block1)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		intrinsics.mem_zero(&block0, BLOCK_SIZE_128_U8)

		intrinsics.mem_copy_non_overlapping(
			&block0,
			raw_data(stream),
			stream_size,
		)

		block5 = x86._mm_xor_si128(block5, block0)
		block5 = gf128mul_raw_hw(block5, block2)

		block3 = transmute(x86.__m128i)(transmute(u128)block3 + 1)
		block1 = encrypt_block_raw_hw(ctx, block3)
		block1 = x86._mm_xor_si128(block1, block0)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block1,
			stream_size,
		)
	}

	block5 = x86._mm_xor_si128(block5, block4)
	block5 = gf128mul_raw_hw(block5, block2)
	block5 = encrypt_block_raw_hw(ctx, block5)

	if runtime.memory_compare(
		raw_data(tag),
		&block5,
		tag_size,
	) == 0 {
		return true
	} else {
		zero_explicit(raw_data(tag), tag_size)
		zero_explicit(raw_data(data), data_size)

		return false
	}
}

/* Authenticated encryption: belt-seal-che */
@(enable_target_feature="sse2,pclmul")
seal_che_hw :: proc "contextless" (ctx: Context, tag, iv, aad, data: []byte) #no_bounds_check {
	data_size := len(data); aad_size := len(aad); tag_size := len(tag)

	ensure_contextless(tag_size != 0 && tag_size <= BLOCK_SIZE_64_U8, "crypto/belt: invalid TAG size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")

	block0: x86.__m128i = ---
	block1: x86.__m128i = ---
	block2: x86.__m128i = ---
	block3: x86.__m128i = ---
	block4: x86.__m128i = ---
	block5: x86.__m128i = ---
	block6: x86.__m128i = ---

	BLOCK_C := Block128_U8 {
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	BLOCK_T := Block128_U8 {
		0xb1, 0x94, 0xba, 0xc8, 0x0a, 0x08, 0xf5, 0x3b,
		0x36, 0x6d, 0x00, 0x8e, 0x58, 0x4a, 0x5d, 0xe4,
	}

	modulus1 := u64((BITS_PER_BYTE * u128(aad_size))  & u128(max(u64)))
	modulus2 := u64((BITS_PER_BYTE * u128(data_size)) & u128(max(u64)))

	block3 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(iv)))
	block4 = x86.__m128i {transmute(i64)modulus1, transmute(i64)modulus2}
	block5 = transmute(x86.__m128i)BLOCK_C
	block6 = transmute(x86.__m128i)BLOCK_T

	block3 = encrypt_block_raw_hw(ctx, block3)
	block2 = block3

	stream := aad
	stream_size := aad_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		block0 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		block6 = x86._mm_xor_si128(block6, block0)
		block6 = gf128mul_raw_hw(block6, block2)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		intrinsics.mem_zero(&block0, BLOCK_SIZE_128_U8)

		intrinsics.mem_copy_non_overlapping(
			&block0,
			raw_data(stream),
			stream_size,
		)

		block6 = x86._mm_xor_si128(block6, block0)
		block6 = gf128mul_raw_hw(block6, block2)
	}

	stream = data
	stream_size = data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		block1 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		block3 = gf128mul_raw_hw(block3, block5)
		block0 = transmute(x86.__m128i)u128(1)
		block3 = x86._mm_xor_si128(block3, block0)

		block0 = encrypt_block_raw_hw(ctx, block3)
		block0 = x86._mm_xor_si128(block0, block1)

		block6 = x86._mm_xor_si128(block6, block0)
		block6 = gf128mul_raw_hw(block6, block2)

		intrinsics.unaligned_store((^x86.__m128i)(raw_data(stream)), block0)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		intrinsics.mem_zero(&block1, BLOCK_SIZE_128_U8)

		intrinsics.mem_copy_non_overlapping(
			&block1,
			raw_data(stream),
			stream_size,
		)

		block3 = gf128mul_raw_hw(block3, block5)
		block0 = transmute(x86.__m128i)u128(1)
		block3 = x86._mm_xor_si128(block3, block0)

		block0 = encrypt_block_raw_hw(ctx, block3)
		block0 = x86._mm_xor_si128(block0, block1)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block0,
			stream_size,
		)

		intrinsics.mem_zero(&block0, BLOCK_SIZE_128_U8)

		intrinsics.mem_copy_non_overlapping(
			&block0,
			raw_data(stream),
			stream_size,
		)

		block6 = x86._mm_xor_si128(block6, block0)
		block6 = gf128mul_raw_hw(block6, block2)
	}

	block6 = x86._mm_xor_si128(block6, block4)
	block6 = gf128mul_raw_hw(block6, block2)
	block6 = encrypt_block_raw_hw(ctx, block6)

	intrinsics.mem_copy_non_overlapping(
		raw_data(tag),
		&block6,
		tag_size,
	)
}

/* Authenticated encryption: belt-open-che */
@(enable_target_feature="sse2,pclmul")
open_che_hw :: proc "contextless" (ctx: Context, tag, iv, aad, data: []byte) -> bool #no_bounds_check {
	data_size := len(data); aad_size := len(aad); tag_size := len(tag)

	ensure_contextless(tag_size != 0 && tag_size <= BLOCK_SIZE_64_U8, "crypto/belt: invalid TAG size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")

	block0: x86.__m128i = ---
	block1: x86.__m128i = ---
	block2: x86.__m128i = ---
	block3: x86.__m128i = ---
	block4: x86.__m128i = ---
	block5: x86.__m128i = ---
	block6: x86.__m128i = ---

	BLOCK_C := Block128_U8 {
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	BLOCK_T := Block128_U8 {
		0xb1, 0x94, 0xba, 0xc8, 0x0a, 0x08, 0xf5, 0x3b,
		0x36, 0x6d, 0x00, 0x8e, 0x58, 0x4a, 0x5d, 0xe4,
	}

	modulus1 := u64((BITS_PER_BYTE * u128(aad_size))  & u128(max(u64)))
	modulus2 := u64((BITS_PER_BYTE * u128(data_size)) & u128(max(u64)))

	block3 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(iv)))
	block4 = x86.__m128i {transmute(i64)modulus1, transmute(i64)modulus2}
	block5 = transmute(x86.__m128i)BLOCK_C
	block6 = transmute(x86.__m128i)BLOCK_T

	block3 = encrypt_block_raw_hw(ctx, block3)
	block2 = block3

	stream := aad
	stream_size := aad_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		block0 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		block6 = x86._mm_xor_si128(block6, block0)
		block6 = gf128mul_raw_hw(block6, block2)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		intrinsics.mem_zero(&block0, BLOCK_SIZE_128_U8)

		intrinsics.mem_copy_non_overlapping(
			&block0,
			raw_data(stream),
			stream_size,
		)

		block6 = x86._mm_xor_si128(block6, block0)
		block6 = gf128mul_raw_hw(block6, block2)
	}

	stream = data
	stream_size = data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		block0 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		block6 = x86._mm_xor_si128(block6, block0)
		block6 = gf128mul_raw_hw(block6, block2)

		block3 = gf128mul_raw_hw(block3, block5)
		block1 = transmute(x86.__m128i)u128(1)
		block3 = x86._mm_xor_si128(block3, block1)

		block1 = encrypt_block_raw_hw(ctx, block3)
		block1 = x86._mm_xor_si128(block1, block0)

		intrinsics.unaligned_store((^x86.__m128i)(raw_data(stream)), block1)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		intrinsics.mem_zero(&block0, BLOCK_SIZE_128_U8)

		intrinsics.mem_copy_non_overlapping(
			&block0,
			raw_data(stream),
			stream_size,
		)

		block6 = x86._mm_xor_si128(block6, block0)
		block6 = gf128mul_raw_hw(block6, block2)

		block3 = gf128mul_raw_hw(block3, block5)
		block1 = transmute(x86.__m128i)u128(1)
		block3 = x86._mm_xor_si128(block3, block1)

		block1 = encrypt_block_raw_hw(ctx, block3)
		block1 = x86._mm_xor_si128(block1, block0)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block1,
			stream_size,
		)
	}

	block6 = x86._mm_xor_si128(block6, block4)
	block6 = gf128mul_raw_hw(block6, block2)
	block6 = encrypt_block_raw_hw(ctx, block6)

	if runtime.memory_compare(
		raw_data(tag),
		&block6,
		tag_size,
	) == 0 {
		return true
	} else {
		zero_explicit(raw_data(tag), tag_size)
		zero_explicit(raw_data(data), data_size)

		return false
	}
}

/* Key wrap encryption: belt-seal-kwp */
@(enable_target_feature="sse2")
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
@(enable_target_feature="sse2")
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
		zero_explicit(raw_data(iv), BLOCK_SIZE_128_U8)
		zero_explicit(raw_data(data), data_size)
		zero_explicit(raw_data(cipher), cipher_size)

		return false
	}
}

@(enable_target_feature="sse2")
compress_hw :: proc "contextless" (dummy, compr, data: []byte) #no_bounds_check {
	assert_contextless(len(dummy) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DUMMY size")
	assert_contextless(len(compr) == BLOCK_SIZE_256_U8, "crypto/belt: invalid COMPR size")
	assert_contextless(len(data)  == BLOCK_SIZE_256_U8, "crypto/belt: invalid DATA size")

	block: x86.__m128i = ---
	data1: [2]x86.__m128i = ---
	data2: [2]x86.__m128i = ---

	data1 = intrinsics.unaligned_load((^[2]x86.__m128i)(raw_data(data)))
	data2 = intrinsics.unaligned_load((^[2]x86.__m128i)(raw_data(compr)))

	block, data2 = compress_raw_hw(data1, data2)

	intrinsics.unaligned_store((^[2]x86.__m128i)(raw_data(compr)), data2)
	intrinsics.unaligned_store((^x86.__m128i)(raw_data(dummy)), block)
}

@(private = "file", enable_target_feature="sse2")
compress_raw_hw :: proc "contextless" (data1, data2: [2]x86.__m128i) -> (dummy: x86.__m128i, compr: [2]x86.__m128i) #no_bounds_check {
	ctx: Context = ---
	stream: x86.__m128i
	a :: 0; b :: 1

	init_raw(
		&ctx,
		transmute(Block128_U32)data1[a],
		transmute(Block128_U32)data1[b],
	)

	stream = x86._mm_xor_si128(data2[a], data2[b])
	dummy = encrypt_block_raw_hw(ctx, stream)
	dummy = x86._mm_xor_si128(dummy, stream)

	init_raw(
		&ctx,
		transmute(Block128_U32)dummy,
		transmute(Block128_U32)data2[b],
	)

	compr[a] = encrypt_block_raw_hw(ctx, data1[a])
	compr[a] = x86._mm_xor_si128(compr[a], data1[a])

	not := x86.__m128i(-1)
	stream = x86._mm_xor_si128(dummy, not)

	init_raw(
		&ctx,
		transmute(Block128_U32)stream,
		transmute(Block128_U32)data2[a],
	)

	compr[b] = encrypt_block_raw_hw(ctx, data1[b])
	compr[b] = x86._mm_xor_si128(compr[b], data1[b])
	return
}

/* Hash bytes to buffer: belt-hash-bytes-to-buffer */
@(enable_target_feature="sse2")
hash_bytes_to_buffer_hw :: proc "contextless" (data, hash: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(hash) == BLOCK_SIZE_256_U8, "crypto/belt: invalid HASH size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")

	a :: 0; b :: 1
	dummy: x86.__m128i = ---
	block0: [2]x86.__m128i = ---
	block1: [2]x86.__m128i = ---
	block2: [2]x86.__m128i

	BLOCK_H1 := Block128_U8 {
		0xb1, 0x94, 0xba, 0xc8, 0x0a, 0x08, 0xf5, 0x3b,
		0x36, 0x6d, 0x00, 0x8e, 0x58, 0x4a, 0x5d, 0xe4,
	}

	BLOCK_H2 := Block128_U8 {
		0x85, 0x04, 0xfa, 0x9d, 0x1b, 0xb6, 0xc7, 0xac,
		0x25, 0x2e, 0x72, 0xc2, 0x02, 0xfd, 0xce, 0x0d,
	}

	block1[a] = transmute(x86.__m128i)BLOCK_H1
	block1[b] = transmute(x86.__m128i)BLOCK_H2
	block2[a] = transmute(x86.__m128i)(BITS_PER_BYTE * u128(data_size))

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_256_U8 {
		block0 = intrinsics.unaligned_load((^[2]x86.__m128i)(raw_data(stream)))

		dummy, block1 = compress_raw_hw(block0, block1)
		block2[b] = x86._mm_xor_si128(block2[b], dummy)

		stream = stream[BLOCK_SIZE_256_U8:]
		stream_size -= BLOCK_SIZE_256_U8
	}

	if stream_size > 0 {
		intrinsics.mem_zero(&block0, BLOCK_SIZE_256_U8)

		intrinsics.mem_copy_non_overlapping(
			&block0,
			raw_data(stream),
			stream_size,
		)

		dummy, block1 = compress_raw_hw(block0, block1)
		block2[b] = x86._mm_xor_si128(block2[b], dummy)
	}

	dummy, block1 = compress_raw_hw(block2, block1)
	intrinsics.unaligned_store((^[2]x86.__m128i)(raw_data(hash)), block1)
}

/* Block level encryption: belt-encrypt-bde */
@(enable_target_feature="sse2,pclmul")
encrypt_bde_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(
		data_size >= BLOCK_SIZE_128_U8 &&
		data_size & (BLOCK_SIZE_128_U8 - 1) == 0,
		"crypto/belt: invalid DATA size",
	)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block0: x86.__m128i = ---
	block1: x86.__m128i = ---
	block2: x86.__m128i = ---

	BLOCK_C := Block128_U8 {
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	block1 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(iv)))
	block2 = transmute(x86.__m128i)BLOCK_C
	block1 = encrypt_block_raw_hw(ctx, block1)

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		block0 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		block1 = gf128mul_raw_hw(block1, block2)
		block0 = x86._mm_xor_si128(block0, block1)
		block0 = encrypt_block_raw_hw(ctx, block0)
		block0 = x86._mm_xor_si128(block0, block1)

		intrinsics.unaligned_store((^x86.__m128i)(raw_data(stream)), block0)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}
}

/* Block level encryption: belt-decrypt-bde */
@(enable_target_feature="sse2,pclmul")
decrypt_bde_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(
		data_size >= BLOCK_SIZE_128_U8 &&
		data_size & (BLOCK_SIZE_128_U8 - 1) == 0,
		"crypto/belt: invalid DATA size",
	)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block0: x86.__m128i = ---
	block1: x86.__m128i = ---
	block2: x86.__m128i = ---

	BLOCK_C := Block128_U8 {
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	block1 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(iv)))
	block2 = transmute(x86.__m128i)BLOCK_C
	block1 = encrypt_block_raw_hw(ctx, block1)

	stream := data
	stream_size := data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		block0 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

		block1 = gf128mul_raw_hw(block1, block2)
		block0 = x86._mm_xor_si128(block0, block1)
		block0 = decrypt_block_raw_hw(ctx, block0)
		block0 = x86._mm_xor_si128(block0, block1)

		intrinsics.unaligned_store((^x86.__m128i)(raw_data(stream)), block0)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}
}

/* Sector level encryption: belt-encrypt-sde */
@(enable_target_feature="sse2")
encrypt_sde_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(
		data_size >= BLOCK_SIZE_256_U8 &&
		data_size & (BLOCK_SIZE_128_U8 - 1) == 0,
		"crypto/belt: invalid DATA size",
	)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block1: x86.__m128i = ---
	block2: x86.__m128i = ---

	block1 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(data)))
	block2 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(iv)))

	block2 = encrypt_block_raw_hw(ctx, block2)
	block1 = x86._mm_xor_si128(block1, block2)

	intrinsics.unaligned_store((^x86.__m128i)(raw_data(data)), block1)

	encrypt_wide_block_hw(ctx, data)

	block1 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(data)))
	block1 = x86._mm_xor_si128(block1, block2)

	intrinsics.unaligned_store((^x86.__m128i)(raw_data(data)), block1)
}

/* Sector level encryption: belt-decrypt-sde */
@(enable_target_feature="sse2")
decrypt_sde_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(
		data_size >= BLOCK_SIZE_256_U8 &&
		data_size & (BLOCK_SIZE_128_U8 - 1) == 0,
		"crypto/belt: invalid DATA size",
	)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block1: x86.__m128i = ---
	block2: x86.__m128i = ---

	block1 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(data)))
	block2 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(iv)))

	block2 = encrypt_block_raw_hw(ctx, block2)
	block1 = x86._mm_xor_si128(block1, block2)

	intrinsics.unaligned_store((^x86.__m128i)(raw_data(data)), block1)

	decrypt_wide_block_hw(ctx, data)

	block1 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(data)))
	block1 = x86._mm_xor_si128(block1, block2)

	intrinsics.unaligned_store((^x86.__m128i)(raw_data(data)), block1)
}

/* Derive key {128, 192, 256} from key {128, 192, 256}: belt-derive-key */
@(enable_target_feature="sse2")
derive_key_hw :: proc "contextless" (depth, iv, dst, src: []byte) #no_bounds_check {
	dst_size := len(dst); src_size := len(src)

	ensure_contextless(
		src_size == BLOCK_SIZE_128_U8 ||
		src_size == BLOCK_SIZE_192_U8 ||
		src_size == BLOCK_SIZE_256_U8,
		"crypto/belt: invalid SRC size",
	)

	ensure_contextless(
		dst_size == BLOCK_SIZE_128_U8 ||
		dst_size == BLOCK_SIZE_192_U8 ||
		dst_size == BLOCK_SIZE_256_U8,
		"crypto/belt: invalid DST size",
	)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(len(depth) == BLOCK_SIZE_96_U8, "crypto/belt: invalid DEPTH size")

	dummy: Block128_U8 = ---
	key: Key256_U8 = ---
	stream: Block256_U8 = ---

	BLOCK_R: Block32_U8
	if src_size == BLOCK_SIZE_128_U8 && dst_size == BLOCK_SIZE_128_U8 {
		BLOCK_R = Block32_U8 {0xb1, 0x94, 0xba, 0xc8}
	} else if src_size == BLOCK_SIZE_192_U8 && dst_size == BLOCK_SIZE_128_U8 {
		BLOCK_R = Block32_U8 {0x5b, 0xe3, 0xd6, 0x12}
	} else if src_size == BLOCK_SIZE_192_U8 && dst_size == BLOCK_SIZE_192_U8 {
		BLOCK_R = Block32_U8 {0x5c, 0xb0, 0xc0, 0xff}
	} else if src_size == BLOCK_SIZE_256_U8 && dst_size == BLOCK_SIZE_128_U8 {
		BLOCK_R = Block32_U8 {0xe1, 0x2b, 0xdc, 0x1a}
	} else if src_size == BLOCK_SIZE_256_U8 && dst_size == BLOCK_SIZE_192_U8 {
		BLOCK_R = Block32_U8 {0xc1, 0xab, 0x76, 0x38}
	} else if src_size == BLOCK_SIZE_256_U8 && dst_size == BLOCK_SIZE_256_U8 {
		BLOCK_R = Block32_U8 {0xf3, 0x3c, 0x65, 0x7b}
	}

	intrinsics.mem_copy_non_overlapping(
		raw_data(stream[:BLOCK_SIZE_32_U8]),
		&BLOCK_R,
		BLOCK_SIZE_32_U8,
	)

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

@(private = "file", enable_target_feature="sse2")
encrypt_block32_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	assert_contextless(len(data) == BLOCK_SIZE_192_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	block: x86.__m128i = ---
	stream1: x86.__m128i
	stream2: x86.__m128i = ---

	intrinsics.mem_copy_non_overlapping(
		&stream1,
		raw_data(data),
		BLOCK_SIZE_64_U8,
	)

	stream := data[BLOCK_SIZE_64_U8:]
	stream2 = intrinsics.unaligned_load((^x86.__m128i)(raw_data(stream)))

	#unroll for round in 1..=3 {
		block = transmute(x86.__m128i)u128(round)
		stream2 = encrypt_block_raw_hw(ctx, stream2)
		stream2 = x86._mm_xor_si128(stream2, block)

		block = x86._mm_set_epi32(0, 0, -1, -1)
		block = x86._mm_and_si128(stream2, block)

		stream2 = x86._mm_xor_si128(stream2, stream1)
		stream2 = x86._mm_shuffle_epi32(stream2, 0x4e)
		stream1 = block
	}

	intrinsics.mem_copy_non_overlapping(
		raw_data(data),
		&stream1,
		BLOCK_SIZE_64_U8,
	)

	intrinsics.unaligned_store((^x86.__m128i)(raw_data(stream)), stream2)
}

@(private = "file", enable_target_feature="sse2")
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
@(enable_target_feature="sse2")
encrypt_fmt_hw :: proc "contextless" (ctx: Context, m: int, iv: []byte, data: []u16) #no_bounds_check {
	data_size := len(data); iv_size := len(iv)

	ensure_contextless(data_size >= M_MIN_INT && data_size <= M_MAX_INT, "crypto/belt: invalid DATA size")
	ensure_contextless(m >= M_MIN_INT && m <= M_MAX_INT, "crypto/belt: invalid M value")
	ensure_contextless(iv_size == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	backbuff1: Backbuff_U8 = ---
	backbuff2: Backbuff_U8 = ---

	stream: Block32_U8 = ---
	intrinsics.unaligned_store((^u16)(raw_data(stream[:BLOCK_SIZE_16_U8])), u16(m))
	intrinsics.unaligned_store((^u16)(raw_data(stream[BLOCK_SIZE_16_U8:])), u16(data_size))

	table1 := [?]Block32_U8 {
		Block32_U8 {0xb1, 0x94, 0xba, 0xc8},
		Block32_U8 {0x0a, 0x08, 0xf5, 0x3b},
		Block32_U8 {0x36, 0x6d, 0x00, 0x8e},
		Block32_U8 {0x58, 0x4a, 0x5d, 0xe4},
		Block32_U8 {0x85, 0x04, 0xfa, 0x9d},
		Block32_U8 {0x1b, 0xb6, 0xc7, 0xac},
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
			&table1[2 * round],
			BLOCK_SIZE_32_U8,
		)

		roundf_hw(ctx, block2)
		bin2str_add(m, data1, block2)

		str2bin(m, block1[:block1_size], data1)

		intrinsics.mem_copy_non_overlapping(
			raw_data(block1[block1_size + BLOCK_SIZE_32_U8:]),
			raw_data(table2[1 + 2 * round]),
			BLOCK_SIZE_32_U8,
		)

		intrinsics.mem_copy_non_overlapping(
			raw_data(block1[block1_size: block2_size + BLOCK_SIZE_32_U8]),
			&table1[1 + 2 * round],
			BLOCK_SIZE_32_U8,
		)

		roundf_hw(ctx, block1)
		bin2str_add(m, data2, block1)
	}
}

/* Format preserving encryption: belt-decrypt-fmt */
@(enable_target_feature="sse2")
decrypt_fmt_hw :: proc "contextless" (ctx: Context, m: int, iv: []byte, data: []u16) #no_bounds_check {
	data_size := len(data); iv_size := len(iv)

	ensure_contextless(data_size >= M_MIN_INT && data_size <= M_MAX_INT, "crypto/belt: invalid DATA size")
	ensure_contextless(m >= M_MIN_INT && m <= M_MAX_INT, "crypto/belt: invalid M value")
	ensure_contextless(iv_size == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	backbuff1: Backbuff_U8 = ---
	backbuff2: Backbuff_U8 = ---

	stream: Block32_U8 = ---
	intrinsics.unaligned_store((^u16)(raw_data(stream[:BLOCK_SIZE_16_U8])), u16(m))
	intrinsics.unaligned_store((^u16)(raw_data(stream[BLOCK_SIZE_16_U8:])), u16(data_size))

	table1 := [?]Block32_U8 {
		Block32_U8 {0xb1, 0x94, 0xba, 0xc8},
		Block32_U8 {0x0a, 0x08, 0xf5, 0x3b},
		Block32_U8 {0x36, 0x6d, 0x00, 0x8e},
		Block32_U8 {0x58, 0x4a, 0x5d, 0xe4},
		Block32_U8 {0x85, 0x04, 0xfa, 0x9d},
		Block32_U8 {0x1b, 0xb6, 0xc7, 0xac},
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
			&table1[5 - 2 * round],
			BLOCK_SIZE_32_U8,
		)

		roundf_hw(ctx, block1)
		bin2str_sub(m, data2, block1)

		str2bin(m, block2[:block2_size], data2)

		intrinsics.mem_copy_non_overlapping(
			raw_data(block2[block2_size + BLOCK_SIZE_32_U8:]),
			raw_data(table2[4 - 2 * round]),
			BLOCK_SIZE_32_U8,
		)

		intrinsics.mem_copy_non_overlapping(
			raw_data(block2[block2_size: block2_size + BLOCK_SIZE_32_U8]),
			&table1[4 - 2 * round],
			BLOCK_SIZE_32_U8,
		)

		roundf_hw(ctx, block2)
		bin2str_sub(m, data1, block2)
	}
}
