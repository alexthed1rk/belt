#+build amd64
package belt

/* STB 34.101.31-2020                                    */
/* Information technology and security                   */
/* Encryption and integrity control algorithms           */
/* https://apmi.bsu.by/assets/files/std/belt-spec371.pdf */

import "base:intrinsics"
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
gf128mul_hw :: proc "contextless" (a, b: x86.__m128i) -> x86.__m128i {
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

/* Block cipher: belt-encrypt-block */
@(enable_target_feature="sse2")
encrypt_block_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	assert_contextless(len(data) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	stream: x86.__m128i
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

@(require_results, private = "file", enable_target_feature="sse2")
encrypt_block_raw_hw :: proc "contextless" (ctx: Context, block: x86.__m128i) -> x86.__m128i #no_bounds_check {
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

		_block_ = transmute(x86.__m128i)stream
		_block_ = x86._mm_shuffle_epi32(_block_, 0x8d)
	}

	return x86._mm_shuffle_epi32(_block_, 0x8d)
}

/* Block cipher: belt-decrypt-block */
@(enable_target_feature="sse2")
decrypt_block_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	assert_contextless(len(data) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	stream: x86.__m128i
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

@(require_results, private = "file", enable_target_feature="sse2")
decrypt_block_raw_hw :: proc "contextless" (ctx: Context, block: x86.__m128i) -> x86.__m128i #no_bounds_check {
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

		_block_ = transmute(x86.__m128i)stream
		_block_ = x86._mm_shuffle_epi32(_block_, 0x72)
	}

	return x86._mm_shuffle_epi32(_block_, 0x72)
}

/* Wide block cipher: belt-encrypt-wide-block */
@(enable_target_feature="sse2")
encrypt_wide_block_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	data_size := len(data)

	assert_contextless(data_size >= BLOCK_SIZE_256_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_stream_: x86.__m128i

	block1: x86.__m128i = ---
	block2: x86.__m128i = ---

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

			block1 = x86._mm_xor_si128(block1, _stream_)

			stream = stream[BLOCK_SIZE_128_U8:]
			stream_size -= BLOCK_SIZE_128_U8
		}

		copy_slice(data[:data_size - BLOCK_SIZE_128_U8], data[BLOCK_SIZE_128_U8:])

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
		block2 = transmute(x86.__m128i)u128(round)
		block1 = x86._mm_xor_si128(block1, block2)
		block1 = x86._mm_xor_si128(block1, _stream_)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block1,
			BLOCK_SIZE_128_U8,
		)
	}
}

/* Wide block cipher: belt-decrypt-wide-block */
@(enable_target_feature="sse2")
decrypt_wide_block_hw :: proc "contextless" (ctx: Context, data: []byte) #no_bounds_check {
	data_size := len(data)

	assert_contextless(data_size >= BLOCK_SIZE_256_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_stream_: x86.__m128i

	block1: x86.__m128i = ---
	block2: x86.__m128i = ---

	num_rounds := 2 * ((uint(data_size) + BLOCK_SIZE_128_U8 - 1) / BLOCK_SIZE_128_U8)
	for round := num_rounds; round >= 1; round -= 1 {

		stream := data[data_size - BLOCK_SIZE_128_U8:]
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		copy_slice(data[BLOCK_SIZE_128_U8:], data[:data_size - BLOCK_SIZE_128_U8])

		block1 = encrypt_block_raw_hw(ctx, _stream_)
		block2 = transmute(x86.__m128i)u128(round)
		block1 = x86._mm_xor_si128(block1, block2)

		stream = data[data_size - BLOCK_SIZE_128_U8:]
		intrinsics.mem_copy_non_overlapping(
			&block2,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block2 = x86._mm_xor_si128(block2, block1)
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

			_stream_ = x86._mm_xor_si128(_stream_, block1)

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
@(enable_target_feature="sse2")
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
@(enable_target_feature="sse2")
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

/* Cipher feedback encryption: belt-encrypt-cfb */
@(enable_target_feature="sse2")
encrypt_cfb_hw :: proc "contextless" (ctx: Context, iv, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_stream_: x86.__m128i

	block: x86.__m128i = ---

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
		block = x86._mm_xor_si128(block, _stream_)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block,
			BLOCK_SIZE_128_U8,
		)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		_stream_ = x86.__m128i{}

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			stream_size,
		)

		block = encrypt_block_raw_hw(ctx, block)
		block = x86._mm_xor_si128(block, _stream_)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block,
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

	_stream_: x86.__m128i

	block: x86.__m128i = ---

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
		block = x86._mm_xor_si128(block, _stream_)

		_stream_ = x86._mm_xor_si128(_stream_, block)
		block = x86._mm_xor_si128(block, _stream_)
		_stream_ = x86._mm_xor_si128(_stream_, block)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&_stream_,
			BLOCK_SIZE_128_U8,
		)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		_stream_ = x86.__m128i{}

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			stream_size,
		)

		block = encrypt_block_raw_hw(ctx, block)
		block = x86._mm_xor_si128(block, _stream_)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block,
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

	_stream_: x86.__m128i

	block1: x86.__m128i = ---
	block2: x86.__m128i = ---

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

		block2 = transmute(x86.__m128i)(transmute(u128)block2 + 1)
		block1 = encrypt_block_raw_hw(ctx, block2)
		block1 = x86._mm_xor_si128(block1, _stream_)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&block1,
			BLOCK_SIZE_128_U8,
		)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		_stream_ = x86.__m128i{}

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			stream_size,
		)

		block2 = transmute(x86.__m128i)(transmute(u128)block2 + 1)
		block1 = encrypt_block_raw_hw(ctx, block2)
		block1 = x86._mm_xor_si128(block1, _stream_)

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
table_φ1_hw :: #force_inline proc "contextless" (data: x86.__m128i) -> x86.__m128i {
	block1, block2: x86.__m128i
	block1 = x86._mm_shuffle_epi32(data, 0x39)
	block2 = x86._mm_slli_si128(block1, 0x0c)
	return x86._mm_xor_si128(block1, block2)
}

@(require_results, private = "file", enable_target_feature="sse2")
table_φ2_hw :: #force_inline proc "contextless" (data: x86.__m128i) -> x86.__m128i {
	block1, block2: x86.__m128i
	block1 = x86._mm_shuffle_epi32(data, 0x93)
	block2 = x86._mm_set_epi32(0, 0, 0, -1)
	block2 = x86._mm_and_si128(data, block2)
	return x86._mm_xor_si128(block1, block2)
}

/* Message authentication code derivation: belt-derive-mac */
@(enable_target_feature="sse2")
derive_mac_hw :: proc "contextless" (ctx: Context, mac, data: []byte) #no_bounds_check {
	data_size := len(data)

	ensure_contextless(len(mac) == MAC_SIZE_64_U8, "crypto/belt: invalid MAC size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_bytes_: Block128_U8
	_stream_: x86.__m128i

	block1: x86.__m128i
	block2: x86.__m128i

	stream := data
	stream_size := data_size

	block1 = encrypt_block_raw_hw(ctx, block1)
	for stream_size > BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block2 = x86._mm_xor_si128(block2, _stream_)
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
		block2 = x86._mm_xor_si128(block2, block1)
		block2 = x86._mm_xor_si128(block2, _stream_)
	} else {
		intrinsics.mem_copy_non_overlapping(
			&_bytes_,
			raw_data(stream),
			stream_size,
		)

		ψ_unit :: 0x80
		_bytes_[stream_size] = ψ_unit
		_stream_ = transmute(x86.__m128i)_bytes_

		block1 = table_φ2_hw(block1)
		block2 = x86._mm_xor_si128(block2, block1)
		block2 = x86._mm_xor_si128(block2, _stream_)
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
@(enable_target_feature="sse2,pclmul")
seal_dwp_hw :: proc "contextless" (ctx: Context, iv, aad, mac, data: []byte) #no_bounds_check {
	data_size := len(data); aad_size := len(aad); mac_size := len(mac)

	ensure_contextless(mac_size != 0 && mac_size <= MAC_SIZE_64_U8, "crypto/belt: invalid MAC size")
	ensure_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")
	ensure_contextless(len(iv) == BLOCK_SIZE_128_U8, "crypto/belt: invalid IV size")
	ensure_contextless(data_size != 0, "crypto/belt: invalid DATA size")

	_stream_: x86.__m128i

	block1: x86.__m128i = ---
	block2: x86.__m128i = ---
	block3: x86.__m128i = ---
	block4: x86.__m128i = ---
	block5: x86.__m128i = ---

	modulus1 := u64((BITS_PER_BYTE * u128(aad_size))  & u128(max(u64)))
	modulus2 := u64((BITS_PER_BYTE * u128(data_size)) & u128(max(u64)))

	intrinsics.mem_copy_non_overlapping(
		&block3,
		raw_data(iv),
		BLOCK_SIZE_128_U8,
	)

	block4 = x86.__m128i {transmute(i64)modulus1, transmute(i64)modulus2}
	block5 = transmute(x86.__m128i)BLOCK_T

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

		block5 = x86._mm_xor_si128(block5, _stream_)
		block5 = gf128mul_hw(block5, block2)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		_stream_ = x86.__m128i{}

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			stream_size,
		)

		block5 = x86._mm_xor_si128(block5, _stream_)
		block5 = gf128mul_hw(block5, block2)
	}

	stream = data
	stream_size = data_size
	for stream_size >= BLOCK_SIZE_128_U8 {
		intrinsics.mem_copy_non_overlapping(
			&block1,
			raw_data(stream),
			BLOCK_SIZE_128_U8,
		)

		block3 = transmute(x86.__m128i)(transmute(u128)block3 + 1)
		_stream_ = encrypt_block_raw_hw(ctx, block3)
		_stream_ = x86._mm_xor_si128(_stream_, block1)

		block5 = x86._mm_xor_si128(block5, _stream_)
		block5 = gf128mul_hw(block5, block2)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&_stream_,
			BLOCK_SIZE_128_U8,
		)

		stream = stream[BLOCK_SIZE_128_U8:]
		stream_size -= BLOCK_SIZE_128_U8
	}

	if stream_size > 0 {
		block1 = x86.__m128i{}

		intrinsics.mem_copy_non_overlapping(
			&block1,
			raw_data(stream),
			stream_size,
		)

		block3 = transmute(x86.__m128i)(transmute(u128)block3 + 1)
		_stream_ = encrypt_block_raw_hw(ctx, block3)
		_stream_ = x86._mm_xor_si128(_stream_, block1)

		intrinsics.mem_copy_non_overlapping(
			raw_data(stream),
			&_stream_,
			stream_size,
		)

		_stream_ = x86.__m128i{}

		intrinsics.mem_copy_non_overlapping(
			&_stream_,
			raw_data(stream),
			stream_size,
		)

		block5 = x86._mm_xor_si128(block5, _stream_)
		block5 = gf128mul_hw(block5, block2)
	}

	block5 = x86._mm_xor_si128(block5, block4)
	block5 = gf128mul_hw(block5, block2)
	block5 = encrypt_block_raw_hw(ctx, block5)

	intrinsics.mem_copy_non_overlapping(
		raw_data(mac),
		&block5,
		mac_size,
	)
}
