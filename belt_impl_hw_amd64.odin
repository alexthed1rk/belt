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
encrypt_block_hw :: proc "contextless" (ctx: Context, block: []byte) #no_bounds_check {
	assert_contextless(len(block) == BLOCK_SIZE_128_U8, "crypto/belt: invalid DATA size")
	assert_contextless(ctx.is_initialized, "crypto/belt: CTX is not initialized")

	_block_: x86.__m128i
	stream: Block128_U32

	intrinsics.mem_copy_non_overlapping(
		&_block_,
		raw_data(block),
		BLOCK_SIZE_128_U8,
	)

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

	_block_ = x86._mm_shuffle_epi32(_block_, 0x8d)

	intrinsics.mem_copy_non_overlapping(
		raw_data(block),
		&_block_,
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
