#+build amd64,arm64
package belt

/* STB 34.101.31-2020                                    */
/* Information technology and security                   */
/* Encryption and integrity control algorithms           */
/* https://apmi.bsu.by/assets/files/std/belt-spec371.pdf */

import "core:encoding/hex"
import "core:testing"

@(test)
test_encrypt_block_hw :: proc (t: ^testing.T) {
	key_string   := "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6"

	block_string := "b194bac80a08f53b366d008e584a5de4"
	truth_string := "69cca1c93557c9e3d66bc3e0fa88fa6e"

	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)
	key_data,   _ := hex.decode(transmute([]byte)key_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	encrypt_block_hw(ctx, block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected: %s for encrypt_block_hw(%s, %s), but got %s instead",
		truth_string,
		block_string,
		key_string,
		check_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_decrypt_block_hw :: proc (t: ^testing.T) {
	key_string   := "92bd9b1ce5d141015445fbc95e4d0ef2682080aa227d642f2687f93490405511"

	block_string := "e12bdc1ae28257ec703fccf095ee8df1"
	truth_string := "0dc5300600cab840b38448e5e993f421"

	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)
	key_data,   _ := hex.decode(transmute([]byte)key_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	decrypt_block_hw(ctx, block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected: %s for decrypt_block_hw(%s, %s), but got %s instead",
		truth_string,
		block_string,
		key_string,
		check_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_encrypt_wide_block_hw :: proc (t: ^testing.T) {
	key_string    := "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6"

	block_string1 := "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d5be3d61217b96181fe6786ad716b890b"
	truth_string1 := "49a38ee108d6c742e52b774f00a6ef98b106cbd13ea4fb0680323051bc04df76e487b055c69bcf541176169f1dc9f6c8"

	block_string2 := "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d5be3d61217b96181fe6786ad716b89"
	truth_string2 := "f08ef22dcaa06c81fb12721974221ca7ab82c62856fcf2f9fca006e019a28f16e5821a51f573594625dbab8f6a5c94"

	key_data,    _ := hex.decode(transmute([]byte)key_string,    context.temp_allocator)
	block_data1, _ := hex.decode(transmute([]byte)block_string1, context.temp_allocator)
	block_data2, _ := hex.decode(transmute([]byte)block_string2, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	encrypt_wide_block_hw(ctx, block_data1)
	encrypt_wide_block_hw(ctx, block_data2)

	check_string1 := string(hex.encode(block_data1, context.temp_allocator))
	check_string2 := string(hex.encode(block_data2, context.temp_allocator))

	testing.expectf(
		t,
		check_string1 == truth_string1,
		"crypto/belt: expected: %s for encrypt_wide_block_hw(%s, %s), but got %s instead",
		truth_string1,
		block_string1,
		key_string,
		check_string1,
	)

	testing.expectf(
		t,
		check_string2 == truth_string2,
		"crypto/belt: expected: %s for encrypt_wide_block_hw(%s, %s), but got %s instead",
		truth_string2,
		block_string2,
		key_string,
		check_string2,
	)

	free_all(context.temp_allocator)
}

@(test)
test_decrypt_wide_block_hw :: proc (t: ^testing.T) {
	key_string    := "92bd9b1ce5d141015445fbc95e4d0ef2682080aa227d642f2687f93490405511"

	block_string1 := "e12bdc1ae28257ec703fccf095ee8df1c1ab76389fe678caf7c6f860d5bb9c4ff33c657b637c306add4ea7799eb23d31"
	truth_string1 := "92632ee0c21ad9e09a39343e5c07daa4889b03f2e6847eb152ec99f7a4d9f154b5ef68d8e4a39e567153de13d72254ee"

	block_string2 := "e12bdc1ae28257ec703fccf095ee8df1c1ab76389fe678caf7c6f860d5bb9c4ff33c657b"
	truth_string2 := "df3f882230baaffc92f05660321172310e3cb2182681ef43102e67175e177bd75e93e4e8"

	key_data,    _ := hex.decode(transmute([]byte)key_string,    context.temp_allocator)
	block_data1, _ := hex.decode(transmute([]byte)block_string1, context.temp_allocator)
	block_data2, _ := hex.decode(transmute([]byte)block_string2, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	decrypt_wide_block_hw(ctx, block_data1)
	decrypt_wide_block_hw(ctx, block_data2)

	check_string1 := string(hex.encode(block_data1, context.temp_allocator))
	check_string2 := string(hex.encode(block_data2, context.temp_allocator))

	testing.expectf(
		t,
		check_string1 == truth_string1,
		"crypto/belt: expected: %s for decrypt_wide_block_hw(%s, %s), but got %s instead",
		truth_string1,
		block_string1,
		key_string,
		check_string1,
	)

	testing.expectf(
		t,
		check_string2 == truth_string2,
		"crypto/belt: expected: %s for decrypt_wide_block_hw(%s, %s), but got %s instead",
		truth_string2,
		block_string2,
		key_string,
		check_string2,
	)

	free_all(context.temp_allocator)
}

@(test)
test_encrypt_ecb_hw :: proc (t: ^testing.T) {
	key_string    := "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6"

	block_string1 := "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d5be3d61217b96181fe6786ad716b890b"
	truth_string1 := "69cca1c93557c9e3d66bc3e0fa88fa6e5f23102ef109710775017f73806da9dc46fb2ed2ce771f26dcb5e5d1569f9ab0"

	block_string2 := "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d5be3d61217b96181fe6786ad716b89"
	truth_string2 := "69cca1c93557c9e3d66bc3e0fa88fa6e36f00cfed6d1ca1498c12798f4beb2075f23102ef109710775017f73806da9"

	key_data,    _ := hex.decode(transmute([]byte)key_string,    context.temp_allocator)
	block_data1, _ := hex.decode(transmute([]byte)block_string1, context.temp_allocator)
	block_data2, _ := hex.decode(transmute([]byte)block_string2, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	encrypt_ecb_hw(ctx, block_data1)
	encrypt_ecb_hw(ctx, block_data2)

	check_string1 := string(hex.encode(block_data1, context.temp_allocator))
	check_string2 := string(hex.encode(block_data2, context.temp_allocator))

	testing.expectf(
		t,
		check_string1 == truth_string1,
		"crypto/belt: expected: %s for encrypt_ecb_hw(%s, %s), but got %s instead",
		truth_string1,
		block_string1,
		key_string,
		check_string1,
	)

	testing.expectf(
		t,
		check_string2 == truth_string2,
		"crypto/belt: expected: %s for encrypt_ecb_hw(%s, %s), but got %s instead",
		truth_string2,
		block_string2,
		key_string,
		check_string2,
	)

	free_all(context.temp_allocator)
}

@(test)
test_decrypt_ecb_hw :: proc (t: ^testing.T) {
	key_string    := "92bd9b1ce5d141015445fbc95e4d0ef2682080aa227d642f2687f93490405511"

	block_string1 := "e12bdc1ae28257ec703fccf095ee8df1c1ab76389fe678caf7c6f860d5bb9c4ff33c657b637c306add4ea7799eb23d31"
	truth_string1 := "0dc5300600cab840b38448e5e993f421e55a239f2ab5c5d5fdb6e81b40938e2a54120ca3e6e19c7ad750fc3531daeab7"

	block_string2 := "e12bdc1ae28257ec703fccf095ee8df1c1ab76389fe678caf7c6f860d5bb9c4ff33c657b"
	truth_string2 := "0dc5300600cab840b38448e5e993f4215780a6e2b69eafbb258726d7b6718523e55a239f"

	key_data,    _ := hex.decode(transmute([]byte)key_string,    context.temp_allocator)
	block_data1, _ := hex.decode(transmute([]byte)block_string1, context.temp_allocator)
	block_data2, _ := hex.decode(transmute([]byte)block_string2, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	decrypt_ecb_hw(ctx, block_data1)
	decrypt_ecb_hw(ctx, block_data2)

	check_string1 := string(hex.encode(block_data1, context.temp_allocator))
	check_string2 := string(hex.encode(block_data2, context.temp_allocator))

	testing.expectf(
		t,
		check_string1 == truth_string1,
		"crypto/belt: expected: %s for decrypt_ecb_hw(%s, %s), but got %s instead",
		truth_string1,
		block_string1,
		key_string,
		check_string1,
	)

	testing.expectf(
		t,
		check_string2 == truth_string2,
		"crypto/belt: expected: %s for decrypt_ecb_hw(%s, %s), but got %s instead",
		truth_string2,
		block_string2,
		key_string,
		check_string2,
	)

	free_all(context.temp_allocator)
}

@(test)
test_encrypt_cfb_hw :: proc (t: ^testing.T) {
	key_string   := "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6"
	iv_string    := "be32971343fc9a48a02a885f194b09a1"

	block_string := "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d5be3d61217b96181fe6786ad716b890b"
	truth_string := "c31e490a90efa374626cc99e4b7b8540a6e48685464a5a06849c9ca769a1b0ae55c2cc5939303ec832dd2fe16c8e5a1b"

	key_data,   _ := hex.decode(transmute([]byte)key_string,   context.temp_allocator)
	iv_data,    _ := hex.decode(transmute([]byte)iv_string,    context.temp_allocator)
	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	encrypt_cfb_hw(ctx, iv_data, block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected: %s for encrypt_cfb_hw(%s, %s, %s), but got %s instead",
		truth_string,
		block_string,
		iv_string,
		key_string,
		check_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_decrypt_cfb_hw :: proc (t: ^testing.T) {
	key_string   := "92bd9b1ce5d141015445fbc95e4d0ef2682080aa227d642f2687f93490405511"
	iv_string    := "7ecda4d01544af8ca58450bf66d2e88a"

	block_string := "e12bdc1ae28257ec703fccf095ee8df1c1ab76389fe678caf7c6f860d5bb9c4ff33c657b637c306add4ea7799eb23d31"
	truth_string := "fa9d107a86f375ee65cd1db881224bd016aff814938ed39b3361abb0bf0851b652244eb06842dd4c94aa4500774e40bb"

	key_data,   _ := hex.decode(transmute([]byte)key_string,   context.temp_allocator)
	iv_data,    _ := hex.decode(transmute([]byte)iv_string,    context.temp_allocator)
	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	decrypt_cfb_hw(ctx, iv_data, block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected: %s for decrypt_cfb_hw(%s, %s, %s), but got %s instead",
		truth_string,
		block_string,
		iv_string,
		key_string,
		check_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_encrypt_ctr_hw :: proc (t: ^testing.T) {
	key_string   := "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6"
	iv_string    := "be32971343fc9a48a02a885f194b09a1"

	block_string := "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d5be3d61217b96181fe6786ad716b890b"
	truth_string := "52c9af96ff50f64435fc43def56bd797d5b5b1ff79fb41257ab9cdf6e63e81f8f00341473eae409833622de05213773a"

	key_data,   _ := hex.decode(transmute([]byte)key_string,   context.temp_allocator)
	iv_data,    _ := hex.decode(transmute([]byte)iv_string,    context.temp_allocator)
	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	encrypt_ctr_hw(ctx, iv_data, block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected: %s for encrypt_ctr_hw(%s, %s, %s), but got %s instead",
		truth_string,
		block_string,
		iv_string,
		key_string,
		check_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_decrypt_ctr_hw :: proc (t: ^testing.T) {
	key_string   := "92bd9b1ce5d141015445fbc95e4d0ef2682080aa227d642f2687f93490405511"
	iv_string    := "7ecda4d01544af8ca58450bf66d2e88a"

	block_string := "e12bdc1ae28257ec703fccf095ee8df1c1ab76389fe678caf7c6f860d5bb9c4ff33c657b637c306add4ea779"
	truth_string := "df181ed008a20f43dcbbb93650dad34b389cdee5826d40e2d4bd80f49a93f5d212f6333166456f169043cc5f"

	key_data,   _ := hex.decode(transmute([]byte)key_string,   context.temp_allocator)
	iv_data,    _ := hex.decode(transmute([]byte)iv_string,    context.temp_allocator)
	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	decrypt_ctr_hw(ctx, iv_data, block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected: %s for decrypt_ctr_hw(%s, %s, %s), but got %s instead",
		truth_string,
		block_string,
		iv_string,
		key_string,
		check_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_derive_mac_hw :: proc (t: ^testing.T) {
	key_string        := "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6"

	block_string1     := "b194bac80a08f53b366d008e58"
	truth_mac_string1 := "7260da60138f96c9"

	block_string2     := "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d5be3d61217b96181fe6786ad716b890b"
	truth_mac_string2 := "2dab59771b4b16d0"

	key_data,    _ := hex.decode(transmute([]byte)key_string,    context.temp_allocator)
	block_data1, _ := hex.decode(transmute([]byte)block_string1, context.temp_allocator)
	block_data2, _ := hex.decode(transmute([]byte)block_string2, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	check_mac_data1: Mac64_U8 = ---
	check_mac_data2: Mac64_U8 = ---

	derive_mac_hw(ctx, check_mac_data1[:], block_data1)
	derive_mac_hw(ctx, check_mac_data2[:], block_data2)

	check_mac_string1 := string(hex.encode(check_mac_data1[:], context.temp_allocator))
	check_mac_string2 := string(hex.encode(check_mac_data2[:], context.temp_allocator))

	testing.expectf(
		t,
		check_mac_string1 == truth_mac_string1,
		"crypto/belt: expected: %s for derive_mac_hw(%s, %s), but got %s instead",
		truth_mac_string1,
		block_string1,
		key_string,
		check_mac_string1,
	)

	testing.expectf(
		t,
		check_mac_string2 == truth_mac_string2,
		"crypto/belt: expected: %s for derive_mac_hw(%s, %s), but got %s instead",
		truth_mac_string2,
		block_string2,
		key_string,
		check_mac_string2,
	)

	free_all(context.temp_allocator)
}

@(test)
test_seal_dwp_hw :: proc (t: ^testing.T) {
	key_string := "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6"
	aad_string := "8504fa9d1bb6c7ac252e72c202fdce0d5be3d61217b96181fe6786ad716b890b"
	iv_string  := "be32971343fc9a48a02a885f194b09a1"

	block_string := "b194bac80a08f53b366d008e584a5de4"
	truth_string := "52c9af96ff50f64435fc43def56bd797"
	truth_mac_string := "3b2e0aeb2b91854b"

	key_data,   _ := hex.decode(transmute([]byte)key_string,   context.temp_allocator)
	aad_data,   _ := hex.decode(transmute([]byte)aad_string,   context.temp_allocator)
	iv_data,    _ := hex.decode(transmute([]byte)iv_string,    context.temp_allocator)
	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)
	mac_data: Mac64_U8 = ---

	ctx: Context = ---
	init(&ctx, key_data)

	seal_dwp_hw(ctx, iv_data, aad_data, mac_data[:], block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))
	check_mac_string := string(hex.encode(mac_data[:], context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected TRUTH: %s for seal_dwp_hw(%s, %s, %s, %s), but got %s instead",
		truth_string,
		block_string,
		iv_string,
		key_string,
		aad_string,
		check_string,
	)

	testing.expectf(
		t,
		check_mac_string == truth_mac_string,
		"crypto/belt: expected MAC: %s for seal_dwp_hw(%s, %s, %s, %s), but got %s instead",
		truth_mac_string,
		block_string,
		iv_string,
		key_string,
		aad_string,
		check_mac_string,
	)

	free_all(context.temp_allocator)
}
