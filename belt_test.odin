package belt

/* STB 34.101.31-2020                                    */
/* Information technology and security                   */
/* Encryption and integrity control algorithms           */
/* https://apmi.bsu.by/assets/files/std/belt-spec371.pdf */

import "core:encoding/hex"
import "core:testing"

@(test)
test_encrypt_block :: proc (t: ^testing.T) {
	key_string   := "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6"

	block_string := "b194bac80a08f53b366d008e584a5de4"
	truth_string := "69cca1c93557c9e3d66bc3e0fa88fa6e"

	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)
	key_data,   _ := hex.decode(transmute([]byte)key_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	encrypt_block(ctx, block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected: %s for encrypt_block(%s, %s), but got %s instead",
		truth_string,
		block_string,
		key_string,
		check_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_decrypt_block :: proc (t: ^testing.T) {
	key_string   := "92bd9b1ce5d141015445fbc95e4d0ef2682080aa227d642f2687f93490405511"

	block_string := "e12bdc1ae28257ec703fccf095ee8df1"
	truth_string := "0dc5300600cab840b38448e5e993f421"

	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)
	key_data,   _ := hex.decode(transmute([]byte)key_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	decrypt_block(ctx, block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected: %s for decrypt_block(%s, %s), but got %s instead",
		truth_string,
		block_string,
		key_string,
		check_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_encrypt_wide_block :: proc (t: ^testing.T) {
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

	encrypt_wide_block(ctx, block_data1)
	encrypt_wide_block(ctx, block_data2)

	check_string1 := string(hex.encode(block_data1, context.temp_allocator))
	check_string2 := string(hex.encode(block_data2, context.temp_allocator))

	testing.expectf(
		t,
		check_string1 == truth_string1,
		"crypto/belt: expected: %s for encrypt_wide_block(%s, %s), but got %s instead",
		truth_string1,
		block_string1,
		key_string,
		check_string1,
	)

	testing.expectf(
		t,
		check_string2 == truth_string2,
		"crypto/belt: expected: %s for encrypt_wide_block(%s, %s), but got %s instead",
		truth_string2,
		block_string2,
		key_string,
		check_string2,
	)

	free_all(context.temp_allocator)
}

@(test)
test_decrypt_wide_block :: proc (t: ^testing.T) {
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

	decrypt_wide_block(ctx, block_data1)
	decrypt_wide_block(ctx, block_data2)

	check_string1 := string(hex.encode(block_data1, context.temp_allocator))
	check_string2 := string(hex.encode(block_data2, context.temp_allocator))

	testing.expectf(
		t,
		check_string1 == truth_string1,
		"crypto/belt: expected: %s for decrypt_wide_block(%s, %s), but got %s instead",
		truth_string1,
		block_string1,
		key_string,
		check_string1,
	)

	testing.expectf(
		t,
		check_string2 == truth_string2,
		"crypto/belt: expected: %s for decrypt_wide_block(%s, %s), but got %s instead",
		truth_string2,
		block_string2,
		key_string,
		check_string2,
	)

	free_all(context.temp_allocator)
}

@(test)
test_encrypt_ecb :: proc (t: ^testing.T) {
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

	encrypt_ecb(ctx, block_data1)
	encrypt_ecb(ctx, block_data2)

	check_string1 := string(hex.encode(block_data1, context.temp_allocator))
	check_string2 := string(hex.encode(block_data2, context.temp_allocator))

	testing.expectf(
		t,
		check_string1 == truth_string1,
		"crypto/belt: expected: %s for encrypt_ecb(%s, %s), but got %s instead",
		truth_string1,
		block_string1,
		key_string,
		check_string1,
	)

	testing.expectf(
		t,
		check_string2 == truth_string2,
		"crypto/belt: expected: %s for encrypt_ecb(%s, %s), but got %s instead",
		truth_string2,
		block_string2,
		key_string,
		check_string2,
	)

	free_all(context.temp_allocator)
}

@(test)
test_decrypt_ecb :: proc (t: ^testing.T) {
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

	decrypt_ecb(ctx, block_data1)
	decrypt_ecb(ctx, block_data2)

	check_string1 := string(hex.encode(block_data1, context.temp_allocator))
	check_string2 := string(hex.encode(block_data2, context.temp_allocator))

	testing.expectf(
		t,
		check_string1 == truth_string1,
		"crypto/belt: expected: %s for decrypt_ecb(%s, %s), but got %s instead",
		truth_string1,
		block_string1,
		key_string,
		check_string1,
	)

	testing.expectf(
		t,
		check_string2 == truth_string2,
		"crypto/belt: expected: %s for decrypt_ecb(%s, %s), but got %s instead",
		truth_string2,
		block_string2,
		key_string,
		check_string2,
	)

	free_all(context.temp_allocator)
}

@(test)
test_encrypt_cbc :: proc (t: ^testing.T) {
	key_string    := "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6"
	iv_string     := "be32971343fc9a48a02a885f194b09a1"

	block_string1 := "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d5be3d61217b96181fe6786ad716b890b"
	truth_string1 := "10116efae6ad58ee14852e11da1b8a745cf2480e8d03f1c19492e53ed3a70f60657c1ee8c0e0ae5b58388bf8a68e3309"

	block_string2 := "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d5be3d612"
	truth_string2 := "10116efae6ad58ee14852e11da1b8a746a9bbadcaf73f968f875dedc0a44f6b15cf2480e"

	key_data,    _ := hex.decode(transmute([]byte)key_string,    context.temp_allocator)
	iv_data,     _ := hex.decode(transmute([]byte)iv_string,     context.temp_allocator)
	block_data1, _ := hex.decode(transmute([]byte)block_string1, context.temp_allocator)
	block_data2, _ := hex.decode(transmute([]byte)block_string2, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	encrypt_cbc(ctx, iv_data, block_data1)
	encrypt_cbc(ctx, iv_data, block_data2)

	check_string1 := string(hex.encode(block_data1, context.temp_allocator))
	check_string2 := string(hex.encode(block_data2, context.temp_allocator))

	testing.expectf(
		t,
		check_string1 == truth_string1,
		"crypto/belt: expected: %s for encrypt_cbc(%s, %s, %s), but got %s instead",
		truth_string1,
		block_string1,
		iv_string,
		key_string,
		check_string1,
	)

	testing.expectf(
		t,
		check_string2 == truth_string2,
		"crypto/belt: expected: %s for encrypt_cbc(%s, %s, %s), but got %s instead",
		truth_string2,
		block_string2,
		iv_string,
		key_string,
		check_string2,
	)

	free_all(context.temp_allocator)
}

@(test)
test_decrypt_cbc :: proc (t: ^testing.T) {
	key_string    := "92bd9b1ce5d141015445fbc95e4d0ef2682080aa227d642f2687f93490405511"
	iv_string     := "7ecda4d01544af8ca58450bf66d2e88a"

	block_string1 := "e12bdc1ae28257ec703fccf095ee8df1c1ab76389fe678caf7c6f860d5bb9c4ff33c657b637c306add4ea7799eb23d31"
	truth_string1 := "730894d6158e17cc1600185a8f411cab0471ff85c83792398d8924ebd57d03db95b97a9b7907e4b020960455e46176f8"

	block_string2 := "e12bdc1ae28257ec703fccf095ee8df1c1ab76389fe678caf7c6f860d5bb9c4ff33c657b"
	truth_string2 := "730894d6158e17cc1600185a8f411cabb6ab7af8541cf85755b8ea27239f08d2166646e4"

	key_data,    _ := hex.decode(transmute([]byte)key_string,    context.temp_allocator)
	iv_data,     _ := hex.decode(transmute([]byte)iv_string,     context.temp_allocator)
	block_data1, _ := hex.decode(transmute([]byte)block_string1, context.temp_allocator)
	block_data2, _ := hex.decode(transmute([]byte)block_string2, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	decrypt_cbc(ctx, iv_data, block_data1)
	decrypt_cbc(ctx, iv_data, block_data2)

	check_string1 := string(hex.encode(block_data1, context.temp_allocator))
	check_string2 := string(hex.encode(block_data2, context.temp_allocator))

	testing.expectf(
		t,
		check_string1 == truth_string1,
		"crypto/belt: expected: %s for decrypt_cbc(%s, %s, %s), but got %s instead",
		truth_string1,
		block_string1,
		iv_string,
		key_string,
		check_string1,
	)

	testing.expectf(
		t,
		check_string2 == truth_string2,
		"crypto/belt: expected: %s for decrypt_cbc(%s, %s, %s), but got %s instead",
		truth_string2,
		block_string2,
		iv_string,
		key_string,
		check_string2,
	)

	free_all(context.temp_allocator)
}

@(test)
test_encrypt_cfb :: proc (t: ^testing.T) {
	key_string   := "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6"
	iv_string    := "be32971343fc9a48a02a885f194b09a1"

	block_string := "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d5be3d61217b96181fe6786ad716b890b"
	truth_string := "c31e490a90efa374626cc99e4b7b8540a6e48685464a5a06849c9ca769a1b0ae55c2cc5939303ec832dd2fe16c8e5a1b"

	key_data,   _ := hex.decode(transmute([]byte)key_string,   context.temp_allocator)
	iv_data,    _ := hex.decode(transmute([]byte)iv_string,    context.temp_allocator)
	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	encrypt_cfb(ctx, iv_data, block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected: %s for encrypt_cfb(%s, %s, %s), but got %s instead",
		truth_string,
		block_string,
		iv_string,
		key_string,
		check_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_decrypt_cfb :: proc (t: ^testing.T) {
	key_string   := "92bd9b1ce5d141015445fbc95e4d0ef2682080aa227d642f2687f93490405511"
	iv_string    := "7ecda4d01544af8ca58450bf66d2e88a"

	block_string := "e12bdc1ae28257ec703fccf095ee8df1c1ab76389fe678caf7c6f860d5bb9c4ff33c657b637c306add4ea7799eb23d31"
	truth_string := "fa9d107a86f375ee65cd1db881224bd016aff814938ed39b3361abb0bf0851b652244eb06842dd4c94aa4500774e40bb"

	key_data,   _ := hex.decode(transmute([]byte)key_string,   context.temp_allocator)
	iv_data,    _ := hex.decode(transmute([]byte)iv_string,    context.temp_allocator)
	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	decrypt_cfb(ctx, iv_data, block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected: %s for decrypt_cfb(%s, %s, %s), but got %s instead",
		truth_string,
		block_string,
		iv_string,
		key_string,
		check_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_encrypt_ctr :: proc (t: ^testing.T) {
	key_string   := "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6"
	iv_string    := "be32971343fc9a48a02a885f194b09a1"

	block_string := "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d5be3d61217b96181fe6786ad716b890b"
	truth_string := "52c9af96ff50f64435fc43def56bd797d5b5b1ff79fb41257ab9cdf6e63e81f8f00341473eae409833622de05213773a"

	key_data,   _ := hex.decode(transmute([]byte)key_string,   context.temp_allocator)
	iv_data,    _ := hex.decode(transmute([]byte)iv_string,    context.temp_allocator)
	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	encrypt_ctr(ctx, iv_data, block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected: %s for encrypt_ctr(%s, %s, %s), but got %s instead",
		truth_string,
		block_string,
		iv_string,
		key_string,
		check_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_decrypt_ctr :: proc (t: ^testing.T) {
	key_string   := "92bd9b1ce5d141015445fbc95e4d0ef2682080aa227d642f2687f93490405511"
	iv_string    := "7ecda4d01544af8ca58450bf66d2e88a"

	block_string := "e12bdc1ae28257ec703fccf095ee8df1c1ab76389fe678caf7c6f860d5bb9c4ff33c657b637c306add4ea779"
	truth_string := "df181ed008a20f43dcbbb93650dad34b389cdee5826d40e2d4bd80f49a93f5d212f6333166456f169043cc5f"

	key_data,   _ := hex.decode(transmute([]byte)key_string,   context.temp_allocator)
	iv_data,    _ := hex.decode(transmute([]byte)iv_string,    context.temp_allocator)
	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	decrypt_ctr(ctx, iv_data, block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected: %s for decrypt_ctr(%s, %s, %s), but got %s instead",
		truth_string,
		block_string,
		iv_string,
		key_string,
		check_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_derive_mac :: proc (t: ^testing.T) {
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

	derive_mac(ctx, check_mac_data1[:], block_data1)
	derive_mac(ctx, check_mac_data2[:], block_data2)

	check_mac_string1 := string(hex.encode(check_mac_data1[:], context.temp_allocator))
	check_mac_string2 := string(hex.encode(check_mac_data2[:], context.temp_allocator))

	testing.expectf(
		t,
		check_mac_string1 == truth_mac_string1,
		"crypto/belt: expected: %s for derive_mac(%s, %s), but got %s instead",
		truth_mac_string1,
		block_string1,
		key_string,
		check_mac_string1,
	)

	testing.expectf(
		t,
		check_mac_string2 == truth_mac_string2,
		"crypto/belt: expected: %s for derive_mac(%s, %s), but got %s instead",
		truth_mac_string2,
		block_string2,
		key_string,
		check_mac_string2,
	)

	free_all(context.temp_allocator)
}

@(test)
test_mul_block :: proc (t: ^testing.T) {
	block_string1 := "3490405511be32971343724c5ab793e9"
	block_string2 := "224817838761a9d6e3ec9689110fb0f3"
	truth_string1 := "0001d107fc67de4004dc2c803dfd95c3"

	block_string3 := "703fccf095ee8df1c1abf8ee8df1c1ab"
	block_string4 := "2055704e2edb48fe87e74075a5e77eb1"
	truth_string2 := "4a5c95938b3fe8f674d59bc1eb356079"

	block_data1, _ := hex.decode(transmute([]byte)block_string1, context.temp_allocator)
	block_data2, _ := hex.decode(transmute([]byte)block_string2, context.temp_allocator)

	block_data3, _ := hex.decode(transmute([]byte)block_string3, context.temp_allocator)
	block_data4, _ := hex.decode(transmute([]byte)block_string4, context.temp_allocator)

	mul_block(block_data1, block_data2)
	mul_block(block_data3, block_data4)

	check_string1 := string(hex.encode(block_data1[:], context.temp_allocator))
	check_string2 := string(hex.encode(block_data3[:], context.temp_allocator))

	testing.expectf(
		t,
		check_string1 == truth_string1,
		"crypto/belt: expected: %s for mul_block(%s, %s), but got %s instead",
		truth_string1,
		block_string1,
		block_string2,
		check_string1,
	)

	testing.expectf(
		t,
		check_string2 == truth_string2,
		"crypto/belt: expected: %s for mul_block(%s, %s), but got %s instead",
		truth_string2,
		block_string3,
		block_string4,
		check_string2,
	)

	free_all(context.temp_allocator)
}

@(test)
test_seal_dwp :: proc (t: ^testing.T) {
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

	seal_dwp(ctx, iv_data, aad_data, mac_data[:], block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))
	check_mac_string := string(hex.encode(mac_data[:], context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected TRUTH: %s for seal_dwp(%s, %s, %s, %s), but got %s instead",
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
		"crypto/belt: expected MAC: %s for seal_dwp(%s, %s, %s, %s), but got %s instead",
		truth_mac_string,
		block_string,
		iv_string,
		key_string,
		aad_string,
		check_mac_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_open_dwp :: proc (t: ^testing.T) {
	key_string := "92bd9b1ce5d141015445fbc95e4d0ef2682080aa227d642f2687f93490405511"
	aad_string := "c1ab76389fe678caf7c6f860d5bb9c4ff33c657b637c306add4ea7799eb23d31"
	iv_string  := "7ecda4d01544af8ca58450bf66d2e88a"
	mac_string := "6a2c2c94c4150dc0"

	block_string := "e12bdc1ae28257ec703fccf095ee8df1"
	truth_string := "df181ed008a20f43dcbbb93650dad34b"
	truth_ok := true

	key_data,   _ := hex.decode(transmute([]byte)key_string,   context.temp_allocator)
	aad_data,   _ := hex.decode(transmute([]byte)aad_string,   context.temp_allocator)
	iv_data,    _ := hex.decode(transmute([]byte)iv_string,    context.temp_allocator)
	mac_data,   _ := hex.decode(transmute([]byte)mac_string,   context.temp_allocator)
	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	check_ok := open_dwp(ctx, iv_data, aad_data, mac_data, block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected TRUTH: %s for open_dwp(%s, %s, %s, %s), but got %s instead",
		truth_string,
		block_string,
		iv_string,
		key_string,
		aad_string,
		check_string,
	)

	testing.expectf(
		t,
		check_ok == truth_ok,
		"crypto/belt: expected OK: %t for open_dwp(%s, %s, %s, %s), but got %t instead",
		truth_ok,
		block_string,
		iv_string,
		key_string,
		aad_string,
		check_ok,
	)

	free_all(context.temp_allocator)
}

@(test)
test_seal_che :: proc (t: ^testing.T) {
	key_string := "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6"
	aad_string := "8504fa9d1bb6c7ac252e72c202fdce0d5be3d61217b96181fe6786ad716b890b"
	iv_string  := "be32971343fc9a48a02a885f194b09a1"

	block_string := "b194bac80a08f53b366d008e584a5d"
	truth_string := "bf3daeaf5d18d2bcc30ea62d2e70a4"
	truth_mac_string := "548622b844123ff7"

	key_data,   _ := hex.decode(transmute([]byte)key_string,   context.temp_allocator)
	aad_data,   _ := hex.decode(transmute([]byte)aad_string,   context.temp_allocator)
	iv_data,    _ := hex.decode(transmute([]byte)iv_string,    context.temp_allocator)
	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)
	mac_data: Mac64_U8 = ---

	ctx: Context = ---
	init(&ctx, key_data)

	seal_che(ctx, iv_data, aad_data, mac_data[:], block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))
	check_mac_string := string(hex.encode(mac_data[:], context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected TRUTH: %s for seal_che(%s, %s, %s, %s), but got %s instead",
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
		"crypto/belt: expected MAC: %s for seal_che(%s, %s, %s, %s), but got %s instead",
		truth_mac_string,
		block_string,
		iv_string,
		key_string,
		aad_string,
		check_mac_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_open_che :: proc (t: ^testing.T) {
	key_string := "92bd9b1ce5d141015445fbc95e4d0ef2682080aa227d642f2687f93490405511"
	aad_string := "c1ab76389fe678caf7c6f860d5bb9c4ff33c657b637c306add4ea7799eb23d31"
	iv_string  := "7ecda4d01544af8ca58450bf66d2e88a"
	mac_string := "7d9d4f59d40d197d"

	block_string := "e12bdc1ae28257ec703fccf095ee8df1c1ab7638"
	truth_string := "2babf43eb37b5398a9068f31a3c758b762f44aa9"
	truth_ok := true

	key_data,   _ := hex.decode(transmute([]byte)key_string,   context.temp_allocator)
	aad_data,   _ := hex.decode(transmute([]byte)aad_string,   context.temp_allocator)
	iv_data,    _ := hex.decode(transmute([]byte)iv_string,    context.temp_allocator)
	mac_data,   _ := hex.decode(transmute([]byte)mac_string,   context.temp_allocator)
	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	check_ok := open_che(ctx, iv_data, aad_data, mac_data, block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected TRUTH: %s for open_che(%s, %s, %s, %s), but got %s instead",
		truth_string,
		block_string,
		iv_string,
		key_string,
		aad_string,
		check_string,
	)

	testing.expectf(
		t,
		check_ok == truth_ok,
		"crypto/belt: expected OK: %t for open_che(%s, %s, %s, %s), but got %t instead",
		truth_ok,
		block_string,
		iv_string,
		key_string,
		aad_string,
		check_ok,
	)

	free_all(context.temp_allocator)
}

@(test)
test_seal_kwp :: proc (t: ^testing.T) {
	key_string := "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6"
	iv_string  := "5be3d61217b96181fe6786ad716b890b"

	block_string := "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d"
	truth_string := "49a38ee108d6c742e52b774f00a6ef98b106cbd13ea4fb0680323051bc04df76e487b055c69bcf541176169f1dc9f6c8"

	key_data,   _ := hex.decode(transmute([]byte)key_string,   context.temp_allocator)
	iv_data,    _ := hex.decode(transmute([]byte)iv_string,    context.temp_allocator)
	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)
	check_data, _ := hex.decode(transmute([]byte)truth_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	seal_kwp(ctx, check_data, iv_data, block_data)
	check_string := string(hex.encode(check_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected TRUTH: %s for seal_kwp(%s, %s, %s), but got %s instead",
		truth_string,
		block_string,
		iv_string,
		key_string,
		check_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_open_kwp :: proc (t: ^testing.T) {
	key_string := "92bd9b1ce5d141015445fbc95e4d0ef2682080aa227d642f2687f93490405511"
	iv_string  := "b5ef68d8e4a39e567153de13d72254ee"

	block_string := "e12bdc1ae28257ec703fccf095ee8df1c1ab76389fe678caf7c6f860d5bb9c4ff33c657b637c306add4ea7799eb23d31"
	truth_string := "92632ee0c21ad9e09a39343e5c07daa4889b03f2e6847eb152ec99f7a4d9f154"
	truth_ok := true

	key_data,   _ := hex.decode(transmute([]byte)key_string,   context.temp_allocator)
	iv_data,    _ := hex.decode(transmute([]byte)iv_string,    context.temp_allocator)
	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)
	check_data, _ := hex.decode(transmute([]byte)truth_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	check_ok := open_kwp(ctx, block_data, iv_data, check_data)
	check_string := string(hex.encode(check_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected TRUTH: %s for open_kwp(%s, %s, %s), but got %s instead",
		truth_string,
		block_string,
		iv_string,
		key_string,
		check_string,
	)

	testing.expectf(
		t,
		check_ok == truth_ok,
		"crypto/belt: expected OK: %t for open_kwp(%s, %s, %s), but got %t instead",
		truth_ok,
		block_string,
		iv_string,
		key_string,
		check_ok,
	)

	free_all(context.temp_allocator)
}

@(test)
test_spec_compress :: proc (t: ^testing.T) {
	block_string1 := "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d"
	block_string2 := "5be3d61217b96181fe6786ad716b890b5cb0c0ff33c356b835c405aed8e07f99"
	dummy_truth_string := "46fe7425c9b181eb41dfee3e72163d5a"
	compr_truth_string := "ed2f5481d593f40d87fce37d6bc1a2e1b7d1a2cc975c82d3c0497488c90d99d8"

	block_data1, _ := hex.decode(transmute([]byte)block_string1, context.temp_allocator)
	block_data2, _ := hex.decode(transmute([]byte)block_string2, context.temp_allocator)

	dummy_check_data: Block128_U8 = ---
	spec_compress(dummy_check_data[:], block_data2, block_data1)

	dummy_check_string := string(hex.encode(dummy_check_data[:], context.temp_allocator))
	compr_check_string := string(hex.encode(block_data2[:], context.temp_allocator))

	testing.expectf(
		t,
		dummy_check_string == dummy_truth_string,
		"crypto/belt: expected DUMMY: %s for spec_compress(%s, %s), but got %s instead",
		dummy_truth_string,
		block_string1,
		block_string2,
		dummy_check_string,
	)

	testing.expectf(
		t,
		compr_check_string == compr_truth_string,
		"crypto/belt: expected COMPR: %s for spec_compress(%s, %s), but got %s instead",
		compr_truth_string,
		block_string1,
		block_string2,
		compr_check_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_derive_hash :: proc (t: ^testing.T) {
	block_string1 := "b194bac80a08f53b366d008e58"
	truth_string1 := "abef9725d4c5a83597a367d14494cc2542f20f659ddfecc961a3ec550cba8c75"

	block_string2 := "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d"
	truth_string2 := "749e4c3653aece5e48db4761227742eb6dbe13f4a80f7beff1a9cf8d10ee7786"

	block_string3 := "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d5be3d61217b96181fe6786ad716b890b"
	truth_string3 := "9d02ee446fb6a29fe5c982d4b13af9d3e90861bc4cef27cf306bfb0b174a154a"

	block_data1, _ := hex.decode(transmute([]byte)block_string1, context.temp_allocator)
	check_data1, _ := hex.decode(transmute([]byte)truth_string1, context.temp_allocator)

	block_data2, _ := hex.decode(transmute([]byte)block_string2, context.temp_allocator)
	check_data2, _ := hex.decode(transmute([]byte)truth_string2, context.temp_allocator)

	block_data3, _ := hex.decode(transmute([]byte)block_string3, context.temp_allocator)
	check_data3, _ := hex.decode(transmute([]byte)truth_string3, context.temp_allocator)

	derive_hash(check_data1, block_data1)
	derive_hash(check_data2, block_data2)
	derive_hash(check_data3, block_data3)

	check_string1 := string(hex.encode(check_data1, context.temp_allocator))
	check_string2 := string(hex.encode(check_data2, context.temp_allocator))
	check_string3 := string(hex.encode(check_data3, context.temp_allocator))

	testing.expectf(
		t,
		check_string1 == truth_string1,
		"crypto/belt: expected: %s for derive_hash(%s), but got %s instead",
		truth_string1,
		block_string1,
		check_string1,
	)

	testing.expectf(
		t,
		check_string2 == truth_string2,
		"crypto/belt: expected: %s for derive_hash(%s), but got %s instead",
		truth_string2,
		block_string2,
		check_string2,
	)

	testing.expectf(
		t,
		check_string3 == truth_string3,
		"crypto/belt: expected: %s for derive_hash(%s), but got %s instead",
		truth_string3,
		block_string3,
		check_string3,
	)

	free_all(context.temp_allocator)
}

@(test)
test_encrypt_bde :: proc (t: ^testing.T) {
	key_string := "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6"
	iv_string  := "be32971343fc9a48a02a885f194b09a1"

	block_string := "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d5be3d61217b96181fe6786ad716b890b"
	truth_string := "e9cab32d879cc50c10378eb07c10f26307257e2dbe2b854cbc9f38282d59d6a77f952001c5d1244f53210a27c216d4bb"

	key_data,   _ := hex.decode(transmute([]byte)key_string,   context.temp_allocator)
	iv_data,    _ := hex.decode(transmute([]byte)iv_string,    context.temp_allocator)
	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	encrypt_bde(ctx, iv_data, block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected: %s for encrypt_bde(%s, %s, %s), but got %s instead",
		truth_string,
		block_string,
		iv_string,
		key_string,
		check_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_decrypt_bde :: proc (t: ^testing.T) {
	key_string := "92bd9b1ce5d141015445fbc95e4d0ef2682080aa227d642f2687f93490405511"
	iv_string  := "7ecda4d01544af8ca58450bf66d2e88a"

	block_string := "e12bdc1ae28257ec703fccf095ee8df1c1ab76389fe678caf7c6f860d5bb9c4ff33c657b637c306add4ea7799eb23d31"
	truth_string := "7041bc226352c706d00ea8ef23cfe46afae118577d037facdc36e4ecc1f6574609f236943fb809e1bee4a1c686c13acc"

	key_data,   _ := hex.decode(transmute([]byte)key_string,   context.temp_allocator)
	iv_data,    _ := hex.decode(transmute([]byte)iv_string,    context.temp_allocator)
	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	decrypt_bde(ctx, iv_data, block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected: %s for decrypt_bde(%s, %s, %s), but got %s instead",
		truth_string,
		block_string,
		iv_string,
		key_string,
		check_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_encrypt_sde :: proc (t: ^testing.T) {
	key_string := "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6"
	iv_string  := "be32971343fc9a48a02a885f194b09a1"

	block_string := "b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d5be3d61217b96181fe6786ad716b890b"
	truth_string := "1fcbb01852003d60b66024c508608baa2c21af1e884cf31154d3077d4643cf2249eb2f5a68e4ba019d90211a81d690d9"

	key_data,   _ := hex.decode(transmute([]byte)key_string,   context.temp_allocator)
	iv_data,    _ := hex.decode(transmute([]byte)iv_string,    context.temp_allocator)
	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	encrypt_sde(ctx, iv_data, block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected: %s for encrypt_sde(%s, %s, %s), but got %s instead",
		truth_string,
		block_string,
		iv_string,
		key_string,
		check_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_decrypt_sde :: proc (t: ^testing.T) {
	key_string := "92bd9b1ce5d141015445fbc95e4d0ef2682080aa227d642f2687f93490405511"
	iv_string  := "7ecda4d01544af8ca58450bf66d2e88a"

	block_string := "e12bdc1ae28257ec703fccf095ee8df1c1ab76389fe678caf7c6f860d5bb9c4ff33c657b637c306add4ea7799eb23d31"
	truth_string := "e9fdf3f788657332e6c46fcf5251b8a6d43543a93e3233837db1571183a6ef4d7feb5cdf999e1a3f51a5a3381beb7fa5"

	key_data,   _ := hex.decode(transmute([]byte)key_string,   context.temp_allocator)
	iv_data,    _ := hex.decode(transmute([]byte)iv_string,    context.temp_allocator)
	block_data, _ := hex.decode(transmute([]byte)block_string, context.temp_allocator)

	ctx: Context = ---
	init(&ctx, key_data)

	decrypt_sde(ctx, iv_data, block_data)
	check_string := string(hex.encode(block_data, context.temp_allocator))

	testing.expectf(
		t,
		check_string == truth_string,
		"crypto/belt: expected: %s for decrypt_sde(%s, %s, %s), but got %s instead",
		truth_string,
		block_string,
		iv_string,
		key_string,
		check_string,
	)

	free_all(context.temp_allocator)
}

@(test)
test_expand_key :: proc (t: ^testing.T) {
	key_string1   := "e9dee72c8f0c0fa62ddb49f46f739647"
	truth_string1 := "e9dee72c8f0c0fa62ddb49f46f739647e9dee72c8f0c0fa62ddb49f46f739647"

	key_string2   := "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a37"
	truth_string2 := "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a374b09a17e8450bf66"

	key_data1,  _ := hex.decode(transmute([]byte)key_string1, context.temp_allocator)
	key_data2,  _ := hex.decode(transmute([]byte)key_string2, context.temp_allocator)

	check_data1: Key256_U8 = ---
	check_data2: Key256_U8 = ---

	expand_key(check_data1[:], key_data1)
	expand_key(check_data2[:], key_data2)

	check_string1 := string(hex.encode(check_data1[:], context.temp_allocator))
	check_string2 := string(hex.encode(check_data2[:], context.temp_allocator))

	testing.expectf(
		t,
		check_string1 == truth_string1,
		"crypto/belt: expected: %s for expand_key(%s), but got %s instead",
		truth_string1,
		key_string1,
		check_string1,
	)

	testing.expectf(
		t,
		check_string2 == truth_string2,
		"crypto/belt: expected: %s for expand_key(%s), but got %s instead",
		truth_string2,
		key_string2,
		check_string2,
	)

	free_all(context.temp_allocator)
}

@(test)
test_derive_key :: proc (t: ^testing.T) {
	key_string := "e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6"
	iv_string  := "5be3d61217b96181fe6786ad716b890b"
	dv_string  := "010000000000000000000000"

	truth_string1 := "6bbbc2336670d31ab83daa90d52c0541"
	truth_string2 := "9a2532a18cbaf145398d5a95feea6c825b9c197156a00275"
	truth_string3 := "76e166e6ab21256b6739397b672b879614b81cf05955fc3ab09343a745c48f77"

	key_data, _ := hex.decode(transmute([]byte)key_string, context.temp_allocator)
	iv_data,  _ := hex.decode(transmute([]byte)iv_string,  context.temp_allocator)
	dv_data,  _ := hex.decode(transmute([]byte)dv_string,  context.temp_allocator)

	check_data1: Key128_U8 = ---
	check_data2: Key192_U8 = ---
	check_data3: Key256_U8 = ---

	derive_key(dv_data, iv_data, check_data1[:], key_data)
	derive_key(dv_data, iv_data, check_data2[:], key_data)
	derive_key(dv_data, iv_data, check_data3[:], key_data)

	check_string1 := string(hex.encode(check_data1[:], context.temp_allocator))
	check_string2 := string(hex.encode(check_data2[:], context.temp_allocator))
	check_string3 := string(hex.encode(check_data3[:], context.temp_allocator))

	testing.expectf(
		t,
		check_string1 == truth_string1,
		"crypto/belt: expected: %s for derive_key(%s, %s, %s), but got %s instead",
		truth_string1,
		key_string,
		iv_string,
		dv_string,
		check_string1,
	)

	testing.expectf(
		t,
		check_string2 == truth_string2,
		"crypto/belt: expected: %s for derive_key(%s, %s, %s), but got %s instead",
		truth_string2,
		key_string,
		iv_string,
		dv_string,
		check_string2,
	)

	testing.expectf(
		t,
		check_string3 == truth_string3,
		"crypto/belt: expected: %s for derive_key(%s, %s, %s), but got %s instead",
		truth_string3,
		key_string,
		iv_string,
		dv_string,
		check_string3,
	)

	free_all(context.temp_allocator)
}
