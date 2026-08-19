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
