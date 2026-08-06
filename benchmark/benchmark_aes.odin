package benchmark

/* STB 34.101.31-2020                                    */
/* Information technology and security                   */
/* Encryption and integrity control algorithms           */
/* https://apmi.bsu.by/assets/files/std/belt-spec371.pdf */

import "base:runtime"
import "core:crypto"
import "core:testing"
import "core:text/table"
import "core:time"
import belt ".."

@(private = "file")
ITERS :: 10000
@(private = "file")
SIZES := []int{64, 1024, 65536}

@(test)
benchmark_crypto_aes :: proc(t: ^testing.T) {
	runtime.DEFAULT_TEMP_ALLOCATOR_TEMP_GUARD()

	tbl: table.Table
	table.init(&tbl)
	defer table.destroy(&tbl)

	table.caption(&tbl, "AES")
	table.aligned_header_of_values(&tbl, .Right, "Algorithm", "Size", "Time", "Throughput")

	{
		key: belt.Key256_U8 = ---
		crypto.rand_bytes(key[:])

		ctx: belt.Context
		belt.init(&ctx, key[:])

		for sz, _ in SIZES {
			options := &time.Benchmark_Options{
				rounds = ITERS,
				bytes = belt.BLOCK_SIZE_128_U8 + sz,
				setup = setup_sized_buf,
				bench = do_bench_dwp,
				teardown = teardown_sized_buf,
			}
			context.user_ptr = &ctx

			err := time.benchmark(options, context.allocator)
			testing.expect(t, err == nil)

			time_per_iter := options.duration / ITERS
			table.aligned_row_of_values(
				&tbl,
				.Right,
				"BELT-DWP-256",
				table.format(&tbl, "%d", sz),
				table.format(&tbl, "%8M", time_per_iter),
				table.format(&tbl, "%5.3f MiB/s", options.megabytes_per_second),
			)
		}
	}

	table.row(&tbl)

	{
		key: belt.Key256_U8 = ---
		crypto.rand_bytes(key[:])

		ctx: belt.Context
		belt.init(&ctx, key[:])

		for sz, _ in SIZES {
			options := &time.Benchmark_Options{
				rounds = ITERS,
				bytes = belt.BLOCK_SIZE_128_U8 + sz,
				setup = setup_sized_buf,
				bench = do_bench_che,
				teardown = teardown_sized_buf,
			}
			context.user_ptr = &ctx

			err := time.benchmark(options, context.allocator)
			testing.expect(t, err == nil)

			time_per_iter := options.duration / ITERS
			table.aligned_row_of_values(
				&tbl,
				.Right,
				"BELT-CHE-256",
				table.format(&tbl, "%d", sz),
				table.format(&tbl, "%8M", time_per_iter),
				table.format(&tbl, "%5.3f MiB/s", options.megabytes_per_second),
			)
		}
	}

	log_table(&tbl)
}

@(private = "file")
do_bench_dwp :: proc(
	options: ^time.Benchmark_Options,
	allocator := context.allocator,
) -> (
	err: time.Benchmark_Error,
) {
	ctx := (^belt.Context)(context.user_ptr)
	iv_sz := belt.BLOCK_SIZE_128_U8

	iv := options.input[:iv_sz]
	buf := options.input[iv_sz:]

	mac: belt.Mac64_U8 = ---
	aad := belt.Block256_U8 {
		0x85, 0x04, 0xfa, 0x9d, 0x1b, 0xb6, 0xc7, 0xac,
		0x25, 0x2e, 0x72, 0xc2, 0x02, 0xfd, 0xce, 0x0d,
		0x5b, 0xe3, 0xd6, 0x12, 0x17, 0xb9, 0x61, 0x81,
		0xfe, 0x67, 0x86, 0xad, 0x71, 0x6b, 0x89, 0x0b,
	}

	for _ in 0 ..= options.rounds {
		belt.seal_dwp(ctx^, iv, aad[:], mac[:], buf)
	}
	options.count = options.rounds
	options.processed = options.rounds * (options.bytes - iv_sz)

	return
}

@(private = "file")
do_bench_che :: proc(
	options: ^time.Benchmark_Options,
	allocator := context.allocator,
) -> (
	err: time.Benchmark_Error,
) {
	ctx := (^belt.Context)(context.user_ptr)
	iv_sz := belt.BLOCK_SIZE_128_U8

	iv := options.input[:iv_sz]
	buf := options.input[iv_sz:]

	mac: belt.Mac64_U8 = ---
	aad := belt.Block256_U8 {
		0x85, 0x04, 0xfa, 0x9d, 0x1b, 0xb6, 0xc7, 0xac,
		0x25, 0x2e, 0x72, 0xc2, 0x02, 0xfd, 0xce, 0x0d,
		0x5b, 0xe3, 0xd6, 0x12, 0x17, 0xb9, 0x61, 0x81,
		0xfe, 0x67, 0x86, 0xad, 0x71, 0x6b, 0x89, 0x0b,
	}

	for _ in 0 ..= options.rounds {
		belt.seal_che(ctx^, iv, aad[:], mac[:], buf)
	}
	options.count = options.rounds
	options.processed = options.rounds * (options.bytes - iv_sz)

	return
}
