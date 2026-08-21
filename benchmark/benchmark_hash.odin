#+build amd64,arm64
package benchmark

/* STB 34.101.31-2020                                    */
/* Information technology and security                   */
/* Encryption and integrity control algorithms           */
/* https://apmi.bsu.by/assets/files/std/belt-spec371.pdf */

import "base:runtime"
import "core:testing"
import "core:text/table"
import "core:time"
import belt ".."

@(private = "file")
ITERS :: 10000
@(private = "file")
SIZES := []int{64, 1024, 65536}

@(test)
benchmark_crypto_hash :: proc(t: ^testing.T) {
	runtime.DEFAULT_TEMP_ALLOCATOR_TEMP_GUARD()

	tbl: table.Table
	table.init(&tbl)
	defer table.destroy(&tbl)

	table.caption(&tbl, "HASH")
	table.aligned_header_of_values(&tbl, .Right, "Algorithm", "Size", "Time", "Throughput")

	for sz, _ in SIZES {
		options := &time.Benchmark_Options{
			rounds = ITERS,
			bytes = sz,
			setup = setup_sized_buf,
			bench = do_bench_hash,
			teardown = teardown_sized_buf,
		}

		err := time.benchmark(options, context.allocator)
		testing.expect(t, err == nil)

		time_per_iter := options.duration / ITERS
		table.aligned_row_of_values(
			&tbl,
			.Right,
			"BELT-HASH-256",
			table.format(&tbl, "%d", sz),
			table.format(&tbl, "%8M", time_per_iter),
			table.format(&tbl, "%5.3f MiB/s", options.megabytes_per_second),
		)
	}

	log_table(&tbl)
}

@(private = "file")
do_bench_hash :: proc(
	options: ^time.Benchmark_Options,
	allocator := context.allocator,
) -> (
	err: time.Benchmark_Error,
) {
	digest: belt.Block256_U8
	buf := options.input

	for _ in 0 ..= options.rounds {
		belt.derive_hash(digest[:], buf)
	}
	options.count = options.rounds
	options.processed = options.rounds * (options.bytes)

	return
}
