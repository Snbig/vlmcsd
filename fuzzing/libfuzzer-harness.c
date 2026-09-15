/*
 * libFuzzer harness for the KMS protocol parsers used by vlmcsd/vlmcs.
 *
 * A thin in-process port of fuzzing/afl-harness.c: the AFL harness's
 * file-based, single-shot parser drivers are reused verbatim (included with
 * main renamed so the libFuzzer runtime stays the real entry point), with the
 * persistent loop replaced by LLVMFuzzerTestOneInput.
 *
 * Build (libFuzzer matrix target):
 *   clang -std=gnu11 -O1 -g -fsanitize=fuzzer,address,undefined ... \
 *         -DFUZZ_CREATE -c libfuzzer-harness.c
 *   clang -fsanitize=fuzzer,address,undefined libfuzzer-harness.o \
 *         ../src/{kms,crypto,crypto_internal,endian,output,shared_globals,helpers,kmsdata}.c \
 *         -o harness-create
 *
 * Run:
 *   ./harness-create <seed-corpus-dir> -max_total_time=120 -timeout=10
 */

#include <stdint.h>

/* Reuse the AFL harness's parser drivers and init/PRNG helpers verbatim.
 * The static functions become part of this TU; the renamed main never runs. */
#define main libfuzzer_afl_main
#include "afl-harness.c"
#undef main

/*
 * initFuzzer() loads the KMS data tables, allocates KmsResponseParameters
 * and seeds the PRNG - normally called from main, which libFuzzer never
 * invokes. Run it once from a constructor instead.
 */
__attribute__((constructor)) static void libfuzzerInit(void)
{
	initFuzzer();
}

int LLVMFuzzerTestOneInput(const uint8_t *const data, const size_t size)
{
	/* Deterministic PRNG seed per input, mirroring seedPrng in the AFL
	 * harness so the same input reproduces the same code path. */
	seedPrng(data, size);

#if defined(FUZZ_CREATE)
	runCreateResponse(data, size);
#elif defined(FUZZ_DECRYPT)
	runDecryptResponse(data, size);
#else
#error "define FUZZ_CREATE or FUZZ_DECRYPT (target mode)"
#endif

	return 0;
}