/*
 * AFL++ fuzz harness for the KMS protocol parsers used by vlmcsd/vlmcs.
 *
 * Modes (argv[1]):
 *   create   - server side: CreateResponseV4 / CreateResponseV6
 *   decrypt  - client side: DecryptResponseV4 / DecryptResponseV6
 *
 * When built with afl-clang-fast the harness uses deferred fork-servers and
 * the persistent loop. With a plain compiler it reads a single test case from
 * the file given in argv[2] (as used by "afl-fuzz ... -- ./harness create @@").
 *
 * Usage:
 *   ./harness create <testcase-file>
 *   ./harness decrypt <testcase-file>
 *   afl-fuzz -i seeds -o out -m none -- ./harness create @@
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kms.h"
#include "helpers.h"
#include "shared_globals.h"

#ifndef MAX_REQUEST_BUFFER
#define MAX_REQUEST_BUFFER (sizeof(REQUEST_V6) + 512)
#endif

#ifndef MAX_RESPONSE_BUFFER
#define MAX_RESPONSE_BUFFER (sizeof(RESPONSE_V6) + 1024)
#endif

static int isCreateMode;

static uint32_t readVersion(const BYTE *const data, const size_t size)
{
	uint32_t version = 0;

	if (size >= sizeof(uint32_t)) memcpy(&version, data, sizeof(version));

	return version;
}

/*
 * Dispatch like the real RPC server does: the KMS protocol major version is
 * stored in the upper 16 bits of the first DWORD of the payload.
 */
static int requestTarget(const BYTE *const data, const size_t size, size_t *const structSize)
{
	const uint32_t major = readVersion(data, size) >> 16;

	if (major == 4 && size >= sizeof(REQUEST_V4))
	{
		*structSize = sizeof(REQUEST_V4);
		return 4;
	}

	if ((major == 5 || major == 6) && size >= sizeof(REQUEST_V6))
	{
		*structSize = sizeof(REQUEST_V6);
		return 6;
	}

	if (size >= sizeof(REQUEST_V6))
	{
		*structSize = sizeof(REQUEST_V6);
		return 6;
	}

	if (size >= sizeof(REQUEST_V4))
	{
		*structSize = sizeof(REQUEST_V4);
		return 4;
	}

	return 0;
}

static void runCreateResponse(const BYTE *const data, const size_t size)
{
	BYTE request[MAX_REQUEST_BUFFER];
	BYTE response[MAX_RESPONSE_BUFFER];
	size_t structSize;
	const int version = requestTarget(data, size, &structSize);

	if (!version) return;

	/* Bytes missing from a too-short request are treated as zero (the server
	 * always reads a full struct out of the RPC stream). */
	memset(request, 0, sizeof(request));
	const size_t copy = size < sizeof(request) ? size : sizeof(request);
	memcpy(request, data, copy);

	if (version == 4)
	{
		CreateResponseV4((REQUEST_V4 *)request, response, "fuzz");
	}
	else
	{
		CreateResponseV6((REQUEST_V6 *)request, response, "fuzz");
	}

	(void)structSize;
}

static void runDecryptResponse(const BYTE *const data, const size_t size)
{
	static BYTE rawRequest[sizeof(REQUEST_V6)];
	static RESPONSE_V6 responseV6;
	static RESPONSE_V4 responseV4;
	static BYTE rawResponse[MAX_RESPONSE_BUFFER];
	static hwid_t hwId;
	const uint32_t major = readVersion(data, size) >> 16;
	size_t copySize = size < sizeof(rawResponse) ? size : sizeof(rawResponse);

	memset(rawRequest, 0, sizeof(rawRequest));
	memset(&responseV6, 0, sizeof(responseV6));
	memset(&responseV4, 0, sizeof(responseV4));
	memset(rawResponse, 0, sizeof(rawResponse));
	memset(hwId, 0, sizeof(hwId));

	memcpy(rawResponse, data, copySize);

	if (major == 4 && copySize >= sizeof(RESPONSE_V4))
	{
		DecryptResponseV4(&responseV4, (int)copySize, rawResponse, rawRequest);
	}
	else if (major == 5 || major == 6)
	{
		DecryptResponseV6(&responseV6, (int)copySize, rawResponse, rawRequest, hwId);
	}
}

/* The KMS code needs its data tables loaded, its per-product response
 * parameter table allocated (vlmcsd.c:1788 does the same), and the PRNG
 * seeded - all once, before the deferred fork server starts. */
extern KmsResponseParam_t *KmsResponseParameters;
extern PVlmcsdHeader_t KmsData;

static void initFuzzer(void)
{
	loadKmsData();

	if (!KmsResponseParameters)
	{
		KmsResponseParameters =
			(PKmsResponseParam_t)calloc(KmsData->CsvlkCount, sizeof(KmsResponseParam_t));
	}

	randomNumberInit();
}

static int readTestcase(const char *const path, BYTE *const buf, const size_t cap, size_t *const outLen)
{
	FILE *file;
	long len;
	int ok = 0;

	file = fopen(path, "rb");
	if (!file) return 0;

	fseek(file, 0, SEEK_END);
	len = ftell(file);
	fseek(file, 0, SEEK_SET);

	if (len > 0 && (size_t)len <= cap)
	{
		if (fread(buf, 1, (size_t)len, file) == (size_t)len)
		{
			*outLen = (size_t)len;
			ok = 1;
		}
	}

	fclose(file);
	return ok;
}

/* vlmcsd's PRNG is seeded from the wall clock (randomNumberInit), so a
 * persistent-mode campaign produces a different rand() stream every
 * iteration and crash inputs cannot be replayed standalone. Re-seed the
 * generator deterministically from the test case itself: the same input
 * always yields the same code path (reproducible), different inputs still
 * explore different paths. FNV-1a over the buffer; the fixed offset keeps
 * an all-zero test case from zeroing the seed. */
static void seedPrng(const BYTE *const buf, const size_t len)
{
	unsigned int hash = 2166136261u;
	size_t i;

	for (i = 0; i < len; i++)
	{
		hash ^= buf[i];
		hash *= 16777619u;
	}

	srand(hash ^ 0x4b4d5301);
}

int main(int argc, char **argv)
{
	isCreateMode = argc < 2 || !strcmp(argv[1], "create");
	const char *const inputFile = argc > 2 ? argv[2] : NULL;

	/* Deferred fork-server: the data tables above are initialized once and
	 * inherited by every forked child. */
	initFuzzer();

#ifdef __AFL_COMPILER
	__AFL_FUZZ_INIT();
	__AFL_INIT();

	while (__AFL_LOOP(1000))
	{
		static BYTE input[MAX_REQUEST_BUFFER + MAX_RESPONSE_BUFFER];
		size_t len;

		/* With "@@" on the command line afl-fuzz rewrites the file every
		 * iteration, so we must re-read it ourselves: the shared-memory
		 * test case buffer is only populated when the target is started
		 * without a file argument. Reading the file each iteration also
		 * makes the harness behave identically when run standalone. */
		if (!readTestcase(inputFile, input, sizeof(input), &len)) continue;

		seedPrng(input, len);

		if (isCreateMode)
		{
			runCreateResponse(input, len);
		}
		else
		{
			runDecryptResponse(input, len);
		}
	}

	return 0;
#else
	/* Plain compiler: run one test case from a file (classic AFL mode). */
	static BYTE input[MAX_REQUEST_BUFFER + MAX_RESPONSE_BUFFER];
	size_t len;

	if (!inputFile) return 0;
	if (!readTestcase(inputFile, input, sizeof(input), &len)) return 0;

	seedPrng(input, len);

	if (isCreateMode)
	{
		runCreateResponse(input, len);
	}
	else
	{
		runDecryptResponse(input, len);
	}

	return 0;
#endif
}