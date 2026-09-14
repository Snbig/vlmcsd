/*
 * Seed generator for the AFL++ fuzz campaign.
 *
 * Builds protocol-shaped KMS request and response test cases using vlmcsd's
 * own client/server builders, so fuzzing starts from realistic inputs.
 *
 *   make-seeds <output-dir>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kms.h"
#include "shared_globals.h"

extern void loadKmsData(void);
extern void randomNumberInit(void);
extern KmsResponseParam_t *KmsResponseParameters;
extern PVlmcsdHeader_t KmsData;

static int writeFile(const char *const dir, const char *const name,
                     const BYTE *const data, const size_t size)
{
	char path[512];
	FILE *file;

	snprintf(path, sizeof(path), "%s/%s", dir, name);

	file = fopen(path, "wb");
	if (!file) return -1;

	if (fwrite(data, 1, size, file) != size)
	{
		fclose(file);
		return -1;
	}

	fclose(file);

	printf("wrote %s (%zu bytes)\n", path, size);
	return 0;
}

static void buildBaseRequest(REQUEST *const base, const WORD major)
{
	memset(base, 0, sizeof(*base));

	base->MajorVer = LE16(major);
	base->MinorVer = LE16(0);
	base->N_Policy = LE32(5);
	getUnixTimeAsFileTime(&base->ClientTime);

	{
		const WCHAR name[] = { 'F','U','Z','Z','P','C',0 };
		memcpy(base->WorkstationName, name, sizeof(name));
	}
}

int main(int argc, char **argv)
{
	BYTE response[MAX_RESPONSE_SIZE + sizeof(RESPONSE_V6) + 64];
	REQUEST base;
	REQUEST_V6 requestV6;
	REQUEST_V4 requestV4;
	BYTE *raw;
	size_t size;
	int ret = 0;

	if (argc < 2) return -1;

	loadKmsData();

	if (!KmsResponseParameters)
	{
		KmsResponseParameters =
			(PKmsResponseParam_t)calloc(KmsData->CsvlkCount, sizeof(KmsResponseParam_t));
	}

	randomNumberInit();

	/* Valid V6 request, prefix of a V4 request, and a deterministic base. */
	buildBaseRequest(&base, 6);
	raw = CreateRequestV6(&size, &base);
	if (!raw) return -1;
	writeFile(argv[1], "req6.bin", raw, size);
	memcpy(&requestV6, raw, sizeof(requestV6));
	free(raw);

	buildBaseRequest(&base, 4);
	raw = CreateRequestV4(&size, &base);
	if (!raw) return -1;
	writeFile(argv[1], "req4.bin", raw, size);
	memcpy(&requestV4, raw, sizeof(requestV4));
	free(raw);

	/* Server-side responses for the client-side decrypt targets. Written at
	 * their exact on-wire length: DecryptResponseV4/V6 size checks derive
	 * from the provided responseSize, so an oversized seed would not only
	 * trigger the bugs being hunted but abort afl-fuzz's initial dry run
	 * (it refuses a corpus where every input crashes). */
	memset(response, 0, sizeof(response));
	size = CreateResponseV6(&requestV6, response, "fuzz");
	if (size) writeFile(argv[1], "resp6.bin", response, size);

	memset(response, 0, sizeof(response));
	size = CreateResponseV4(&requestV4, response, "fuzz");
	if (size) writeFile(argv[1], "resp4.bin", response, size);

	/* A structurally shaped all-zero request for both parsers. */
	writeFile(argv[1], "zero6.bin", (const BYTE *)&(const REQUEST_V6){ .Version = 6 }, sizeof(REQUEST_V6));

	return ret;
}