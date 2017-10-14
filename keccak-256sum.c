/* See LICENSE file for copyright and license details. */
#include "common.h"

int
main(int argc, char *argv[])
{
	libkeccak_generalised_spec_t spec;
	libkeccak_generalised_spec_initialise(&spec);
	libkeccak_spec_keccak((libkeccak_spec_t *)&spec, 256);
	return RUN("Keccak", "keccak-256sum", LIBKECCAK_KECCAK_SUFFIX);
}
