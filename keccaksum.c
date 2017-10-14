/* See LICENSE file for copyright and license details. */
#include "common.h"

int
main(int argc, char *argv[])
{
	libkeccak_generalised_spec_t spec;
	libkeccak_generalised_spec_initialise(&spec);
	return RUN("Keccak", "keccaksum", LIBKECCAK_KECCAK_SUFFIX);
}
