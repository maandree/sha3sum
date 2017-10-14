/* See LICENSE file for copyright and license details. */
#include "common.h"

int
main(int argc, char *argv[])
{
	libkeccak_generalised_spec_t spec;
	libkeccak_generalised_spec_initialise(&spec);
	libkeccak_spec_rawshake((libkeccak_spec_t *)&spec, 256, 256);
	return RUN(LIBKECCAK_RAWSHAKE_SUFFIX);
}
