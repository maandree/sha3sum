/* See LICENSE file for copyright and license details. */
#include "common.h"
#include "arg.h"

#include <alloca.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static void
usage(void)
{
	/*
	 * Since our main in this file validates the arguments,
	 * we can add -a here but leave it left out in common.c,
	 * which we like because the other commands do not have -a.
	 */

	fprintf(stderr, "usage: %s [-u | -l | -b | -c] [-a bits] [-R rate] [-C capacity] "
	                "[-N output-size] [-S state-size] [-W word-size] "
	                "[-Z squeeze-count] [-vxz] [file ...]\n", argv0);
	exit(2);
}

int
main(int argc, char *argv[])
{
	int bits = 224, orig_argc = argc;
	char **orig_argv = alloca((argc + 1) * sizeof(*argv));
	struct libkeccak_generalised_spec spec;

	libkeccak_generalised_spec_initialise(&spec);
	memcpy(orig_argv, argv, (argc + 1) * sizeof(*argv));

	ARGBEGIN {
	case 'R':
	case 'C':
	case 'N':
	case 'O':
	case 'S':
	case 'B':
	case 'W':
	case 'Z':
		(void) EARGF(usage());
		break;
	case 'u':
	case 'l':
	case 'b':
	case 'c':
	case 'v':
	case 'x':
	case 'z':
		break;
	case 'a':
		bits = atoi(EARGF(usage()));
		if (bits != 224 && bits != 256 && bits != 384 && bits != 512) {
			fprintf(stderr, "%s: valid arguments for -a are 224 (default), 256, 384, and 512\n", argv0);
			return 2;
		}
		break;
	default:
		usage();
	} ARGEND;

	libkeccak_spec_sha3((struct libkeccak_spec *)&spec, bits);
	return run(orig_argc, orig_argv, &spec, LIBKECCAK_SHA3_SUFFIX, 1);
}
