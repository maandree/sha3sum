/* See LICENSE file for copyright and license details. */
#include <string.h>
#include <stdio.h>

#include "commands.h"

#define _(NAME, MAIN) int MAIN(int argc, char *argv[]);
LIST_COMMANDS(_)
#undef _

int
main(int argc, char *argv[])
{
	char *p;

	p = strrchr(argv[0], '/');
	p = p ? &p[1] : argv[0];

	#define _(NAME, MAIN)\
		if (!strcmp(p, NAME))\
			return MAIN(argc, argv);
	LIST_COMMANDS(_)
	#undef _

	fprintf(stderr, "%s is a multicall binary and cannot be execute directly\n", argv[0]);
	return 127;
}
