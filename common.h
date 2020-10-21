/* See LICENSE file for copyright and license details. */
#include <libkeccak.h>


#define COMMON_MAIN(CONFIGURATION, SUFFIX)\
	int main(int argc, char *argv[]) {\
		struct libkeccak_generalised_spec spec;\
		libkeccak_generalised_spec_initialise(&spec);\
		CONFIGURATION;\
		return run(argc, argv, &spec, SUFFIX, 0);\
	}
#define KECCAK_MAIN(N)\
	COMMON_MAIN(libkeccak_spec_sha3((struct libkeccak_spec *)&spec, N), "")
#define SHA3_MAIN(N)\
	COMMON_MAIN(libkeccak_spec_sha3((struct libkeccak_spec *)&spec, N), LIBKECCAK_SHA3_SUFFIX)
#define RAWSHAKE_MAIN(N)\
	COMMON_MAIN(libkeccak_spec_rawshake((struct libkeccak_spec *)&spec, N, N), LIBKECCAK_RAWSHAKE_SUFFIX)
#define SHAKE_MAIN(N)\
	COMMON_MAIN(libkeccak_spec_shake((struct libkeccak_spec *)&spec, N, N), LIBKECCAK_SHAKE_SUFFIX)


/**
 * Message digest representation formats
 */
enum representation {
	/**
	 * Print the checksum in binary
	 */
	REPRESENTATION_BINARY,

	/**
	 * Print the checksum in upper case hexadecimal
	 */
	REPRESENTATION_UPPER_CASE,

	/**
	 * Print the checksum in lower case hexadecimal
	 */
	REPRESENTATION_LOWER_CASE
};


/**
 * Parse the command line and calculate the hashes of the selected files
 * 
 * @param   argc    The first argument from `main`
 * @param   argv    The second argument from `main`
 * @param   gspec   The default algorithm parameters
 * @param   suffix  Message suffix
 * @param   with_a  Whether the -a option should be recognised (but ignored)
 * @return          An appropriate exit value
 */
int run(int argc, char *argv[], struct libkeccak_generalised_spec *restrict gspec, const char *restrict suffix, int with_a);
