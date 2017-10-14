/* See LICENSE file for copyright and license details. */
#include <libkeccak.h>

/**
 * Wrapper for `run` that also initialises the command line parser
 * 
 * @param  suffix  The message suffix
 */
#define RUN(suffix)\
	(run(argc, argv, &spec, suffix))


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
 * @return          An appropriate exit value
 */
int run(int argc, char *argv[], libkeccak_generalised_spec_t *restrict gspec, const char *restrict suffix);
