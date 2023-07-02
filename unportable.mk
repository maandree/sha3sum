keccak-%sum.c:
	printf '%s\n' '#include "common.h"' 'KECCAK_MAIN($*)' > $@

sha3-%sum.c:
	printf '%s\n' '#include "common.h"' 'SHA3_MAIN($*)' > $@

rawshake%sum.c:
	printf '%s\n' '#include "common.h"' 'RAWSHAKE_MAIN($*)' > $@

shake%sum.c:
	printf '%s\n' '#include "common.h"' 'SHAKE_MAIN($*)' > $@
