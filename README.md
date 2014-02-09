COMPLETE STATUS:

    Java 1.2+      :: optimised
    Python 3       :: optimised
    Python 2       :: optimised for Python 3
    C ISO C90      :: optimised
    Java/C JNI     :: optimised
    Vala           :: under development
    NASM           :: planned (maybe)
    Python 3 + C   :: planned (maybe)
    Haskell        :: planned (maybe)
    Perl           :: planned (maybe)
    D              :: planned (maybe)
    Common Lisp    :: planned (perhaps)
    Scala          :: planned (perhaps)
    Magic          :: planned (perhaps)


PERFORMANCE COMPARISON:

    C ISO C90      ::  0,082s ~   1
    Java/C JNI     ::  0,175s ~   2,13
    Java 1.2+      ::  0,228s ~   2,78
    Python 3       :: 24,373s ~ 297
    Python 2       :: 34,595s ~ 422
    
    md5sum         ::  0,009s ~   0,110
    sha1sum        ::  0,013s ~   0,159
    sha384sum      ::  0,015s ~   0,183
    sha512sum      ::  0,015s ~   0,183
    sha224sum      ::  0,020s ~   0,244
    sha256sum      ::  0,021s ~   0,256
    md6sum         ::  0,165s ~   2,01
    
    Based on test against a 2,3 MB file.


**SHA-3/Keccak checksum calculator**

*USAGE:*

    sha3sum [option...] < FILE
    sha3sum [option...] file...

*OPTIONS:*

    -r BITRATE
    --bitrate      The bitrate to use for SHA-3.          (default: 1024)
    
    -c CAPACITY
    --capacity     The capacity to use for SHA-3.         (default: 576)
    
    -w WORDSIZE
    --wordsize     The word size to use for SHA-3.        (default: 64)
    
    -o OUTPUTSIZE
    --outputsize   The output size to use for SHA-3.      (default: 512)
    
    -s STATESIZE
    --statesize    The state size to use for SHA-3.       (default: 1600)
    
    -i ITERATIONS
    --iterations   The number of hash iterations to run.  (default: 1)
    
    -j SQUEEZES
    --squeezes     The number of hash squeezes to run.    (default: 1)
    
    -x
    --hex          Read the input in hexadecimal, rather than binary.
    
    -b
    --binary       Print the checksum in binary, rather than hexadecimal.
    
    -m
    --multi        Print the chechsum at all iterations.


**Pending the standardisation of SHA-3**, there is no specification of particular
SHA-3 functions yet. Our defaults are based on Keccak[] being Keccak[r = 1024, c = 576]
rather than the functions in Wikipedia's entires that uses [r = 576, c = 1024].
No release will made until SHA-3 has been standardise, this is to prevent the
program to change behaviour caused by mismatch with standardisation.


If you want to contribute with an implementation in another
language, please try do so in the earliest version of the
language officially supported on GNU/Linux, unless there are
backwards incompatibilities (as is the case with Python.)
This helps for embedded devices.

