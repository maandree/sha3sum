COMPLETE STATUS:

    Pure Java 1.2+ :: optimised
    Python 3       :: optimised
    C ISO C90      :: optimised
    Java/C JNI     :: under development
    Vala           :: under development
    NASM           :: planned (maybe, after jni)
    Haskell        :: planned (maybe)
    Python 2       :: planned (maybe)
    Perl           :: planned (maybe)
    D              :: planned (maybe)
    Common Lisp    :: planned (perhaps)
    Scala          :: planned (perhaps)


**SHA-3/Keccak checksum calculator**

*USAGE:*

    sha3sum [option...] < FILE
    sha3sum [option...] file...

*OPTIONS:*

    -r BITRATE
    --bitrate      The bitrate to use for SHA-3.          (default: 576)
    
    -c CAPACITY
    --capacity     The capacity to use for SHA-3.         (default: 1024)
    
    -w WORDSIZE
    --wordsize     The word size to use for SHA-3.        (default: 64)
    
    -o OUTPUTSIZE
    --outputsize   The output size to use for SHA-3.      (default: 512)
    
    -s STATESIZE
    --statesize    The state size to use for SHA-3.       (default: 1600)
    
    -i ITERATIONS
    --iterations   The number of hash iterations to run.  (default: 1)
    
    -b
    --binary       Print the checksum in binary, rather than hexadecimal.

