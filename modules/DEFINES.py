

class CONFIGURATION:
    # to hold variables
    dict = {}
    # cryptolib set
    cryptolibs = set()
    # exclude list set
    excludelist = set()
    # rules constants
    rules = {}

    # Used only in meta analysis
    # groups constants
    algorithms = {}
    modesofoperation = {}
    #weakalgorithms = {}
    weakciphers = {}
    weakmodesofoperation = {}
    weakdigesthmac = {}
    weakkdfdigest = {}
    weakpublicdigest = {}
    libsrelease = {}

class DEFINES:

    SUCCESS = 0
    FAILED = 1

    UNKNOWN = 0
    EXECUTABLE = 1
    PIE_EXECUTABLE = 2
    LIBRARY = 3
    SYMBOLIC_LINK = 4
    INODE = 5

    BIT32 = 1
    BIT64 = 2

    LITTLE_ENDIAN = 1
    BIG_ENDIAN = 2

    ELF = 0
    PE =  1
    RAW = 2

    # from configuration only
    DEFAULT = 0
    # from yara or version
    YARAORVERSION = 1
    # from wrapper library
    WRAPPER = 2

    NO_ARGUMENTS = 0

    LEVEL1 = "1"
    LEVEL2 = "2"
    LEVEL3 = "3"
