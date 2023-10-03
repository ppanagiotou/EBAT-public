import ssdeep as fuzzyhashing
import json
import shutil
from random import randrange

from modules.Version import Version, getVersionID
from modules.analysis import Analysis
from modules.helpfunctions import sha256, mexec, createDir, normcaseLinux, mexecGhidra
from modules.log import log
from modules.DEFINES import DEFINES, CONFIGURATION
from pathlib import Path


class Binary:

    def __init__(self, location, firmwareName="", verbose=False, getTypeOnly=False, hash_code=""):
        self.name = location.name  # ntpath.basename(location)
        self.location = str(location)
        self.verbose = verbose
        self.typeNum = DEFINES.UNKNOWN
        # hold firmware name
        self.firmwareName = firmwareName
        # hold library version
        self.version = []
        # hold CVE's
        self.cve = None

        # hold strings
        self.strings = ""

        if self.verbose:
            log.logF("Init binary '" + self.name + "' at location '" + str(self.location) + "'")

        self.getMimeType()
        if (getTypeOnly == True):
            return

        if (self.typeNum == DEFINES.SYMBOLIC_LINK) or (self.typeNum == DEFINES.INODE):
            return

        if (self.typeNum == DEFINES.UNKNOWN):
            return

        self.libraries = set()
        self.vcrypto = {}
        self.isCrypt = False

        # for libraries hold the symbolic names
        self.setofSymbolicNames = set()

        self.hashssdeep = None

        self.crypto_constants = set()

        # hold libraries real SO NAME
        self.soname = ""

        # hold security hardening features
        self.security_hard = {}

        # hold cwe if any
        self.cwe = None

        if hash_code != "":
            # update the digest of file only if it is not updated earlier
            self.updateHashCode()

        self.errcode = self.getArch()
        if self.errcode == DEFINES.FAILED:
            return
        self.errcode = self.checkDynamicLibraries()
        self.updatessdeep()

    def updatessdeep(self):
        self.hashssdeep = fuzzyhashing.hash_from_file(self.location)

    def updateHashCode(self):
        self.hashcode = sha256(self.location)

    def addVersionOfLibrary(self, versionObj):
        # also the version of library
        self.version.append(versionObj)

    # Get mime type and implements the first filter
    def getMimeType(self):

        strtype = mexec([CONFIGURATION.dict["FILECMD"], "--brief", "--mime-type", "--mime-encoding",
                         self.location], self.verbose)

        if (isinstance(strtype, str) == False):
            log.logW("Something went wrong in getMimeType()")
            return DEFINES.FAILED

        self.description = strtype
        x = strtype.split(';')

        if (len(x) == 0):
            log.logW("Something went wrong in len(x) in File CMD")
            return DEFINES.FAILED

        # strip every element in list
        for i in range(0, len(x)):
            x[i] = x[i].strip()

        # application/x-dosexec -> exe
        if (x[0] == 'application/x-executable'):
            self.typeNum = DEFINES.EXECUTABLE  # for executables
            self.charset = x[1]
        # More information about PIE depends on the compiler!!
        elif (x[0] == 'application/x-pie-executable'):
            # mark this as executable -> resolve it on hardening check
            self.typeNum = DEFINES.EXECUTABLE
            self.charset = x[1]
        # x-object = relocatable
        elif (x[0] == 'application/x-sharedlib') or (x[0] == 'application/x-object'):
            self.typeNum = DEFINES.LIBRARY  # for libaries
            self.charset = x[1]
        elif (x[0] == 'inode/symlink'):
            self.typeNum = DEFINES.SYMBOLIC_LINK
            # resolve symbolic link location
            strsym = ""  # catch non utf links resolve
            try:
                strsym = mexec([CONFIGURATION.dict["READLINK"], "-q", "-n", self.location], self.verbose)
            except:
                pass
            self.symbolic_loc = strsym
        elif x[0].__contains__('inode'):
            self.typeNum = DEFINES.INODE

        return DEFINES.SUCCESS

    def getArch(self):

        strtype = mexec([CONFIGURATION.dict["FILECMD"], "--brief", self.location], False)

        if (isinstance(strtype, str) == False):
            log.logW("Something went wrong in getArch()")
            return DEFINES.FAILED

        if self.verbose:
            log.logF(strtype)

        obj = strtype.split(',')

        if len(obj) <= 1:
            log.logW("file error " + self.name)
            return DEFINES.FAILED

        ARCH_INDEX = 1
        ARCH_TYPES = 0
        if (obj[0].strip() == "setuid"):
            ARCH_INDEX = 2
            ARCH_TYPES = 1

        # read architecture
        self.arch = obj[ARCH_INDEX].strip()

        # [type = ELF,PE,RAW, BIT = 32bit, 64bit, endianness = MSB,LSB, pie executable, executable, shared ]
        x = obj[ARCH_TYPES].split()

        # strip every element in list
        for i in range(0, len(x)):
            x[i] = x[i].strip()

        # check if there are shared objects as well and marked them
        if ("shared" in x):
            # check the ending extension
            pos = self.name.find(".")
            isSo = False
            if (pos >= 0):
                ext = self.name[pos:]
                if (ext.find(".so") >= 0):
                    # update type
                    self.typeNum = DEFINES.LIBRARY
                    isSo = True
            if not isSo:
                # possibly executable
                self.typeNum = DEFINES.EXECUTABLE

        elif ("pie" in x):
            # mark this as executable -> resolve it on hardening check
            self.typeNum = DEFINES.EXECUTABLE
        elif ("executable" in x):
            self.typeNum = DEFINES.EXECUTABLE

        # read type
        if ("ELF" in x):
            self.filetype = DEFINES.ELF
        elif ("PE" in x):
            self.filetype = DEFINES.PE
        else:
            self.filetype = DEFINES.RAW

        # read bit architecture
        if ("32-bit" in x):
            self.bit = DEFINES.BIT32
        elif ("64-bit" in x):
            self.bit = DEFINES.BIT64
        else:
            self.bit = DEFINES.UNKNOWN

        # read endianness
        if ("LSB" in x):
            self.endianness = DEFINES.LITTLE_ENDIAN
        elif ("MSB" in x):
            self.endianness = DEFINES.BIG_ENDIAN
        else:
            self.endianness = DEFINES.UNKNOWN

        return DEFINES.SUCCESS

    def filterBinaries(self):
        # search all crypto libs
        for x in CONFIGURATION.cryptolibs:
            for lib in self.libraries:
                if (lib.startswith(x)):
                    self.vcrypto[lib] = DEFINES.DEFAULT

        if (len(self.vcrypto) > 0):
            if self.verbose:
                log.logF("FOUND CRYPTO LIB" + ",".join(self.vcrypto))

            # true includes crypto lib!
            # now only for executables
            self.isCrypt = True

            if self.verbose:
                for x in self.vcrypto:
                    log.logF(x + ",")

        else:
            if self.verbose:
                log.logF("Not found crypto lib\n" + ",".join(self.libraries))

        return DEFINES.SUCCESS

    def checkDynamicLibraries(self):
        if self.filetype != DEFINES.ELF:
            log.logWF("Only ELF files are supported so far: " + self.name + " '" + self.location + "'")
            log.logW("Only ELF files are supported so far. See log files for more info")
            return DEFINES.FAILED

        if (CONFIGURATION.dict["READELF"] == ""):
            log.logE("check configuration for READELF not found")
            return DEFINES.FAILED

        strlibs = ""
        try:
            # capture non utf-8 decodes
            strlibs = mexec([CONFIGURATION.dict["READELF"], "-d", self.location])
        except:
            pass

        if (isinstance(strlibs, str) == False):
            if (self.getLibrariesWithGhidra() == DEFINES.FAILED):
                log.logWF("Something went wrong in checkDynamicLibraries() - "
                          "readelf Needed libraries:" + self.name + " at " + self.location)
                return DEFINES.FAILED

            return self.filterBinaries()

        # adding the name to the library set
        for line in strlibs.splitlines():
            if (line.find("NEEDED") > 0):
                arr = line.strip().split('Shared library:')
                if (len(arr) >= 2):
                    libname = arr[1]
                    libname = libname.strip()
                    libname = libname.replace(']', '')
                    libname = libname.replace('[', '')
                    self.libraries.add(libname)
                else:
                    if (self.getLibrariesWithGhidra() == DEFINES.FAILED):
                        log.logWF("Something went wrong in checkDynamicLibraries() - "
                                  "readelf Needed libraries:" + self.name + " at " + self.location)
                        return DEFINES.FAILED

                    break

            elif (line.find("SONAME") > 0):
                try:
                    soname = line.strip().split('Library soname:')[1]
                except:
                    continue
                soname = soname.replace("[", "").replace("]", "").strip()
                if (soname != ""):
                    self.soname = soname
                    pos = self.soname.find(".")
                    # get crypto lib and mark it
                    if (pos >= 0):
                        realname = self.soname[:pos]
                        if (Version.UNKNOWN != getVersionID(realname)):
                            # mark as crypto library
                            self.isCrypt = True
                    # define the type
                    # if I have soname I am sure it is a library
                    self.typeNum = DEFINES.LIBRARY

        return self.filterBinaries()

    def getLibrariesWithGhidra(self):
        LIMIT_PLUS = 20
        # use GHIDRA import no analysis and delete after!
        # -deleteProject
        # -noanalysis
        ANALYZEPROC = CONFIGURATION.dict["GHIDRADIR"] + "/support/" + CONFIGURATION.dict["GHIDRAANALYSE"]
        tmp_dir = Path("/tmp/" + self.hashcode + str(randrange(int(self.hashcode, 16))))
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir)
        createDir(tmp_dir)
        strout = mexecGhidra([ANALYZEPROC, str(tmp_dir), self.name,
                              "-noanalysis", "-deleteProject",
                              "-import", normcaseLinux(self.location),
                              "-scriptPath", Analysis.GHIDRA_SCRIPTS,
                              "-postScript", "FindLibraries.java"], verbose=self.verbose)
        # delete any remaining
        shutil.rmtree(tmp_dir)
        if (isinstance(strout, str) == False):
            log.logW(
                "Something went wrong during analysis of " + self.name + ". Error in getLibrariesWithGhidra() please see the log files for more")
            return DEFINES.FAILED

        getjson = ""
        for lines in strout.splitlines():
            if lines.startswith("JSON;"):
                getjson = lines[5:]
                break

        try:
            libs = json.loads(getjson)
            for libname in libs["libnames"]:
                self.libraries.add(libname)
        except ValueError as e:
            log.logW(
                "Something went wrong during getLibrariesWithGhidra() of " + self.name + ". Parsing JSON string failed, please see the log files for more")
            return DEFINES.FAILED

    def isSymbolic(self):
        return (self.typeNum == DEFINES.SYMBOLIC_LINK)

    def isinode(self):
        return (self.typeNum == DEFINES.INODE)

    def isExec(self):
        return (self.typeNum == DEFINES.EXECUTABLE)

    def isLib(self):
        return (self.typeNum == DEFINES.LIBRARY)

    def isBinary(self):
        return (self.typeNum == DEFINES.LIBRARY or self.typeNum == DEFINES.PIE_EXECUTABLE
                or self.typeNum == DEFINES.EXECUTABLE)

    def toString(self):
        if self.typeNum == DEFINES.UNKNOWN or self.errcode == DEFINES.FAILED:
            return ""

        return "{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}" \
            .format(self.name, self.getTypeMnemonic(),
                    self.getFileMnemonic(), self.arch, self.getBitMnemonic(), self.getEndiannessMnemonic(),
                    ";".join(self.vcrypto), ";".join(self.libraries), self.firmwareName, self.location, self.hashcode,
                    self.hashssdeep, ";".join(self.setofSymbolicNames), str(self.security_hard))

    def getTypeMnemonic(self):
        cstr = ""
        if (self.isCrypt):
            cstr = " - Crypto"

        if (self.isExec()):
            return "EXECUTABLE" + cstr
        elif (self.isLib()):
            return "LIBRARY" + cstr

        return "NOT FOUND"

    def getFileMnemonic(self):

        if self.filetype == DEFINES.ELF:
            return "ELF"
        elif self.filetype == DEFINES.PE:
            return "PE"
        elif self.filetype == DEFINES.RAW:
            return "RAW"

        return "NOT FOUND"

    def getBitMnemonic(self):

        if self.bit == DEFINES.BIT32:
            return "32"
        elif self.bit == DEFINES.BIT64:
            return "64"

        return "NOT FOUND"

    def getEndiannessMnemonic(self):

        if self.endianness == DEFINES.LITTLE_ENDIAN:
            return "LE"
        elif self.endianness == DEFINES.BIG_ENDIAN:
            return "BE"

        return "NOT FOUND"

    def binaryFromString(self, bstr):
        arrstr = bstr.split(",")

        if (len(arrstr) != 13):
            return False
        # strip every element in list
        for i in range(0, len(arrstr)):
            arrstr[i] = arrstr[i].strip()

        self.version = None
        self.cve = None
        self.setofSymbolicNames = set()

        self.name = arrstr[0]
        mnemonic = arrstr[1]
        self.isCrypt = False
        if (mnemonic.find("Crypto") >= 0):
            self.isCrypt = True

        if (mnemonic.startswith("EXECUTABLE")):
            self.typeNum = DEFINES.EXECUTABLE
        elif (mnemonic.startswith("LIBRARY")):
            self.typeNum = DEFINES.LIBRARY
        else:
            self.typeNum = DEFINES.UNKNOWN

        mnemonic = arrstr[2]
        if (mnemonic.startswith("ELF")):
            self.filetype = DEFINES.ELF
        elif (mnemonic.startswith("PE")):
            self.filetype = DEFINES.PE
        elif (mnemonic.startswith("RAW")):
            self.filetype = DEFINES.RAW
        else:
            self.filetype = DEFINES.UNKNOWN

        self.arch = arrstr[3]

        mnemonic = arrstr[4]
        if (mnemonic.startswith("32")):
            self.bit = DEFINES.BIT32
        elif (mnemonic.startswith("64")):
            self.bit = DEFINES.BIT64
        else:
            self.bit = DEFINES.UNKNOWN

        mnemonic = arrstr[5]
        if (mnemonic.startswith("LE")):
            self.endianness = DEFINES.LITTLE_ENDIAN
        elif (mnemonic.startswith("BE")):
            self.endianness = DEFINES.BIG_ENDIAN
        else:
            self.endianness = DEFINES.UNKNOWN

        self.libraries = set()
        self.vcrypto = {}
        if (self.isCrypt == True):
            vcryptstr = arrstr[6]
            for elem in vcryptstr.split(";"):
                self.vcrypto[elem.strip()] = DEFINES.DEFAULT

        libstr = arrstr[7]
        for elem in libstr.split(";"):
            self.libraries.add(elem.strip())

        self.firmwareName = arrstr[8]
        self.location = arrstr[9]
        self.hashcode = arrstr[10]

        if (len(self.hashcode) != 64):
            return False

        self.hashssdeep = arrstr[11]
        for elem in arrstr[12].split(";"):
            self.setofSymbolicNames.add(elem.strip())

        self.errcode = DEFINES.SUCCESS
        return True

    def isCryptVersion(self):

        if len(self.version) == 0:
            return False

        for vobj in self.version:
            if vobj.type != Version.UNKNOWN:
                return True

        return False
