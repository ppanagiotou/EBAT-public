import copy

from modules.DEFINES import CONFIGURATION
from modules.helpfunctions import mexec


class Yara:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.YARA_COMPILED_CRYPTO = CONFIGURATION.dict["YARA_CRYPTO_CONSTANT_RULES"]
        self.YARA_COMPILED_CREDENTIALS = CONFIGURATION.dict["YARA_CREDENTIAL_RULES"]
        self.YARA_COMPILED_SOFTWARE = CONFIGURATION.dict["YARA_SOFTWARE_COMPONENTS_RULES"]

    def findCryptoConstants(self, location):

        strout = mexec([CONFIGURATION.dict["YARA"], "--compiled-rules", self.YARA_COMPILED_CRYPTO, location], self.verbose)

        # found nothing
        if not isinstance(strout, str):
            return []

        crypto_const = set()
        # get crypto constants names
        for lines in strout.splitlines():
            crypto_constant = lines.split(' ')[0]
            # print(crypto_constant)
            crypto_const.add(crypto_constant)

        return crypto_const

    def findCredentialSearch(self, binary):
        # FACT yara credential search
        strout = mexec([CONFIGURATION.dict["YARA"], "--compiled-rules", self.YARA_COMPILED_CREDENTIALS, binary.location]
                       , self.verbose)

        # found nothing
        if not isinstance(strout, str):
            return False

        if strout == "":
            return False

        return True

    def findSoftwareSearch(self, binary):
        # FACT yara credential search
        strout = mexec([CONFIGURATION.dict["YARA"], "--compiled-rules",
                        self.YARA_COMPILED_SOFTWARE, binary.location, "-s"], self.verbose)

        # found nothing
        if not isinstance(strout, str):
            return []

        if strout == "":
            return []

        arr = []
        for s in strout.splitlines():
            arr.append(s)

        return arr

    def extractCredentialSearch(self, binary):
        # FACT yara credential search
        strout = mexec([CONFIGURATION.dict["YARA"], "--compiled-rules",
                        self.YARA_COMPILED_CREDENTIALS, binary.location, "-s", "-L"],
                       self.verbose)

        yaratype = ""
        lstartoffsets = {}
        lendoffsets = {}
        for line in strout.splitlines():

            arr = line.split()
            if arr[1] == binary.location:
                yaratype = arr[0].strip()
                continue

            if line.__contains__("$start_string"):
                arr = line.split(":")
                lstartoffsets[arr[0].strip()] = arr[1].strip()
            elif line.__contains__("$end_string"):
                arr = line.split(":")
                lendoffsets[arr[0].strip()] = arr[1].strip()

        # convert structures to integers
        startoffsets = []
        endoffsets = []
        for key, value in lstartoffsets.items():
            try:
                startoffsets.append([int(key, 0), int(value)])
            except:
                continue

        for key, value in lendoffsets.items():
            try:
                endoffsets.append([int(key, 0), int(value)])
            except:
                continue

        # print(startoffsets)
        # print(endoffsets)

        canditates = []
        with open(binary.location, 'rb') as f:
            read_data = f.read()
            # print(read_data)
            for i in range(0, len(startoffsets)):
                try:
                    arrs = startoffsets[i]
                    if 0 <= i < len(endoffsets):
                        arre = endoffsets[i]
                        canditates.append(read_data[arrs[0]:(arre[0] + arre[1])])
                    else:
                        canditates.append(read_data[arrs[0]:arrs[1]])
                except:
                    continue


        newbinary = copy.deepcopy(binary)

        newbinary.location = binary.location + ".credentials"

        fpembed = open(newbinary.location, "w+")
        for c in canditates:
            try:
                fpembed.write(str(c, 'utf-8'))
                fpembed.write("\n")
            except:
                continue

        fpembed.close()

        return [newbinary, yaratype]
