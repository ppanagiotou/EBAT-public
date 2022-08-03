from modules.DEFINES import CONFIGURATION
from modules.log import log


class TaintPostRules:

    def __init__(self):
        self.rule = ""
        self.arg = {}

    def updateArg(self, param, constants):
        lconstant = {}
        for key, c in constants.items():
            if key.strip().upper() == "SAMEAS":
                continue
            try:
                lconstant[key.strip().upper()] = int(c)
            except ValueError:
                try:
                    # try hex string
                    lconstant[key.strip().upper()] = int(c, 16)
                except:
                    lconstant[key.strip().upper()] = c

        self.arg[param] = lconstant


class SingleGroup:

    def __init__(self, parseline):
        # General
        # FunctionName = Library, Cryptographic Algorithm type, keysize (bits), Mode of Operation, encrypt = 1/decrypt = 0, IV or none, sign = 0/verify = 1, Padding or none
        # empty or none for none

        self.crypto_algorithm = None
        self.keysize = None
        self.modeofoperation = None
        self.ivsize = None
        # encrypt = 1 / decrypt = 0
        # if is set then we have the information, if isDecrypt = False then is encrypting!
        self.isEncrypt = None
        # sign = 0 / verify = 1
        self.isVerify = None
        # RSA padding
        self.rsaPadding = None

        arr = parseline.split(',')

        self.library = self.addorNone(arr[0])
        self.crypto_algorithm = self.addorNone(arr[1])

        if len(arr) >= 3:
            self.keysize = self.addorNone(arr[2])

        if len(arr) >= 4:
            self.modeofoperation = self.addorNone(arr[3])

        if len(arr) >= 5:
            if self.addorNone(arr[4]) is not None:
                self.isEncrypt = bool(int(self.addorNone(arr[4])))

        if len(arr) >= 6:
            self.ivsize = self.addorNone(arr[5])

        if len(arr) >= 7:
            if self.addorNone(arr[6]) is not None:
                self.isVerify = bool(int(self.addorNone(arr[6])))

        # TODO added for results need to be implemented in Future general
        if len(arr) >= 8:
            if self.addorNone(arr[7]) is not None:
                self.rsaPadding = self.addorNone(arr[7])


    def addorNone(self, t):
        t = t.strip()
        if t == "none" or t == "":
            return None

        return t


class PostRules:
    GROUPS = ["Cryptographic-Groups"]

    def __init__(self, config):

        self.rules = {}
        sec = config.sections()
        self.groups = {}

        for name in sec:

            if name in self.GROUPS:
                self.groups[name] = dict()
                d = self.groups[name]
                for key, c in config[name].items():
                    d[key] = SingleGroup(c)

                continue

            arr = name.split(".")
            funcName = arr[0]
            if funcName not in self.rules:
                self.rules[funcName] = TaintPostRules()

        for name in sec:

            if name in self.GROUPS:
                continue

            self.addrules(name, config)

            if "SAMEAS" in config[name]:
                sname = config[name]["SAMEAS"].split(",")
                for samename in sname:
                    self.addrules(samename.strip(), config, sameas=name)

    def addrules(self, name, config, sameas=""):

        if sameas == "":
            sameas = name

        arr = name.split(".")
        funcName = arr[0]

        if funcName not in self.rules:
            self.rules[funcName] = TaintPostRules()

        if (len(arr) == 1):
            self.rules[funcName].rule = config[sameas]["rule"]
        elif (len(arr) == 2):
            self.rules[funcName].updateArg(int(arr[1]), config[sameas])
        else:
            log.logWF("Something went wrong parsing post configuration file")
