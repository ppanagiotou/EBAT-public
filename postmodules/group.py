import re

from modules.DEFINES import CONFIGURATION
from modules.Rule import mapToID


class CryptoGroup:

    def __init__(self, func, groupID, postRules, isPhi=False):

        self.funcName = func
        self.groupID = groupID
        self.algorithm = None
        self.keysize = None
        self.library = None
        self.ivsize = None
        self.modeofoperation = None
        self.isEncrypt = None
        self.isVerify = None
        self.isFound = False
        self.isPhi = isPhi

        for name, g in postRules.groups.items():
            if self.funcName in g:
                if g[self.funcName].crypto_algorithm is not None:
                    self.algorithm = CONFIGURATION.algorithms[g[self.funcName].crypto_algorithm]
                if self.algorithm == CONFIGURATION.algorithms["UNKNOWN"]:
                    self.algorithm = None
                self.keysize = g[self.funcName].keysize
                self.modeofoperation = g[self.funcName].modeofoperation
                self.isEncrypt = g[self.funcName].isEncrypt
                self.isVerify = g[self.funcName].isVerify
                self.library = g[self.funcName].library
                self.ivsize = g[self.funcName].ivsize
                self.isFound = True
                break


    def __eq__(self, other):
        return (self.__class__ == other.__class__ and self.funcName == other.funcName)

    def __hash__(self):
        return hash(self.funcName)

    def canMerge(self, other):

        if self.library != other.library:
            return False

        if self.algorithm is not None and other.algorithm is not None:
            return False

        if self.keysize is not None and other.keysize is not None:
            return False

        if self.ivsize is not None and other.ivsize is not None:
            return False

        if self.modeofoperation is not None and other.modeofoperation is not None:
            return False

        if self.isEncrypt is not None and other.isEncrypt is not None:
            return False

        if self.isVerify is not None and other.isVerify is not None:
            return False

        return True
