import re

from modules.DEFINES import CONFIGURATION


# get rule mnemonic from rules dictionary
def getRuleMnemonic(ruleid):
    for key, v in CONFIGURATION.rules.items():
        if v == ruleid:
            return key
    return "NOT FOUND"


# get mapped key from a dictionary
def getMappedKey(id, ldict):
    for key, v in ldict.items():
        if v == id:
            return key
    return "NOT FOUND"


class TaintedArgs:
    def __init__(self, type, ruleid):
        self.defaultValues = set()

        if (type.startswith("bytes")):
            arrtype = type.strip().split("=")

            self.type = arrtype[0]
            for i in range(1, len(arrtype)):
                self.defaultValues.add(arrtype[i].strip())

        else:
            self.type = type

        self.ruleid = ruleid
        self.successors = set()

    def addSuccessor(self, arg):
        self.successors.add(arg)

    def typeToString(self):
        if len(self.defaultValues) > 0:
            return self.type + "=" + "=".join(self.defaultValues)
        else:
            return self.type


class Rule:

    def __init__(self, rule):
        try:
            arr = rule.split(";")

            if (len(arr) < 4):
                self.isRule = False
                return

            self.taintedArgs = {}
            for i in range(4, len(arr)):
                arrtype = arr[i].strip().split(":")

                if (len(arrtype) != 3):
                    continue

                self.taintedArgs[arrtype[0].strip()] = TaintedArgs(arrtype[1].strip(), arrtype[2].strip())

            for i in range(4, len(arr)):
                arrtype = arr[i].strip().split("<")

                if (len(arrtype) != 2):
                    continue

                if arrtype[0].strip() in self.taintedArgs:
                    self.taintedArgs[arrtype[0].strip()].addSuccessor(arrtype[1].strip())

            self.rule = rule
            self.FunctionName = arr[0].strip()
            self.FunctionSignature = arr[1]
            self.NumberofParameters = int(arr[2].strip())
            self.ruleType = int(arr[3].strip())
            self.isRule = True
        except:
            self.isRule = False

    def toString(self):

        argstring = ""
        argsuccesor = ""
        for arg, obj in self.taintedArgs.items():
            typestr = obj.typeToString()
            argstring = argstring + str(arg) + ":" + typestr + ":" + str(obj.ruleid) + "; "

            for s in obj.successors:
                argsuccesor = argsuccesor + str(arg) + "<" + str(s) + "; "

        return '{}; {}; {}; {}; {} {}'.format(self.FunctionName, self.FunctionSignature, self.NumberofParameters,
                                              self.ruleType, argstring, argsuccesor)


class AbstractRule:

    def __init__(self, strrule, abstract=None, mapped=None):
        self.rule = Rule(strrule)
        self.abstract = []
        self.mapped = mapped
        if (abstract != None):
            self.abstract.append(abstract)

    def addAbstract(self, obj):
        self.abstract.append(obj)


class Misuse:

    def __init__(self, ruleID, fromFunc, targetFunc, atAddress, ruleType, getAlgorithm, getArg, constValue=None,
                 constAddress=None,
                 isPhi=False):
        self.ruleID = ruleID
        self.ruleType = ruleType
        self.fromFunc = fromFunc
        self.targetFunc = targetFunc
        self.atAddress = atAddress
        self.constValue = constValue
        self.constAddress = constAddress
        self.isPhi = isPhi
        self.constLength = 0
        self.algorithm = getAlgorithm
        self.getArg = getArg


class Sink:

    def __init__(self, rule, fromFunc, targetFunc, atAddress, algorithm, isEntry=False, isLib=False, isWrapper=False,
                 metarule=None, extrameta=None, isHMAC=False):
        self.rule = rule
        self.fromFunc = fromFunc
        self.targetFunc = targetFunc
        self.atAddress = atAddress
        self.algorithm = algorithm
        self.isEntry = isEntry
        self.isLib = isLib
        self.isWrapper = isWrapper
        self.metarule = metarule
        self.cryptoGroup = []
        self.extrameta = extrameta
        self.isHMAC = isHMAC


def mapToID(funcName, ldict):
    for key, value in ldict.items():
        if re.search(key, funcName, re.IGNORECASE):
            return value

    return ldict["UNKNOWN"]


class CryptoPrimitiveGroup:

    def __init__(self, type):
        self.type = type


class TaintedMapped:

    def __init__(self, argFrom, rule):
        self.argFrom = argFrom
        self.rule = rule
