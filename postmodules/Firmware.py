import base64
import copy
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

from modules.DEFINES import DEFINES, CONFIGURATION
from modules.Rule import getRuleMnemonic, getMappedKey
from modules.Version import Version, getVersionID, getMnemonicToVersionID
from modules.binary import Binary
from modules.credentials import Credentials
from modules.helpfunctions import mexec
from modules.log import log
import mimetypes

from postmodules.group import CryptoGroup


class Firmware:
    def __init__(self, name, postRules=None, plot=False):

        self.postRules = postRules
        self.plot = plot
        self.name = name
        self.firmwareName = name
        self.times = None
        self.allbinaries = {}

        # hold only executable binaries that have crypto libraries
        self.crypto_binaries = {}
        # hold only executable binaries that have not crypto libraries
        self.non_binaries = {}

        # hold library binaries that have crypto libraries
        self.crypto_libraries = {}
        # hold library binaries that have crypto libraries
        self.non_libraries = {}
        # hold all libraries
        self.allLibraries = {}

        self.alreadyBinaries = {}

        self.analysis = None

        self.usedDict = {}

        self.credentials = {}

        mimetypes.init()

    def isPlot(self):
        return self.plot

    def updateTimes(self, times):
        self.times = times
        self.overallTime = times.getOverall()

    def emptyFilter(self, objmis):

        # TODO recheck that
        if (isinstance(objmis.constValue, list) != True):
            return True

        # discard empty or zero depends if it is ptr = NULL
        if objmis.ruleType == "string" or objmis.ruleType == "bytes":
            if isinstance(objmis.constValue, list):
                # remove all empty values from the list
                objmis.constValue = list(filter(lambda a: a != "", objmis.constValue))
                if len(objmis.constValue) == 0:
                    return True

                allzeroes = True
                for val in objmis.constValue:
                    try:
                        barr = base64.b64decode(val)
                        for b in barr:
                            if b != 0x0:
                                allzeroes = False
                                break
                        if allzeroes == False:
                            break
                    except:
                        continue

                return allzeroes

            if str(objmis.constValue) == "0" or str(objmis.constValue) == "":
                return True

        return False

    def getRulesStatistics(self):

        self.usedDict = copy.copy(CONFIGURATION.rules)

        self.uniqueConstant = {}
        self.uniqueGroup = {}

        for r, item in self.usedDict.items():
            self.usedDict[r] = False

        if (len(self.analysis.uniqueSinks) > 0):
            for hashcode, items in self.analysis.uniqueSinks.items():
                for addr, sinkobj in items.items():
                    self.usedDict[getRuleMnemonic(sinkobj.rule.ruleType)] = True

                    if getRuleMnemonic(sinkobj.rule.ruleType) not in self.uniqueGroup:
                        self.uniqueGroup[getRuleMnemonic(sinkobj.rule.ruleType)] = set()

                    #if (len(sinkobj.algorithm) == 0):
                    #    self.uniqueGroup[getRuleMnemonic(sinkobj.rule.ruleType)].add(
                            #CryptoGroup(sinkobj.sinkFunc, sinkobj.rule.ruleType, self.allbinaries[hashcode],
                            #            sinkobj.isEntry, sinkobj.isLib))
                    #else:
                    #    for alg in sinkobj.algorithm.keys():
                    #        if alg.startswith("NOT-FOUND:"):
                    #            continue
                    #        self.uniqueGroup[getRuleMnemonic(sinkobj.rule.ruleType)].add(
                    #            CryptoGroup(alg, sinkobj.rule.ruleType, self.allbinaries[hashcode], sinkobj.isEntry,
                     #                       sinkobj.isLib))

        # for items in self.uniqueGroup.values():
        #    for obj in items:
        #        if obj.algorithm == 0:
        #            log.logWF("oo -> %s, %s" % (obj.funcName, self.firmwareName))

        for hashcode, lmisuserules in self.analysis.misuseRules.items():
            for addr, absrule in lmisuserules.items():
                for objmis in absrule.abstract:

                    if objmis.isPhi == True or self.analysis.uniqueSinks[hashcode][addr].isEntry == False:
                        continue

                    if objmis.ruleID == CONFIGURATION.rules["SYMMETRIC_KEY_ENCRYPTION_CONSTANT_KEYS"] or \
                            objmis.ruleID == CONFIGURATION.rules["KDFS_AND_PASSWORD_HASH_CONSTANT_KEYS"] or \
                            objmis.ruleID == CONFIGURATION.rules["AUTHENTICATED_ENCRYPTION_CONSTANT_KEY"] or \
                            objmis.ruleID == CONFIGURATION.rules["HASH_FUNCTIONS_KEYED_CONSTANT_KEY"] or \
                            objmis.ruleID == CONFIGURATION.rules["SYMMETRIC_KEY_ENCRYPTION_CONSTANT_IV"] or \
                            objmis.ruleID == CONFIGURATION.rules["AUTHENTICATED_ENCRYPTION_CONSTANT_IV"] or \
                            objmis.ruleID == CONFIGURATION.rules["KDFS_AND_PASSWORD_HASH_CONSTANT_SALTS"] or \
                            objmis.ruleID == CONFIGURATION.rules["HASH_FUNCTIONS_KEYED_CONSTANT_HASH_INPUT"] or \
                            objmis.ruleID == CONFIGURATION.rules["HASH_FUNCTIONS_UNKEYED_CONSTANT_HASH_INPUT"] or \
                            objmis.ruleID == CONFIGURATION.rules["AUTHENTICATED_ENCRYPTION_CONSTANT_INPUT"] or \
                            objmis.ruleID == CONFIGURATION.rules["SYMMETRIC_KEY_ENCRYPTION_CONSTANT_INPUT"] or \
                            objmis.ruleID == CONFIGURATION.rules["AUTHENTICATED_ENCRYPTION_CONSTANT_AAD"] or \
                            objmis.ruleID == CONFIGURATION.rules["AUTHENTICATED_ENCRYPTION_CONSTANT_TAG"]:

                        if (self.emptyFilter(objmis) == True):
                            continue

                        self.usedDict[getRuleMnemonic(objmis.ruleID)] = True

                        if getRuleMnemonic(objmis.ruleID) not in self.uniqueConstant:
                            self.uniqueConstant[getRuleMnemonic(objmis.ruleID)] = set()

                        for item in objmis.constValue:
                            self.uniqueConstant[getRuleMnemonic(objmis.ruleID)].add(item)

                    else:
                        if objmis.ruleID == CONFIGURATION.rules["PSEUDORANDOM_NUMBER_GENERATORS_USING_STATIC_SEED"]:
                            if objmis.constValue is not None:
                                self.usedDict[getRuleMnemonic(objmis.ruleID)] = True
                        else:
                            self.usedDict[getRuleMnemonic(objmis.ruleID)] = True

    def getUniqueConstants(self):

        self.sinkKeys = {}
        self.sinkIVs = {}
        self.sinkInputs = {}
        # parse misuse rules
        for hashcode, lmisuserules in self.analysis.misuseRules.items():

            sinkKeys = {}
            sinkIVs = {}
            sinkInputs = {}
            for addr, absrule in lmisuserules.items():
                for objmis in absrule.abstract:

                    if objmis.ruleID == CONFIGURATION.rules["SYMMETRIC_KEY_ENCRYPTION_CONSTANT_KEYS"] or \
                            objmis.ruleID == CONFIGURATION.rules["KDFS_AND_PASSWORD_HASH_CONSTANT_KEYS"] or \
                            objmis.ruleID == CONFIGURATION.rules["AUTHENTICATED_ENCRYPTION_CONSTANT_KEY"] or \
                            objmis.ruleID == CONFIGURATION.rules["HASH_FUNCTIONS_KEYED_CONSTANT_KEY"]:

                        if (self.emptyFilter(objmis) == True):
                            continue

                        for v in objmis.constValue:
                            if getRuleMnemonic(objmis.ruleID) not in sinkKeys:
                                sinkKeys[getRuleMnemonic(objmis.ruleID)] = set()

                            sinkKeys[getRuleMnemonic(objmis.ruleID)].add(v)
                            # print("\t\t%s, %s, %s" % (getRuleMnemonic(objmis.ruleID), str(objmis.sinkFunc), v))

                    if objmis.ruleID == CONFIGURATION.rules["SYMMETRIC_KEY_ENCRYPTION_CONSTANT_IV"] or \
                            objmis.ruleID == CONFIGURATION.rules["AUTHENTICATED_ENCRYPTION_CONSTANT_IV"] or \
                            objmis.ruleID == CONFIGURATION.rules["KDFS_AND_PASSWORD_HASH_CONSTANT_SALTS"]:

                        if (self.emptyFilter(objmis) == True):
                            continue

                        for v in objmis.constValue:
                            if getRuleMnemonic(objmis.ruleID) not in sinkIVs:
                                sinkIVs[getRuleMnemonic(objmis.ruleID)] = set()

                            sinkIVs[getRuleMnemonic(objmis.ruleID)].add(v)

                    if objmis.ruleID == CONFIGURATION.rules["HASH_FUNCTIONS_KEYED_CONSTANT_HASH_INPUT"] or \
                            objmis.ruleID == CONFIGURATION.rules["HASH_FUNCTIONS_UNKEYED_CONSTANT_HASH_INPUT"] or \
                            objmis.ruleID == CONFIGURATION.rules["AUTHENTICATED_ENCRYPTION_CONSTANT_INPUT"] or \
                            objmis.ruleID == CONFIGURATION.rules["SYMMETRIC_KEY_ENCRYPTION_CONSTANT_INPUT"] or \
                            objmis.ruleID == CONFIGURATION.rules["AUTHENTICATED_ENCRYPTION_CONSTANT_AAD"] or \
                            objmis.ruleID == CONFIGURATION.rules["AUTHENTICATED_ENCRYPTION_CONSTANT_TAG"]:

                        if (self.emptyFilter(objmis) == True):
                            continue

                        for v in objmis.constValue:
                            if getRuleMnemonic(objmis.ruleID) not in sinkInputs:
                                sinkInputs[getRuleMnemonic(objmis.ruleID)] = set()

                            sinkInputs[getRuleMnemonic(objmis.ruleID)].add(v)

            self.sinkKeys[hashcode] = sinkKeys
            self.sinkIVs[hashcode] = sinkIVs
            self.sinkInputs[hashcode] = sinkInputs

    def updateReleaseDate(self, objrelease):
        self.releaseDate = objrelease

    def getLibBinaries(self):
        libversion = []
        for binary in self.allbinaries.values():
            if (binary.version != None):
                libversion.append(binary)

        return libversion

    def parseLibVersions(self, location):
        with open(location) as fp:
            # skip first line
            fp.readline()
            # read the others
            for line in fp.readlines():
                # TODO new version v0.5 change this
                objbin = Binary(location)
                arr = line.split(",")
                newline = ",".join(arr[3:])

                ret = objbin.binaryFromString(newline)
                if not ret:
                    newline = ",".join(arr[2:])
                    objbin.binaryFromString(newline)

                assert (objbin.hashcode in self.allbinaries)

                vid = getMnemonicToVersionID(arr[0].strip())
                v = arr[2].strip().replace(";", "").strip()
                self.allbinaries[objbin.hashcode].version = Version(vid, date=None, version=v,
                                                                    version_name=arr[0].strip())

    def parseCVE(self, location):
        with open(location) as fp:
            getCVE = False
            for line in fp.readlines():
                objBinary = Binary(location)
                ret = objBinary.binaryFromString(line)
                if ret:
                    binary = self.allbinaries[objBinary.hashcode]
                    getCVE = True
                    continue

                if getCVE:
                    binary.cve = json.loads(line)
                    getCVE = False

                    # update version library if it is None
                    if binary.version == None:
                        strid = ""
                        version = ""
                        for item in binary.cve:
                            strid = item["package"]
                            version = item["version"]
                            break

                        binary.version = Version(getMnemonicToVersionID(strid), date=None,
                                                 version=version, version_name=strid)

    def parseCredentials(self, cred_dir):
        for root, dirs, files in os.walk(cred_dir):
            for name in files:

                if name == CONFIGURATION.dict["FILE_CREDENTIALS"]:
                    continue
                location = Path(os.path.join(root, name))

                binary = Binary(location)
                binary.updateHashCode()

                mime = mimetypes.guess_type(binary.location)
                filename, file_extension = os.path.splitext(binary.location)

                self.credentials[binary.hashcode] = Credentials(binary, location, mime[0], file_extension, verbose=False)

    def parseBinaries(self, location):
        with open(location) as fp:
            # skip first line
            fp.readline()
            # read the others
            for line in fp.readlines():
                if line == "\n":
                    continue

                objBinary = Binary(location, getTypeOnly=True)
                ret = objBinary.binaryFromString(line)
                if ret == False:
                    log.logWF("Problem in parsing binary %s" % location)
                    log.logW("Problem in parsing binary %s" % location)
                    continue

                # not unknown and not a symbolic link
                self.allbinaries[objBinary.hashcode] = objBinary

                # If it is a library
                if (objBinary.typeNum == DEFINES.LIBRARY):
                    if (objBinary.isCrypt == True):
                        self.crypto_libraries[objBinary.hashcode] = objBinary
                    else:
                        self.non_libraries[objBinary.hashcode] = objBinary

                    if objBinary.name not in self.allLibraries:
                        self.allLibraries[objBinary.name] = set()

                    self.allLibraries[objBinary.name].add(objBinary)

                    if self.isVerbose():
                        log.logF("library added %s " % (objBinary.location))



                # else if the binary is executable and defined successfully then is a file
                elif (objBinary.typeNum == DEFINES.EXECUTABLE):
                    if (objBinary.isCrypt == True):
                        self.crypto_binaries[objBinary.hashcode] = objBinary
                    else:
                        self.non_binaries[objBinary.hashcode] = objBinary
                    if self.isVerbose():
                        log.logF("executable added %s " % (objBinary.location))

    # dummy function below not to break
    def isDebugPrintAll(self):
        return False

    def isVerbose(self):
        return False

    def isDebug(self):
        return False

    def isYara(self):
        return False

    def applyExclude(self):
        return False

    def saveAST(self):
        return False

    def saveExecutables(self):
        return False

    def saveCallGraphs(self):
        return False

    def saveGhidraProjects(self):
        return True

    def saveAnalysisResults(self):
        return False

    def isEmpty(self):
        return len(self.allbinaries) == 0


class Times:
    def __init__(self, extract=0.0, filter=0.0, cveandlibs=0.0, ghidra=0.0, results=0.0, overall=0.0):
        self.extract = extract
        self.filter = filter
        self.cveandlibs = cveandlibs
        self.overall = overall
        self.ghidralibs = 0.0
        self.ghidraexec = 0.0

        # not used
        self.ghidra = ghidra
        self.results = results


class ParseTime:

    def __init__(self, location):
        self.location = location
        self.timedict = {}
        self.overallTime = 0.0
        self.parseTime()

    def getTimes(self):

        print("Overall: %f" % float(self.overallTime))

        for firmwareName, arrlist in self.timedict.items():
            for arr in arrlist:
                info = arr[0]
                time = float(arr[1])
                print("%s , %s: %f" % (firmwareName, info, time))

    def updateTimes(self, postrules, options):
        firmwares = {}
        for firmwareName, arrlist in self.timedict.items():
            obj = Firmware(firmwareName, postRules=postrules, plot=options.plot)
            times = Times()
            addghidra = 0.0
            addres = 0.0
            for arr in arrlist:
                info = arr[0]
                time = float(arr[1])
                if (info == "Extract-Firmware"):
                    times.extract = time
                elif (info == "Filter-Files"):
                    times.filter = time
                elif (info.startswith("Ghidra")):
                    addghidra = addghidra + time
                elif (info.startswith("Results")):
                    addres = addres + time

            times.ghidra = addghidra
            times.results = addres
            obj.updateTimes(times)
            firmwares[firmwareName] = obj

        return firmwares

    def parseTime(self):
        with open(self.location) as fp:
            for line in fp.readlines():
                arr = line.split(",")

                if len(arr) < 2:
                    continue

                infoarr = arr[0].split(" - ")

                if (len(infoarr) != 5):
                    continue

                info = infoarr[4].strip()
                time = arr[1].strip()
                firmwareName = ""
                if len(arr) == 3:
                    firmwareName = arr[2].strip()
                    if firmwareName not in self.timedict:
                        self.timedict[firmwareName] = []

                    self.timedict[firmwareName].append([info, time])
                else:
                    self.overallTime = time

