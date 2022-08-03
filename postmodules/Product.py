import base64
import collections
import copy
import hashlib
import os
import queue
import shutil
from pathlib import Path
from collections import OrderedDict
import numpy

from modules.DEFINES import *
from modules.Rule import getRuleMnemonic
from modules.Version import Version
from modules.analysis import Analysis
from modules.binary import Binary
from modules.helpfunctions import createDir, mexec
from modules.log import log


class Product:
    def __init__(self, options, outputDir, location, objTime, firmwares, name, vendorName, typeName, sortRelease):

        self.options = options
        self.location = location
        self.vendorName = vendorName
        self.typeName = typeName
        self.outputDir = outputDir
        self.name = name
        self.objTime = objTime
        self.firmwares = {}
        self.sortRelease = sortRelease

        self.cvehold = {}

        for name, obj in sortRelease.items():
            self.firmwares[name] = firmwares[name]

        self.updateTimes()

        self.guniqueSinks = {}

        self.xaxis = []
        self.yaxis = []

        self.cxaxis = []
        self.cyaxis = []

    def isPlot(self):
        return self.options.plot

    def updateAnalysisLocations(self):

        self.analysisDir = self.location / CONFIGURATION.dict["DIR_ANALYSIS"]

        for firm in self.firmwares.values():
            firm.analysisDir = self.location / CONFIGURATION.dict["DIR_ANALYSIS"] / firm.name

    def parseAnalysisandMisuse(self):

        for firm in self.firmwares.values():
            fp = open(firm.analysisDir / CONFIGURATION.dict["FILE_ANALYSIS"], "r")
            # skip header
            fp.readline()
            fp.readline()

            toget = False
            for line in fp.readlines():
                binary = Binary(firm.analysisDir)
                if (binary.binaryFromString(line) == True):
                    toget = True
                    forbinary = binary
                    continue

                if (line == "\n"):
                    toget = False
                    continue

                if toget:
                    # print(line)
                    isSame = False
                    if (line.startswith("SAME")):
                        isSame = True
                    else:
                        arr = line.split(",")
                        getSink = arr[0]
                        getType = arr[1]
                        fromEntry = arr[2]
                        algorithms = ""
                        if (len(arr) == 6):
                            algorithms = arr[5]
            fp.close()

            fp = open(firm.analysisDir / CONFIGURATION.dict["FILE_MISUSE"], "r")
            # skip header
            fp.readline()
            fp.readline()

            toget = False
            for line in fp.readlines():
                binary = Binary(firm.analysisDir)
                if (binary.binaryFromString(line) == True):
                    toget = True
                    forbinary = binary
                    continue

                if (line == "\n"):
                    toget = False
                    continue

                if toget:
                    # print(line)
                    isSame = False
                    if (line.startswith("SAME")):
                        isSame = True
                    else:
                        arr = line.split(",")
                        getSink = arr[0]
                        getType = arr[1]
                        fromEntry = arr[2]
                        algorithms = ""
                        if (len(arr) == 6):
                            algorithms = arr[5]
            fp.close()

    def dummybinary(self, line):
        arr = line.split(",")
        if (len(arr) != 4):
            return False

        if (len(arr[3].strip()) != 64):
            return False

        return True

    def getdummyhash(self, line):
        arr = line.split(",")
        return arr[3].strip()

    def updateAnalysisStructure(self):

        for firm in self.firmwares.values():
            analysisDir = firm.analysisDir
            firm.analysisDir = Path(str(self.outputDir) + str(firm.analysisDir))
            createDir(firm.analysisDir)

            # update analysis already
            for hashcode in firm.alreadyBinaries.values():
                binary = firm.allbinaries[hashcode]
                if (binary.firmwareName != firm.name):
                    # set namewrappers
                    firm.analysis.namewrappers[hashcode] = self.firmwares[binary.firmwareName].analysis.namewrappers[
                        hashcode]

                    # set crypto wrappers
                    firm.analysis.setofCryptoWrapper.add(binary.name)

            firm.analysis = Analysis(firm)

            savefirstSAME = ""
            fp = open(analysisDir / CONFIGURATION.dict["FILE_ANALYSIS"], "r")
            # skip header
            fp.readline()
            fp.readline()

            toget = False
            forbinary = None
            isSameb = False
            for line in fp.readlines():
                binary = Binary(firm.analysisDir)
                if (binary.binaryFromString(line) == True):
                    toget = True
                    forbinary = binary

                    continue

                if (line == "\n"):
                    toget = False
                    continue

                if toget:
                    toget = False
                    if (line.startswith("SAME")):
                        savefirstSAME = savefirstSAME + forbinary.toString() + "\n"
                        savefirstSAME = savefirstSAME + line + "\n"
                    else:
                        dirname = forbinary.name
                        dirs = os.listdir(analysisDir / "JSON")
                        assert(dirname in dirs)

                        testdir = forbinary.name + "-" + forbinary.hashcode
                        if testdir in dirs:
                            dirname = testdir

                        fpjson = open(analysisDir / "JSON" / dirname / "json.txt", "r")
                        lineb = fpjson.readline()
                        # init
                        objBinary = Binary(analysisDir)
                        objBinary.binaryFromString(lineb)
                        PROJECTNAME = dirname

                        print("\n\t%s at %s\n\t\tCryptolibs: %s\n\t\tAllLibs: %s" % (
                            objBinary.name, objBinary.location, objBinary.vcrypto, objBinary.libraries))

                        # create structures
                        firm.analysis.getAnalysisResults(objBinary, "".join(fpjson.readlines()), PROJECTNAME,
                                                         objBinary.isLib())

                        fpjson.close()

            fp.close()

            firm.analysis.fpanalysis.close()
            firm.analysis.fpmisuse.close()

            if (savefirstSAME != ""):
                fpedit = open(firm.analysisDir / CONFIGURATION.dict["FILE_ANALYSIS"], "r")
                ah1 = fpedit.readline()
                ah2 = fpedit.readline()
                aothers = "".join(fpedit.readlines())
                fpedit.close()

                fpedit = open(firm.analysisDir / CONFIGURATION.dict["FILE_MISUSE"], "r")
                mh1 = fpedit.readline()
                mh2 = fpedit.readline()
                mothers = "".join(fpedit.readlines())
                fpedit.close()

                fpnew = open(firm.analysisDir / CONFIGURATION.dict["FILE_ANALYSIS"], "w")
                fpnew.write(ah1)
                fpnew.write(ah2)
                fpnew.write(savefirstSAME)
                fpnew.write(aothers)
                fpnew.close()

                fpnew = open(firm.analysisDir / CONFIGURATION.dict["FILE_MISUSE"], "w")
                fpnew.write(mh1)
                fpnew.write(mh2)
                fpnew.write(savefirstSAME)
                fpnew.write(mothers)
                fpnew.close()

            origanalysis = Path(analysisDir / CONFIGURATION.dict["FILE_ANALYSIS"]).stat().st_size
            copyanalysis = Path(firm.analysisDir / CONFIGURATION.dict["FILE_ANALYSIS"]).stat().st_size
            if (origanalysis != copyanalysis):
                # check for same
                # log.logWF("ERROR SIZE ANALYSIS %s" % (firm.name))
                log.logW("ERROR SIZE ANALYSIS %s" % (firm.name))
                # exit(DEFINES.FAILED)

            origanalysis = Path(analysisDir / CONFIGURATION.dict["FILE_MISUSE"]).stat().st_size
            copyanalysis = Path(firm.analysisDir / CONFIGURATION.dict["FILE_MISUSE"]).stat().st_size
            if (origanalysis != copyanalysis):
                #log.logWF("ERROR SIZE MISUSE %s" % (firm.name))
                log.logW("ERROR SIZE MISUSE %s" % (firm.name))
                #exit(DEFINES.FAILED)

            firm.analysisDir = analysisDir

            # update analysis already
            for hashcode in firm.alreadyBinaries.values():
                binary = firm.allbinaries[hashcode]
                if (binary.firmwareName != firm.name):
                    firm.analysis.misuseRules[hashcode] = self.firmwares[binary.firmwareName].analysis.misuseRules[
                        hashcode]
                    firm.analysis.uniqueSinks[hashcode] = self.firmwares[binary.firmwareName].analysis.uniqueSinks[
                        hashcode]

            # update rule statistics
            firm.getRulesStatistics()

            # update global uniqueSinks
            self.guniqueSinks[firm.name] = firm.analysis.uniqueSinks

        # update product rules statistics
        self.usedDict = copy.copy(CONFIGURATION.rules)
        self.uniqueConstant = copy.copy(CONFIGURATION.rules)
        for r, item in self.usedDict.items():
            self.usedDict[r] = False
            self.uniqueConstant[r] = set()

        for firm in self.firmwares.values():
            for key, value in firm.usedDict.items():
                self.usedDict[key] = self.usedDict[key] or value

            for key, sv in firm.uniqueConstant.items():
                for v in sv:
                    self.uniqueConstant[key].add(v)

    def isEmpty(self):
        ret = False
        for firm in self.firmwares.values():
            ret = ret or firm.isEmpty()

        return ret

    def updateTimes(self):
        self.overallTime = float(self.objTime.overallTime)
        self.overallExtract = 0.0
        self.overallFilter = 0.0
        self.overallGhidra = 0.0
        self.overallResults = 0.0
        for firm in self.firmwares.values():
            self.overallExtract = self.overallExtract + firm.times.extract
            self.overallFilter = self.overallFilter + firm.times.filter
            self.overallGhidra = self.overallGhidra + firm.times.ghidra
            self.overallResults = self.overallResults + firm.times.results

    def createStatistics(self):

        fp = open(self.outputDir / CONFIGURATION.dict["GLOBAL_REPORT_STATISTICS"], "w+")

        self.countercredentials = {}

        for firmware in self.firmwares.values():

            fp.write("Firmware: %s, %s:\n" % (firmware.name, firmware.releaseDate.strftime("%d/%m/%Y")))

            maxarch = maxbit = maxtype = maxendiannes = ""
            # get architectures
            cgen = {}
            if len(firmware.counters.arch) > 0:
                maxarch = max(firmware.counters.arch, key=lambda key: firmware.counters.arch[key])
                maxbit = max(firmware.counters.bit, key=lambda key: firmware.counters.bit[key])
                maxtype = max(firmware.counters.file, key=lambda key: firmware.counters.file[key])
                maxendiannes = max(firmware.counters.endianness, key=lambda key: firmware.counters.endianness[key])

            if (maxarch == ""):
                continue

            strgen = maxarch + "-" + maxbit + "-" + maxendiannes + "-" + maxtype
            if (strgen not in cgen):
                cgen[strgen] = 0

            cgen[strgen] = cgen[strgen] + 1

            fp.write("General:\n")
            for key, count in cgen.items():
                fp.write("\t%s\n" % (key))

            ccred = {}
            for credential in firmware.credentials.values():
                for index, type in credential.type.items():
                    key = credential.getMnemonic(credential.type[index])

                    if key not in ccred:
                        ccred[key] = 0

                    ccred[key] = ccred[key] + 1

                    if key not in self.countercredentials:
                        self.countercredentials[key] = 0

                    self.countercredentials[key] = self.countercredentials[key] + 1

            fp.write("\nCredential types:\n")
            for key, count in ccred.items():
                fp.write("\t%s: %d\n" % (key, count))

            fp.write("\n")

        fp.close()

    def createTimeFile(self):
        fp = open(self.outputDir / CONFIGURATION.dict["TIME_MATRIX"], "w+")

        fp.write(
            "Firmware/Product Name, Release Date, Extract Time (s), Filter Time (s), Ghidra Time (s), Analysis Time (s), Overall Time(s)\n")

        for firm in self.firmwares.values():
            fp.write("%s, %s, %f, %f, %f, %f, %f\n" % (firm.name, firm.releaseDate.strftime("%d/%m/%Y"),
                                                       firm.times.extract, firm.times.filter, firm.times.ghidra,
                                                       firm.times.results, firm.overallTime))

        fp.write("%s, %s, %f, %f, %f, %f, %f\n" % (self.name, "None",
                                                   float(self.overallExtract), float(self.overallFilter),
                                                   float(self.overallGhidra), float(self.overallResults),
                                                   float(self.overallTime)))
        fp.close()

    def createCounterFile(self):
        fp = open(self.outputDir / CONFIGURATION.dict["COUNTERS_ALL"], "w+")

        fp.write("Firmware Name, Date, Libraries, PIE, Executables, Libraries - Crypto, PIE - Crypto,"
                 " Executables - Crypto, Total previous Libraries, Total previous PIE, Total previous Executables, "
                 "Total previous Libraries - Crypto, Total previous PIE - Crypto, Total previous Executables - Crypto, ")
        for name, obj in self.sortRelease.items():
            fp.write("Libraries: " + name + ", ")
            fp.write("PIE: " + name + ", ")
            fp.write("Executables: " + name + ", ")
            fp.write("Libraries - Crypto: " + name + ", ")
            fp.write("PIE - Crypto: " + name + ", ")
            fp.write("Executables - Crypto: " + name + ", ")

        fp.write("\n")

        for firm in self.firmwares.values():
            wrstr = firm.name + ", " + firm.releaseDate.strftime("%d/%m/%Y") + ", "
            wrstr = wrstr + firm.counters.toString() + ", " + firm.counters.maptoString(self.sortRelease) + "\n"
            fp.write(wrstr)

        fp.close()

    def createLibMatrix(self):

        fp = open(self.outputDir / CONFIGURATION.dict["LIB_MATRIX"], "w+")

        libs = {}
        for firm in self.firmwares.values():
            libs[firm.name] = firm.getLibBinaries()

        uniquelibs = {}
        for binaries in libs.values():
            for binary in binaries:
                uniquelibs[binary.hashcode] = binary

        fp.write(", , ")
        bitvector = {}
        uniquename = set()
        for binary in uniquelibs.values():
            namestr = binary.name + ":" + binary.version.VersionToString()
            uniquename.add(namestr)

        for namestr in sorted(uniquename):
            fp.write(namestr + ", ")
            bitvector[namestr] = "0"

        fp.write("\n")

        for firm in self.firmwares.values():
            binaries = libs[firm.name]
            lbitvector = copy.copy(bitvector)
            for binary in binaries:
                namestr = binary.name + ":" + binary.version.VersionToString()
                lbitvector[namestr] = "1"

            wrstr = firm.name + ", " + firm.releaseDate.strftime("%d/%m/%Y") + ", " \
                    + ", ".join(lbitvector.values()) + "\n"
            fp.write(wrstr)

        fp.close()

    def createCounterMatrix(self):

        fp = open(self.outputDir / CONFIGURATION.dict["COUNTERS_MATRIX_TOTAL"], "w+")

        fp.write(", , ")
        for name, obj in self.sortRelease.items():
            fp.write(name + ", ")

        fp.write("\n")
        lvector = {}
        rvector = []
        for firm in self.firmwares.values():
            wrstr = firm.name + ", " + firm.releaseDate.strftime("%d/%m/%Y") + ", " \
                    + firm.counters.mapTotalToString(firm.name, self.sortRelease) + "\n"
            fp.write(wrstr)

            # get vector
            lvector[firm.name] = wrstr.strip().split(",")[2:]
            # remove empty elements
            lvector[firm.name] = list(filter(lambda a: a != "", lvector[firm.name]))
            # convert every element to int
            lvector[firm.name] = [int(x) for x in lvector[firm.name]]

            rvector.append(firm.releaseDate)

        fp.close()

        # self.createCounterPlot(lvector, rvector, self.xaxis, self.yaxis, "all-")

        fp = open(self.outputDir / CONFIGURATION.dict["COUNTERS_MATRIX_CRYPTO"], "w+")

        fp.write(", , ")
        for name, obj in self.sortRelease.items():
            fp.write(name + ", ")

        fp.write("\n")

        lvector = {}
        for firm in self.firmwares.values():
            wrstr = firm.name + ", " + firm.releaseDate.strftime("%d/%m/%Y") + ", " \
                    + firm.counters.mapTotalCryptoToString(firm.name, self.sortRelease) + "\n"

            fp.write(wrstr)

            # get vector
            lvector[firm.name] = wrstr.strip().split(",")[2:]
            # remove empty elements
            lvector[firm.name] = list(filter(lambda a: a != "", lvector[firm.name]))
            # convert every element to int
            lvector[firm.name] = [int(x) for x in lvector[firm.name]]

        fp.close()


    def uniqueConstants(self):
        # for every firmware
        for firm in self.firmwares.values():
            firm.getUniqueConstants()

        for firm in self.firmwares.values():
            # print("Firmware Name= %s" % firm.name)
            # get previous bin
            for hashcode, binary in firm.alreadyBinaries.items():
                firmname = binary.firmwareName
                prevfirm = self.firmwares[firmname]
                if hashcode not in prevfirm.sinkKeys:
                    log.logWF("Hachcode error %s" % (firm.name))
                    continue
                firm.sinkKeys[hashcode] = prevfirm.sinkKeys[hashcode]
                firm.sinkIVs[hashcode] = prevfirm.sinkIVs[hashcode]
                firm.sinkInputs[hashcode] = prevfirm.sinkInputs[hashcode]

            totalSinkKeys = {}
            for hashcode, sinkKeys in firm.sinkKeys.items():
                for type, constant in sinkKeys.items():
                    # print("\t%s" % (type))
                    if type not in totalSinkKeys:
                        totalSinkKeys[type] = set()
                    for c in constant:
                        totalSinkKeys[type].add(c)
                        # print("\t\t%s" % (c))

            totalsinkIVs = {}
            for hashcode, sinkIVs in firm.sinkIVs.items():
                for type, constant in sinkIVs.items():
                    # print("\t%s" % (type))
                    if type not in totalsinkIVs:
                        totalsinkIVs[type] = set()
                    for c in constant:
                        totalsinkIVs[type].add(c)
                        # print("\t\t%s" % (c))

            totalsinkInputs = {}
            for hashcode, sinkInputs in firm.sinkInputs.items():
                for type, constant in sinkInputs.items():
                    # print("\t%s" % (type))
                    if type not in totalsinkInputs:
                        totalsinkInputs[type] = set()
                    for c in constant:
                        totalsinkInputs[type].add(c)
                        # print("\t\t%s" % (c))

            firm.totalSinkKeys = totalSinkKeys
            firm.totalsinkIVs = totalsinkIVs
            firm.totalsinkInputs = totalsinkInputs

            """
            print("TOTAL!!!")
            for type, constant in totalSinkKeys.items():
                print("\t%s" % (type))
                for c in constant:
                    print("\t\t%s" % (c))

            for type, constant in totalsinkIVs.items():
                print("\t%s" % (type))
                for c in constant:
                    print("\t\t%s" % (c))

            for type, constant in totalsinkInputs.items():
                print("\t%s" % (type))
                for c in constant:
                    print("\t\t%s" % (c))
            """

    def createGeneralMatrix(self):
        columnheader = set()
        for firm in self.firmwares.values():
            for key, value in firm.usedDict.items():
                if (value == True):
                    columnheader.add(key)

        scolumnheader = sorted(columnheader)

        fp = open(self.outputDir / CONFIGURATION.dict["MATRIX_USED_MISUSE"], "w+")
        fp.write(", , ")
        fp.write(", ".join(scolumnheader))
        fp.write("\n")

        for firm in self.firmwares.values():
            wrstr = firm.name + ", " + firm.releaseDate.strftime("%d/%m/%Y")
            for key in scolumnheader:
                wrstr = wrstr + ", " + str(firm.usedDict[key])

            fp.write(wrstr + "\n")

    def createConstantMisuseMatrix(self):

        self.uniqueConstants()

        columnheader = set()
        for firm in self.firmwares.values():
            for type, constant in firm.totalSinkKeys.items():
                columnheader.add(type)
            for type, constant in firm.totalsinkIVs.items():
                columnheader.add(type)
            for type, constant in firm.totalsinkInputs.items():
                columnheader.add(type)

        scolumnheader = sorted(columnheader)

        fp = open(self.outputDir / CONFIGURATION.dict["MATRIX_CONSTANT_MISUSE"], "w+")
        fp.write(", , ")
        fp.write(", ".join(scolumnheader))
        fp.write("\n")

        for firm in self.firmwares.values():
            wrstr = firm.name + ", " + firm.releaseDate.strftime("%d/%m/%Y") + ", " \
 \
            # get all unique constants
            for gtype in scolumnheader:
                if gtype in firm.totalSinkKeys:
                    for c in firm.totalSinkKeys[gtype]:
                        wrstr = wrstr + "'" + str(c) + "'; "
                if gtype in firm.totalsinkIVs:
                    for c in firm.totalsinkIVs[gtype]:
                        wrstr = wrstr + "'" + str(c) + "'; "
                if gtype in firm.totalsinkInputs:
                    for c in firm.totalsinkInputs[gtype]:
                        wrstr = wrstr + "'" + str(c) + "'; "

                wrstr = wrstr + ", "

            fp.write(wrstr + "\n")

        fp.close()

    def saveGlobalFile(self):

        fpall = open(self.outputDir / CONFIGURATION.dict["FILE_MATRIX_ALL"], "w+")
        fpcalled = open(self.outputDir / CONFIGURATION.dict["FILE_MATRIX_CALLED"], "w+")

        # print("")
        columnheader = set()
        # get header
        for firmwareName, uniqueSinks in self.guniqueSinks.items():
            for hash, dictsink in uniqueSinks.items():
                for rules in dictsink.values():
                    # add sink function
                    columnheader.add(rules.sinkFunc)
                    # add any underlying algorithms
                    for alg in rules.algorithm.keys():
                        if not str(alg).strip().startswith("NOT-FOUND:"):
                            columnheader.add(alg)

        scolumnheader = sorted(columnheader)

        # print(scolumnheader)

        fpall.write(" , ," + ", ".join(scolumnheader) + "\n")
        fpcalled.write(" , ," + ", ".join(scolumnheader) + "\n")

        # for every firmware
        for firmwareName, uniqueSinks in self.guniqueSinks.items():

            # print(firmwareName)

            wstr = firmwareName + ", " + self.firmwares[firmwareName].releaseDate.strftime("%d/%m/%Y") + ", "
            wstrCalled = firmwareName + ", " + self.firmwares[firmwareName].releaseDate.strftime("%d/%m/%Y") + ", "

            uniqueSink = {}
            uniqueSinkCalled = {}
            current_set = set()
            current_setCalled = set()
            for hash, dictsink in uniqueSinks.items():
                for rules in dictsink.values():
                    if (rules.isEntry):
                        self.updateCounters(rules, uniqueSinkCalled, current_setCalled)

                    self.updateCounters(rules, uniqueSink, current_set)

            for elem in columnheader.difference(current_set):
                uniqueSink[elem] = 0

            for elem in columnheader.difference(current_setCalled):
                uniqueSinkCalled[elem] = 0

            uniqueSink = OrderedDict(sorted(uniqueSink.items()))
            for key, value in uniqueSink.items():
                # print("%s : %d" % (key, value))
                wstr = wstr + str(value) + ", "

            uniqueSinkCalled = OrderedDict(sorted(uniqueSinkCalled.items()))
            for key, value in uniqueSinkCalled.items():
                wstrCalled = wstrCalled + str(value) + ", "

            # print("")

            fpall.write(wstr + "\n")
            fpcalled.write(wstrCalled + "\n")

        fpall.close()
        fpcalled.close()

    def updateCounters(self, rules, uniqueSink, currentSet):
        if (rules.sinkFunc not in uniqueSink):
            # initialisation
            uniqueSink[rules.sinkFunc] = 1
        else:
            uniqueSink[rules.sinkFunc] = uniqueSink[rules.sinkFunc] + 1

        # add any underlying algorithms
        for alg in rules.algorithm.keys():
            if not str(alg).strip().startswith("NOT-FOUND:"):
                if (alg not in uniqueSink):
                    # initialisation
                    uniqueSink[alg] = 1
                else:
                    uniqueSink[alg] = uniqueSink[alg] + 1

                currentSet.add(alg)

        currentSet.add(rules.sinkFunc)
