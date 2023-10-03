import copy
import json
import ntpath
import os
import queue
import random
import shutil
import subprocess
import threading
from datetime import datetime
from os import path
from pathlib import Path

from modules.Results import Results
from modules.Rule import Rule
from modules.Version import Version, getVersionID, getMnemonicToVersionID
from modules.analysis import Analysis
from modules.credentials import Credentials, ScriptCMDs, isSSHKey
from modules.helpfunctions import createDir, mexec, normcaseLinux, mexecQuiet, tryCopy, mexecGhidra
from modules.log import log
from modules.DEFINES import DEFINES, CONFIGURATION
from toposort import toposort, CircularDependencyError
from modules.yara import Yara

import re
import mimetypes

from postmodules.Firmware import Times


class Project:

    def __init__(self, options, originalInput, firmwareInput, projectOutDir, extractDir, analysisDir, firmwareName="",
                 releaseFile="",
                 isGlobal=False, numthreads=0, postRules=None, releaseDate=None, yaraobj=None, productLine=set()):

        self.originalInput = originalInput
        self.firmwareInput = firmwareInput
        self.projectOutDir = projectOutDir
        self.extractDir = extractDir
        self.analysisDir = analysisDir
        self.options = options

        self.postRules = postRules

        self.level = str(options.level)

        self.firmwareName = firmwareName
        self.releaseFile = releaseFile
        self.releaseDate = releaseDate
        # hold product line
        self.productLine = productLine

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

        # hold symbolic files
        self.symbolic = {}
        # hold set
        self.setofsymbolic = queue.Queue()

        self.numThreads = numthreads
        # hold all binaries
        self.allbinaries = {}

        self.resobj = Results()
        # hold the updated set if already analysed form global project
        self.alreadyAnalyse = set()

        # hold any credentials
        self.credentials = {}
        # hold any script relevant commands
        self.scriptcmds = {}

        # hold the cryptolibraries
        self.cryptolibs = CONFIGURATION.cryptolibs

        # unpack reasons
        self.unpackresults = set()

        # Global analysis object
        self.analysis = None
        # array of unique binary analysis
        self.qanalysis = queue.Queue()
        # times object
        self.times = Times()

        # hold other related files for signature detection
        self.otherbinaries = {}

        # read rules dict for exclude wrappers
        fp = open(path.abspath(CONFIGURATION.dict["RULES"]), 'r')
        self.setRuleNames = set()
        for line in fp.readlines():
            obj = Rule(line)
            if (obj.isRule):
                self.setRuleNames.add(obj.FunctionName)

        if (isGlobal == False):
            mimetypes.init()
            if self.saveExecutables():
                createDir(self.analysisDir / CONFIGURATION.dict["DIR_EXEC"])

            createDir(self.analysisDir / CONFIGURATION.dict["DIR_CVE"])

            self.yaraobj = yaraobj

        self.isGlobal = isGlobal
        if (isGlobal == True):
            # create yara object
            self.yaraobj = Yara(self.isVerbose())
            # global store [firmwareName] = analysis.uniqueSinks
            self.guniqueSinks = {}
            # global store [firmwareName] = analysis.misuseRules
            self.gmisuseRules = {}
            # global store [firmwareName] = analysis.entries
            self.gentries = {}
            # hold all wrappers
            self.libwrappers = {}
            # hold all name mapping
            # dict [hash] = analysis.namewrappers
            self.namewrappers = {}
            # global store [hash]
            self.hmisuseRules = {}
            self.huniqueSinks = {}
            # global store projects
            self.firmwares = {}

            self.sortRelease = {}

            # originalDir
            self.name = originalInput.name
            self.vendorName = originalInput.parent.name
            self.typeName = originalInput.parent.parent.name

        else:
            self.fpbinaries = open(self.analysisDir / CONFIGURATION.dict["FILE_BINARIES"], "w+")
            self.fpversions = open(self.analysisDir / CONFIGURATION.dict["FILE_LIBRARIES"], "w+")

            # header
            self.fpbinaries.write("Name, Type, FileType, Arch, Bit Processor, Endianness, Crypto Libraries, Libraries,"
                                  " Firmware Name, Location, SHA256 Hash\n")
            self.fpversions.write("Library Type, GNU Version Definition, Version, Name, Type, FileType, Arch, "
                                  "Bit Processor, Endianness, Crypto Libraries, Libraries,"
                                  " Firmware Name, Location, SHA256 Hash\n")

    def __del__(self):
        if (self.isGlobal == False):
            self.fpbinaries.close()
            self.fpversions.close()

    def setProductLine(self, sortRelease):
        self.sortRelease = sortRelease

    def getProductLine(self, firmwareName):

        productLine = set()
        productLine.add(self.name)
        if firmwareName not in self.sortRelease:
            return productLine

        try:
            for item in self.sortRelease[firmwareName][1][1]:
                productLine.add(item)
        except:
            pass

        # TODO replace change firmwareName (spaces to dash) with original firmware name problem with pid, fids database

        return productLine

    def saveCredentials(self):

        # save openssl cmds to file
        if (len(self.scriptcmds) != 0):
            fpcmd = open(
                self.analysisDir / CONFIGURATION.dict["DIR_OTHERS"] / CONFIGURATION.dict["FILE_BASH_SCRIPT_CMDS"], "w+")

            for objcmd in self.scriptcmds.values():
                fpcmd.write(objcmd.toString())

            fpcmd.close()

        if (path.exists(self.analysisDir / CONFIGURATION.dict["DIR_CREDENTIALS"]) == False):
            return

        fp = open(
            self.analysisDir / CONFIGURATION.dict["DIR_CREDENTIALS"] / CONFIGURATION.dict["FILE_CREDENTIALS"], "w+")

        for objcred in self.credentials.values():
            fp.write(objcred.toString())

        fp.close()

    def addBinaryWithFilter(self, objBinary):

        if (objBinary.typeNum == DEFINES.UNKNOWN):
            self.checkOtherTypes(objBinary)
            return

        if (objBinary.typeNum == DEFINES.INODE):
            return

        # if it is a inode/symbolink link
        # possibly a link that points to a library with a different name
        if (objBinary.typeNum == DEFINES.SYMBOLIC_LINK):
            if self.isVerbose():
                log.logF("symbolic link added %s " % (objBinary.location))
            self.setofsymbolic.put(objBinary)
            self.setofsymbolic.task_done()
            return

        # not unknown and not a symbolic link
        self.allbinaries[objBinary.hashcode] = objBinary

    # CVE checker
    # hardening-checker
    # libraries checker
    def updateInfoparallel(self):

        # buckets depends on number of threads available
        buckets = {}
        i = 0
        for hashcode, binary in self.allbinaries.items():
            id = i % self.numThreads

            if id not in buckets:
                buckets[id] = []
            buckets[id].append(hashcode)
            i = i + 1

        threads = []
        for key, bucket in buckets.items():
            t = threading.Thread(target=self.updateInfobucket, args=(bucket,))
            threads.append(t)
            t.start()

        # wait until all threads are finished
        for t in threads:
            t.join()

    def updateInfobucket(self, bucket):
        for hashcode in bucket:
            # get CVE
            self.updateCVE(self.allbinaries[hashcode])
            # hardening-check
            self.security_hardening(self.allbinaries[hashcode])
            # CWE checker --cwe-checker only in crypto related files
            self.updateCWE(self.allbinaries[hashcode])
            # get library version only if it is a library object
            self.updateLibraries(self.allbinaries[hashcode])
            # yara constant crypto search
            self.yaraConstantCryptoSearch(self.allbinaries[hashcode])
            # parse for yara credentials signatures detection
            # return true if found any
            if self.yaraobj.findCredentialSearch(self.allbinaries[hashcode]):
                # return [binary, mimetype (as found by yara search)
                retarr = self.yaraobj.extractCredentialSearch(self.allbinaries[hashcode])
                self.copyCredentials(retarr[0], retarr[1], "")

            # add FACT software os signature
            self.updateLibrariesSignatures(self.allbinaries[hashcode])

    def updateLibrariesSignatures(self, binary):

        arrversions = self.yaraobj.findSoftwareSearch(binary)

        if len(arrversions) == 0:
            return False

        pattern = re.compile(r'\d+.\d+(.\d+)?(\w)?')

        libname = None
        version = None
        for s in arrversions:
            arr = s.split()

            if len(arr) <= 1:
                continue

            if arr[1] == binary.location:
                libname = arr[0].strip().lower()
                continue

            input_str = " ".join(arr[1:])
            ispattern = pattern.search(input_str)
            if ispattern is not None:
                version = str(ispattern.group(0))

        return self.addsigLibrary(binary, libname, version)

    # create library version object from signature
    def addsigLibrary(self, binary, libname, version):
        if libname is None or version is None:
            # discard signature version
            return False

        if not binary.isBinary():
            binary.updateHashCode()

        binary.addVersionOfLibrary(Version(getMnemonicToVersionID(libname), date=None, version=version,
                                           version_name=libname, where=Version.SIGNATURES))
        self.forceCVEGeneral(binary)

        return True

    def forceCVEGeneral(self, binary):

        # get last added element
        vobj = binary.version[-1]
        vendor = product = vobj.version_name

        # CPE
        # TODO: (FUTURE) add more CPEs
        if vendor == "linuxkernel":
            vendor = "linux"
            product = "linux_kernel"

        # tmp file
        csv_file = self.analysisDir / CONFIGURATION.dict["DIR_CVE"] / str(
            "tmp" + "-" + binary.hashcode + "-other.csv")

        fp = open(csv_file, "w+")
        fp.write("vendor,product,version\n")
        fp.write("%s,%s,%s\n" % (vendor, product, vobj.VersionToString()))
        fp.close()

        outfile = self.analysisDir / CONFIGURATION.dict["DIR_CVE"] / str(
            "out" + "-" + binary.hashcode + str(random.randint(0, 1000)) + ".json")
        mexecQuiet(
            [CONFIGURATION.dict["CSV2CVE"], "-o",  str(outfile), "-u", "never", "-f", "json", str(csv_file)])

        csv_file.unlink(missing_ok=True)

        if outfile.exists():
            with open(outfile, 'r') as file:
                getjson = file.read()
                if getjson != "":
                    try:
                        cvejson = json.loads(getjson)

                        dcve = {}
                        for item in cvejson:
                            if binary.cve is not None:
                                if item['cve_number'] in binary.cve:
                                    continue
                            item["foundWith"] = Version.SIGNATURES
                            dcve[item['cve_number']] = item

                        if binary.cve is None:
                            binary.cve = copy.deepcopy(dcve)
                        else:
                            binary.cve.update(copy.deepcopy(dcve))

                        # try to resolve the publish date
                        resolveCVEextra(binary)

                    except ValueError as e:
                        log.logWF(
                            "Something went wrong during CVE2CVE checker of json: %s" % e)

            outfile.unlink(missing_ok=True)

    # TODO future need manual review
    def updateCWE(self, binary):

        # run with docker
        # docker run --rm -v /home/elite/Desktop/mm/libgcc_s.so.1:/tmp/libgcc_s.so.1 fkiecad/cwe_checker bap /tmp/libgcc_s.so.1 --pass=cwe-checker --cwe-checker-json --cwe-checker-no-logging

        if not self.isCWEchecker():
            return

        if binary.cwe is not None:
            return

        if not binary.isCrypt:
            return

        strout = mexec([CONFIGURATION.dict["CWE_CHECKER"], "-json", "-no-logging", "-check-path", binary.location],
                       self.isVerbose())

        if not isinstance(strout, str):
            return

        try:
            binary.cwe = json.loads(strout)
        except ValueError as e:
            log.logW("Something went wrong during CWE checker of " + binary.name + "," + self.firmwareName + str(e))
            log.logWF("Something went wrong CWE checker of " + binary.name + "," + self.firmwareName + str(e))
            return

    def yaraConstantCryptoSearch(self, binary):
        # search with Yara for crypto constants
        binary.crypto_constants = self.yaraobj.findCryptoConstants(binary.location)

    def security_hardening(self, binary):
        self.hardening_check(binary)
        self.readelf_check(binary)

    def hardening_check(self, binary):
        # hardening check on different architectures cannot use objdump
        # added timeout to capture endless loop
        # give timeout proportionally to filesize
        sizebytes = Path(binary.location).stat().st_size
        timeoutsec = int(min(Analysis.MIN_TIMEOUT + sizebytes / 100, Analysis.MAX_TIMEOUT))
        LIMIT_PLUS = 20
        out = subprocess.run(['timeout', '-k', str(1), str(timeoutsec + LIMIT_PLUS), CONFIGURATION.dict["HARDENINGCHECK"],
                              binary.location], capture_output=True)
        strout = str(out.stdout, 'utf-8')
        if not isinstance(strout, str):
            log.logWF("hardening_check for binary % failed " % binary.name)
            return

        hard_dict = {}
        for line in strout.splitlines():
            if line.startswith(binary.location):
                continue

            if line == "\n":
                continue

            arr = line.split(":")
            if len(arr) < 2:
                continue

            hard_dict[arr[0].strip()] = arr[1].strip()

        binary.security_hard.update(hard_dict)

        if len(hard_dict) != 7:
            log.logWF("hardening_check for binary %s failed" % binary.name)
            return

    def readelf_check(self, binary):
        # base on FACT, https://github.com/fkie-cad/FACT_core, checksec.py
        args = [CONFIGURATION.dict["READELF"], '-W', '-l', '-d', '--dyn-syms', '-h', binary.location]
        out = subprocess.run(args, capture_output=True)
        elfout = str(out.stdout, 'utf-8')
        if not isinstance(elfout, str):
            return

        hard_dict = {}
        # add NX enable/disable
        nx_off = re.search(r'GNU_STACK[\s0-9a-z]*RWE', elfout)
        if nx_off is None:
            mitigation_off = False
        else:
            mitigation_off = True

        hard_dict.update({'NX off': mitigation_off})
        # add PIE/DSO present
        pie_dso = False
        if re.search(r'Type:\s*DYN', elfout):
            if not re.search(r'\(DEBUG\)', elfout):
                pie_dso = True

        hard_dict.update({'PIE/DSO': pie_dso})

        binary.security_hard.update(hard_dict)

    def updateLibraries(self, binary):
        self.checkVersion(binary)

        if binary.isCryptVersion():
            # strings to debug
            self.stringsToVersion(binary, 0, tobinary=True)


    def updateBinariesStructure(self):

        for objBinary in self.setofsymbolic.queue:
            if objBinary is not None:
                if objBinary.name not in self.symbolic:
                    self.symbolic[objBinary.name] = set()

                self.symbolic[objBinary.name].add(objBinary)

        for objBinary in self.allbinaries.values():
            # If it is a library
            if (objBinary.typeNum == DEFINES.LIBRARY):
                if (objBinary.isCrypt == True):
                    self.crypto_libraries[objBinary.hashcode] = objBinary
                else:
                    self.non_libraries[objBinary.hashcode] = objBinary

                if objBinary.name not in self.allLibraries:
                    self.allLibraries[objBinary.name] = set()

                self.allLibraries[objBinary.name].add(objBinary.hashcode)

                if self.isVerbose():
                    log.logF("library added %s " % (objBinary.location))

            # else if the binary is executable and defined successfully then is a file
            # with crypto library!!! -> worth analysing it
            elif (objBinary.typeNum == DEFINES.EXECUTABLE):
                if (objBinary.isCrypt == True):
                    self.crypto_binaries[objBinary.hashcode] = objBinary
                else:
                    self.non_binaries[objBinary.hashcode] = objBinary
                if self.isVerbose():
                    log.logF("executable added %s " % (objBinary.location))

            if objBinary.isCrypt:
                # copy executable if option is specify
                if (self.saveExecutables()):
                    self.copyExecutable(objBinary)

    # cve checker
    # Run cve-bin-tool
    # https://github.com/intel/cve-bin-tool
    def updateCVE(self, objBinary):
        # tmp file
        tmp_file = self.analysisDir / CONFIGURATION.dict["DIR_CVE"] / str(
            "tmp" + "-" + objBinary.hashcode + ".json")
        mexecQuiet([CONFIGURATION.dict["CVECHECKER"], "-u", "never", "-f", "json", "-o", str(tmp_file),
                    str(objBinary.location)])

        if tmp_file.exists():
            with open(tmp_file, 'r') as file:
                getjson = file.read()
                if getjson != "":
                    try:
                        cvejson = json.loads(getjson)

                        dcve = {}
                        for item in cvejson:
                            item["foundWith"] = Version.CVE
                            dcve[item['cve_number']] = item

                        if objBinary.cve is None:
                            objBinary.cve = copy.deepcopy(dcve)
                        else:
                            objBinary.cve.update(copy.deepcopy(dcve))

                        # try to resolve the publish date
                        resolveCVEextra(objBinary)

                    except ValueError as e:
                        log.logWF(
                            "Something went wrong during CVE checker of json")

            tmp_file.unlink(missing_ok=True)

    # link the symbolic links to actual libraries if any
    def SymbolicLinksToLibs(self):

        for name, setBinary in self.symbolic.items():
            for objBinary in setBinary:
                findthis = ntpath.basename(objBinary.symbolic_loc)

                if (findthis in self.allLibraries):
                    hashcodes = self.allLibraries[findthis]

                    if name not in self.allLibraries:
                        self.allLibraries[name] = set()

                    # for every binary
                    for hashcode in hashcodes:
                        binary = self.allbinaries[hashcode]
                        # add symbolic name!
                        binary.setofSymbolicNames.add(name)

                        self.allLibraries[name].add(hashcode)

        # del self.symbolic

    # find the order of analysis of libraries
    def produceOrder(self, bundleoflibs):
        # for circular dependencies
        nodeset = set()
        # produce the topological graph
        graphtopo = {}
        for name, binary in bundleoflibs.items():
            setb = set()
            for lib in binary.libraries:
                if (lib in self.allLibraries):
                    sethashbin = self.allLibraries[lib]
                    for hashcode in sethashbin:
                        setb.add(hashcode)

            graphtopo[binary.hashcode] = setb
        # topological sort
        topom = []
        try:
            topom = list(toposort(graphtopo))
        except CircularDependencyError as e:
            # find all circular nodes
            x = e.data
            for key, value in x.items():
                for e in value:
                    for v in x[e]:
                        if v == key:
                            nodeset.add(key)
            # remove all circular nodes
            for key in nodeset:
                graphtopo.pop(key)

            # produce now the topological sort
            topom = list(toposort(graphtopo))

        orderbundle = {}
        id = 0
        for dset in topom:

            if id not in orderbundle:
                orderbundle[id] = []

            for hashcode in dset:
                if hashcode in bundleoflibs:
                    binary = bundleoflibs[hashcode]
                    orderbundle[id].append(binary)

            id = id + 1

        # put circular node to a single thread 0 best we can do
        id = 0
        for hashcode in nodeset:

            if id not in orderbundle:
                orderbundle[id] = []

            if hashcode in bundleoflibs:
                binary = bundleoflibs[hashcode]
                orderbundle[id].append(binary)

        # return the buckets
        return orderbundle

    def applyFilterAfterSymbolicLinks(self):

        addset = set()
        for name, setofhashes in self.allLibraries.items():

            if (name.split(".")[0] in self.cryptolibs) or (
                    name.split("-")[0] in self.cryptolibs) or \
                    (name in self.cryptolibs):
                # get all symbolic references
                addset.add(name)
                for hashcode in setofhashes:
                    binary = self.allbinaries[hashcode]
                    for e in binary.setofSymbolicNames:
                        addset.add(e)
                        binary.isCrypt = True

        # update self.cryptolibs
        for lib in addset:
            self.cryptolibs.add(lib)

        self.applyFilter(self.cryptolibs, DEFINES.YARAORVERSION)

    def applyFilter(self, setofCryptoLibs, INFO):
        if (len(setofCryptoLibs) == 0):
            return

        delset = set()
        for binary in self.non_libraries.values():
            if (binary.name in setofCryptoLibs):
                continue
            if (binary.libraries.isdisjoint(setofCryptoLibs) == False):
                # get the intersection and add it to cryptov
                cryptoset = binary.libraries.intersection(setofCryptoLibs)
                for name in cryptoset:
                    binary.vcrypto[name] = INFO
                    binary.isCrypt = True

                self.crypto_libraries[binary.hashcode] = binary
                if (self.saveExecutables()):
                    self.copyExecutable(binary)
                delset.add(binary.hashcode)

        for key in delset:
            del self.non_libraries[key]

        delset = set()
        for binary in self.non_binaries.values():
            # isdisjoint(other)
            # Return True if the set has no elements in common with other.
            # Sets are disjoint if and only if their intersection is the empty set.
            if (binary.libraries.isdisjoint(setofCryptoLibs) == False):
                # get the intersection and add it to cryptov
                cryptoset = binary.libraries.intersection(setofCryptoLibs)
                for name in cryptoset:
                    binary.vcrypto[name] = INFO
                    binary.isCrypt = True

                # possibly executable that uses a wrapper crypto lib
                # add it
                self.crypto_binaries[binary.hashcode] = binary
                if (self.saveExecutables()):
                    self.copyExecutable(binary)
                delset.add(binary.hashcode)

        for key in delset:
            del self.non_binaries[key]

    def updateStructure(self, proj):
        analysis = proj.analysis
        if (self.isVerbose()):
            log.logF("Update global structure")

        self.allbinaries.update(proj.allbinaries)
        self.allLibraries.update(proj.allLibraries)
        self.non_libraries.update(proj.non_libraries)
        self.crypto_libraries.update(proj.crypto_libraries)
        self.non_binaries.update(proj.non_binaries)
        self.crypto_binaries.update(proj.crypto_binaries)
        self.libwrappers.update(analysis.libwrappers)
        self.namewrappers.update(analysis.namewrappers)
        self.hmisuseRules.update(analysis.misuseRules)
        self.huniqueSinks.update(analysis.uniqueSinks)

        # store project structure
        self.firmwares[proj.firmwareName] = proj

    def checkBinary(self, binary):
        if binary.isBinary():
            binary.updateHashCode()
            # check hash code
            if binary.hashcode in self.allbinaries:
                return True

        return False

    def setSameBinary(self, hash):
        self.alreadyAnalyse.add(hash)

    # update local libraries from already analysed global libraries
    # if hash is match
    def updateLocalAllLibraries(self, GlobalProject):
        # alreadyAnalyse holds hashes for libraries, pies, executables
        for hash in self.alreadyAnalyse:
            objBinary = GlobalProject.allbinaries[hash]

            # update all binaries only for mapping
            self.allbinaries[objBinary.hashcode] = objBinary

            # If it is a library
            if (objBinary.typeNum == DEFINES.LIBRARY):
                # not unknown and not a symbolic link
                if objBinary.name not in self.allLibraries:
                    self.allLibraries[objBinary.name] = set()

                self.allLibraries[objBinary.name].add(objBinary.hashcode)

                if self.isVerbose():
                    log.logF("Function - updateLocalLibraries() : library added %s" % (objBinary.location))

    # except alllibraries
    def updateLocalBinaries(self, GlobalProject):

        for hash in self.alreadyAnalyse:
            objBinary = GlobalProject.allbinaries[hash]
            # not unknown and not a symbolic link
            self.allbinaries[objBinary.hashcode] = objBinary

            # If it is a library
            if (objBinary.typeNum == DEFINES.LIBRARY):
                if (objBinary.isCrypt == True):
                    self.crypto_libraries[objBinary.hashcode] = objBinary
                else:
                    self.non_libraries[objBinary.hashcode] = objBinary

                if self.isVerbose():
                    log.logF("Function - updateBinaries() : library added %s " % (objBinary.location))


            # else if the binary is executable and defined successfully then is a file
            # with crypto library!!! -> worth analysing it
            elif (objBinary.typeNum == DEFINES.EXECUTABLE):
                if (objBinary.isCrypt == True):
                    self.crypto_binaries[objBinary.hashcode] = objBinary
                else:
                    self.non_binaries[objBinary.hashcode] = objBinary
                if self.isVerbose():
                    log.logF("executable added %s " % (objBinary.location))

        # save local file.csv
        # after updating all the binaries
        self.saveLocalBinaryFile()
        # save local CVE checker file
        self.saveLocalCVEFile()

    def isCWEchecker(self):
        return self.options.cwe_checker

    def isDebugPrintAll(self):
        return self.options.print_all

    def isVerbose(self):
        return self.options.verbose

    def isDebug(self):
        return self.options.debug

    def applyExclude(self):
        return self.options.exclude

    def saveAST(self):
        return self.options.save_ast

    def saveExecutables(self):
        return self.options.save_exec

    def saveCallGraphs(self):
        return self.options.save_callgraph

    def saveGhidraProjects(self):
        return self.options.save_ghidra

    def saveAnalysisResults(self):
        return self.options.save_analysis

    # check version from libraries
    # also update local project from already analysed in global project
    def updateVersion(self, GlobalProject):

        # search all libraries to be independent of the name
        for binary in self.non_libraries.values():
            if len(binary.version) != 0:
                if binary.isCryptVersion():
                    self.cryptolibs.add(binary.name)
                    if (binary.soname != ""):
                        self.cryptolibs.add(binary.soname)
                    binary.isCrypt = True

        for binary in self.crypto_libraries.values():
            if len(binary.version) != 0:
                if binary.isCryptVersion():
                    self.cryptolibs.add(binary.name)
                    if (binary.soname != ""):
                        self.cryptolibs.add(binary.soname)

        # global search
        for hash in self.alreadyAnalyse:
            objBinary = GlobalProject.allbinaries[hash]
            # If it is a library
            if objBinary.typeNum == DEFINES.LIBRARY:
                # if version is found
                if len(objBinary.version) != 0:
                    # check if it is a cryptographic library
                    if objBinary.isCryptVersion():
                        # add to current project filter
                        self.cryptolibs.add(objBinary.name)
                        # also add the soname
                        if (objBinary.soname != ""):
                            self.cryptolibs.add(objBinary.soname)
                        objBinary.isCrypt = True

    def checkVersion(self, binary):
        # first phase
        # CVE found version add to binary
        self.checkCVEtoversion(binary)
        if not binary.isLib():
            return

        if binary.isCryptVersion():
            return
        # second phase only for libraries
        # from name add to version
        retid = self.nameToVersion(binary)
        # readelf -v
        retid = self.readelfToVersion(binary, retid)
        # force strings command
        retid = self.stringsToVersion(binary, retid)
        # ghidra to find real version
        retid = self.ghidraToVersion(binary, retid)
        # force CVE to the found version
        self.forceCVECrypto(binary, retid)

    def readelfToVersion(self, binary, retid):

        if retid != Version.UNKNOWN:
            return retid
        # try with GNU readelf version info
        strout = mexec([CONFIGURATION.dict["READELF"], "--version-info", binary.location])
        if not isinstance(strout, str):
            return Version.UNKNOWN

        found_version = False
        version = False
        version_defined = False
        version_req = False
        currentobj = None
        for line in strout.splitlines():
            if line.find("'.gnu.version'") >= 0:
                version = True
                version_defined = False
                version_req = False
                continue
            elif line.find("'.gnu.version_d'") >= 0:
                currentobj = None
                version_defined = True
                version = False
                version_req = False
                continue
            elif line.find("'.gnu.version_r'") >= 0:
                version_req = True
                version = False
                version_defined = False
                continue

            if version_defined:
                arr = line.split()
                if len(arr) != 0:
                    if "Name:" in arr:
                        if ("BASE" not in arr):
                            if currentobj != None:
                                currentobj.addVersionName(arr[-1])
                        else:
                            # update type based on name
                            getname = arr[-1]
                            pos = getname.find(".")
                            version_id = Version.UNKNOWN
                            if (pos >= 0):
                                realname = getname[:pos]
                                version_id = getVersionID(realname)

                            if version_id != Version.UNKNOWN:
                                return version_id

        return Version.UNKNOWN

    def stringsToVersion(self, binary, retid, tobinary=False):
        if not tobinary:
            if retid != Version.UNKNOWN:
                return retid

        # check with strings
        strout = mexec([CONFIGURATION.dict["STRINGSCMD"], binary.location])

        if tobinary:
            binary.strings = strout
            return

        for line in strout.splitlines():

            # get the OpenSSL version!
            if (re.match("OpenSSL \d.\d.\d", line)):
                return Version.OpenSSL

        return Version.UNKNOWN

    def nameToVersion(self, binary):

        # update type based on name
        version_id = Version.UNKNOWN
        getname = binary.soname
        pos = getname.find(".")
        if (pos >= 0):
            realname = str(getname[:pos])
            version_id = getVersionID(realname)
        else:
            getname = binary.name
            pos = getname.find(".")
            if (pos >= 0):
                realname = str(getname[:pos])
                version_id = getVersionID(realname)

            # try -
            if version_id == Version.UNKNOWN:
                getname = binary.soname
                pos = getname.find("-")
                if (pos >= 0):
                    realname = str(getname[:pos])
                    version_id = getVersionID(realname)
                else:
                    getname = binary.name
                    pos = getname.find("-")
                    if (pos >= 0):
                        realname = str(getname[:pos])
                        version_id = getVersionID(realname)

        return version_id

    def ghidraToVersion(self, binary, retid, processor=""):

        # if not found a crypto library return
        if retid == Version.UNKNOWN:
            return retid

        # implemented so far
        # add more in the future
        validfinders = [Version.OpenSSL, Version.WolfSSL, Version.LIBGCRYPT, Version.GnuTLS,
                        Version.mbedTLS, Version.Libmcrypt, Version.Nettle, Version.Libsodium]
        if retid not in validfinders:
            # add version object
            vobj = Version(retid, None, "", where=Version.UNKNOWN)
            binary.addVersionOfLibrary(vobj)
            return Version.UNKNOWN

        strLib = ""
        if binary.isLib():
            strLib = "isLib"

        # use GHIDRA import no analysis and delete after!
        # -deleteProject
        ANALYZEPROC = CONFIGURATION.dict["GHIDRADIR"] + "/support/" + CONFIGURATION.dict["GHIDRAANALYSE"]
        tmp_dir = Path("/tmp/" + binary.hashcode)
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)
        createDir(tmp_dir)

        # give timeout proportionally to filesize
        LIMIT_PLUS = 20
        sizebytes = Path(binary.location).stat().st_size
        timeoutsec = int(min(Analysis.MIN_TIMEOUT + sizebytes / 100, Analysis.MAX_TIMEOUT))
        if processor != "":
            strout = mexecGhidra([ANALYZEPROC, str(tmp_dir), binary.name, "-deleteProject",
                        "-import", normcaseLinux(binary.location),
                        "-analysisTimeoutPerFile", str(timeoutsec),
                        "-scriptPath", Analysis.GHIDRA_SCRIPTS,
                        "-processor", processor,
                        "-preScript", "setOptionsPre.java", strLib, "level", self.level,
                        "-postScript", "FindLibrariesVersion.java"], verbose=True, isGhidra=True, timeout=str(timeoutsec + LIMIT_PLUS))
        else:
            strout = mexecGhidra([ANALYZEPROC, str(tmp_dir), binary.name, "-deleteProject",
                        "-import", normcaseLinux(binary.location),
                        "-analysisTimeoutPerFile", str(timeoutsec),
                        "-scriptPath", Analysis.GHIDRA_SCRIPTS,
                        "-preScript", "setOptionsPre.java", strLib, "level", self.level,
                        "-postScript", "FindLibrariesVersion.java"],  verbose=True, isGhidra=True, timeout=str(timeoutsec + LIMIT_PLUS))

        if (isinstance(strout, str) == False):
            log.logWF(
                "Something went wrong during analysis of " + binary.name + "-"
                + self.firmwareName + ". Error in ghidraToVersion() please see the log files for more")
            log.logW(
                "Something went wrong during analysis of " + binary.name + "-"
                + self.firmwareName + ". Error in ghidraToVersion() please see the log files for more")
            return DEFINES.FAILED

        haserrors = False
        garch = ""
        getjson = ""
        for line in strout.splitlines():
            if line.startswith('WARN  Decompiling'):
                haserrors = True
            if line.startswith('INFO  REPORT: Import succeeded with language'):
                garch = line.split('"')[1].strip()
            if line.startswith("JSONLIBS;"):
                getjson = line[9:]
                break

        try:
            libversion = json.loads(getjson)
            # print(binary.name)
            # print(libversion)
            previd = retid
            retid = getVersionID(libversion['versionType'])
            # not found version of the library
            if retid == Version.UNKNOWN:
                # add version object
                vobj = Version(previd, None, "", where=Version.UNKNOWN)
                binary.addVersionOfLibrary(vobj)
                return Version.UNKNOWN

            version = ""
            arr = libversion['fres']

            # parse results from ghidra
            if retid == Version.OpenSSL or retid == Version.WolfSSL or retid == Version.LIBGCRYPT \
                    or retid == Version.Libmcrypt or retid == Version.GnuTLS or retid == Version.Libsodium:
                for dres in arr:
                    if dres['isStr'] == True:
                        for s in dres['str']:
                            if s == None:
                                continue
                            if retid == Version.OpenSSL:
                                if (re.match("OpenSSL \d.\d.\d", s)):
                                    version = s.split()[1].strip()
                                    break

                            if retid == Version.WolfSSL or retid == Version.LIBGCRYPT or retid == Version.Libmcrypt \
                                    or retid == Version.GnuTLS or retid == Version.Libsodium:
                                if (re.match("\d+.\d+.\d+", s)):
                                    version = s.strip()
                                    break
            elif retid == Version.mbedTLS:
                for dres in arr:
                    if dres['isStr'] == False:
                        hexstr = '{:08x}'.format(dres['value'])
                        barr = bytes.fromhex(hexstr)
                        version = str(barr[0]) + "." + str(barr[1]) + "." + str(barr[2])
                        break
            elif retid == Version.Nettle:
                major = ""
                minor = ""
                for dres in arr:
                    if dres['isStr'] == False:
                        if dres['isMajor'] == True:
                            major = str(dres['value'])
                        elif dres['isMinor'] == True:
                            minor = str(dres['value'])

                version = major + "." + minor

        except ValueError as e:
            log.logW(
                "Something went wrong during analysis of " + binary.name + "-"
                + self.firmwareName + ". Error in ghidraToVersion() please see the log files for more")
            log.logWF(
                "Something went wrong during analysis of " + binary.name + "-"
                + self.firmwareName + ". Error in ghidraToVersion() please see the log files for more")
            return Version.UNKNOWN

        if version == "":
            retid = previd
        # add version object
        vobj = Version(retid, None, version, where=Version.GHIDRA)
        binary.addVersionOfLibrary(vobj)

        # recursive call if it is has errors and arch not equal and version not found
        if garch != "" and haserrors is True and processor == "" and version == "":
            arr = garch.split(':')
            barch = str(binary.arch)
            ischanged = False
            if barch.__contains__('PowerPC'):
                barch = "PowerPc"
                ischanged = True
            elif barch.__contains__('ARM'):
                barch = "ARM"
                if binary.getBitMnemonic() == "64":
                    barch = "AARCH64"
                ischanged = True
            elif barch.__contains__('MIPS'):
                barch = "MIPS"
                ischanged = True

            newarch = barch + ":" + binary.getEndiannessMnemonic() + ":" + binary.getBitMnemonic()
            garchcmp = arr[0] + ":" + arr[1] + ":" + arr[2]
            if newarch.lower() != garchcmp.lower() and ischanged:
                retid = self.ghidraToVersion(binary, retid, processor=newarch + ":default")

        return retid

    def checkCVEtoversion(self, binary):
        # check cve
        if binary.cve is not None:
            # find all different products and versions
            dproduct = {}
            for item in binary.cve.values():
                if item['product'] not in dproduct:
                    dproduct[item['product']] = set()

                dproduct[item['product']].add(item['version'])

            for product, s in dproduct.items():
                for version_number in s:
                    version_id = getVersionID(product)
                    vobj = Version(version_id, None, version_number, product, where=Version.CVE)
                    binary.addVersionOfLibrary(vobj)

    def forceCVECrypto(self, binary, retid):

        # if not found a crypto library return
        if retid == Version.UNKNOWN:
            return

        if len(binary.version) == 0:
            return

        # last added element
        version_string = binary.version[-1].VersionToString()

        # create CPE
        vendor = ""
        product = ""
        if retid == Version.OpenSSL:
            vendor = "openssl"
            product = "openssl"
        elif retid == Version.LIBGCRYPT:
            vendor = "gnupg"
            product = "libgcrypt"
        elif retid == Version.GnuTLS:
            vendor = "gnu"
            product = "gnutls"
        elif retid == Version.WolfSSL:
            vendor = "wolfssl"
            product = "wolfssl"
        elif retid == Version.mbedTLS:
            vendor = "mbed"
            product = "mbedtls"
        elif retid == Version.Libmcrypt:
            vendor = "mcrypt"
            product = "libmcrypt"
        elif retid == Version.Nettle:
            vendor = "nettle_project"
            product = "nettle"

        # tmp file
        csv_file = self.analysisDir / CONFIGURATION.dict["DIR_CVE"] / str(
            "tmp" + "-" + binary.hashcode + ".csv")

        fp = open(csv_file, "w+")
        fp.write("vendor,product,version\n")
        fp.write("%s,%s,%s\n" % (vendor, product, version_string))
        # extra info for database
        if retid == Version.mbedTLS:
            fp.write("%s,%s,%s\n" % ("polarssl", "polarssl", version_string))
            fp.write("%s,%s,%s\n" % ("arm", "mbed_tls", version_string))
            fp.write("%s,%s,%s\n" % ("arm", "mbed_crypto", version_string))

        fp.close()

        outfile = self.analysisDir / CONFIGURATION.dict["DIR_CVE"] / str(
            "out" + "-" + binary.hashcode + ".json")
        mexecQuiet(
            [CONFIGURATION.dict["CSV2CVE"], "-o", str(outfile), "-u", "never", "-f", "json", str(csv_file)])

        csv_file.unlink(missing_ok=True)

        if outfile.exists():
            with open(outfile, 'r') as file:
                getjson = file.read()
                if getjson != "":
                    try:
                        cvejson = json.loads(getjson)
                        dcve = {}
                        for item in cvejson:
                            item["foundWith"] = Version.GHIDRA
                            dcve[item['cve_number']] = item

                        if binary.cve is None:
                            binary.cve = copy.deepcopy(dcve)
                        else:
                            binary.cve.update(copy.deepcopy(dcve))

                        # try to resolve the publish date
                        resolveCVEextra(binary)

                    except ValueError as e:
                        log.logWF(
                            "Something went wrong during CVE2CVE checker of json: %s" % e)

            outfile.unlink(missing_ok=True)

    def checkOtherTypes(self, binary):

        excludeMimeList = ["application/pdf", "application/msword", "application/xtar", "application/zip",
                           "application/vnd.rar", "application/x-7z-compressed"]

        mime = mimetypes.guess_type(binary.location)
        filename, file_extension = os.path.splitext(binary.location)

        if mime[0] in excludeMimeList:
            return

        # check for openssl commands in scripts
        if mime[0] == "text/x-shellscript" or mime[0] == "text/x-sh" or file_extension == ".sh":
            obj = ScriptCMDs(binary)
            # save script to future
            self.copyOthers(binary)
            if not obj.isNone:
                binary.updateHashCode()
                self.scriptcmds[binary.hashcode] = obj

        if isSSHKey(binary.location) > 0:
            # if return true then found and exit function
            if self.copyCredentials(binary, mime[0], file_extension):
                return

        if mime[0] in Credentials.MIMETYPES:
            if self.copyCredentials(binary, mime[0], file_extension):
                return

        strtype = mexec([CONFIGURATION.dict["FILECMD"], "--brief", str(binary.location)], False)
        if not isinstance(strtype, str):
            log.logW("Something went wrong in checkOtherTypes()")
            strtype = ""

        # ssh, openssh, dropbear credentials not extension but file command can discover it
        ssh_discover_keys = ["PEM", "DSA", "private", "public", "OpenSSH", "RSA", "certificate", "PGP"]
        for ext in ssh_discover_keys:
            if re.search(ext, strtype, re.IGNORECASE):
                if self.copyCredentials(binary, strtype, file_extension):
                    return

        # parse for extension
        if file_extension in Credentials.EXTENSIONS:
            if self.copyCredentials(binary, strtype, file_extension):
                return

        # parse for yara signatures detection
        if self.yaraobj.findCredentialSearch(binary):
            # return [binary, mimetype (as found by yara search)
            retarr = self.yaraobj.extractCredentialSearch(binary)
            if self.copyCredentials(retarr[0], retarr[1], file_extension):
                return

        # if return true it means that a signature is found on a file that is not binary
        # possibly an OS like linux kernel?
        if self.updateLibrariesSignatures(binary):
            self.otherbinaries[binary.hashcode] = binary
            # print(binary.name, binary.location)
            # print(binary.version.toString())

        # other future files
        othersEXT = [".conf", ".cfg", ".config", ".cnf", ".lua"]
        otherNames = ["passwd", "shadow", "id_rsa", "known_hosts", "passwd.basic", "shadow.basic", "users", "eap",
                      "server", "chilli", "sql", "hostapd", "websys", "image_sign", "zebra"]

        filename = Path(filename).name
        # file command not mime gives us other types as well
        if file_extension in othersEXT or filename in otherNames:
            self.copyOthers(binary)
            return

        contains = False
        # also if contain any of them
        for n in othersEXT:
            if filename.__contains__(n):
                contains = True

        for n in otherNames:
            if filename.__contains__(n):
                contains = True

        if contains:
            self.copyOthers(binary)
            return

    def copyOthers(self, binary):
        rel = os.path.dirname(os.path.relpath(binary.location, self.extractDir))
        copylocation = self.analysisDir / CONFIGURATION.dict["DIR_OTHERS"] / rel
        createDir(copylocation)
        tryCopy(binary.location, copylocation)

    def copyCredentials(self, binary, mimetype, filextension):
        rel = os.path.dirname(os.path.relpath(binary.location, self.extractDir))
        if self.isVerbose():
            log.logF("Credentials: " + binary.location)
        copylocation = self.analysisDir / CONFIGURATION.dict["DIR_CREDENTIALS"] / rel

        createDir(copylocation)
        tryCopy(binary.location, copylocation)

        if not binary.isBinary():
            binary.updateHashCode()

        self.credentials[binary.hashcode] = Credentials(binary, copylocation, mimetype, filextension, self.extractDir,
                                                        self.analysisDir, self.isVerbose())

        return not self.credentials[binary.hashcode].isEmpty()

    def copyExecutable(self, binary):
        rel = os.path.dirname(os.path.relpath(binary.location, self.extractDir))
        copylocation = self.analysisDir / CONFIGURATION.dict["DIR_EXEC"] / rel

        if (path.exists(copylocation) == False):
            os.makedirs(copylocation)

        tryCopy(binary.location, copylocation)

    # update rules if a library is already analysed before
    # update rules.conf the previous wrappers
    # update self crypto wrappers
    # update self crypto wrappers name
    def updateLocalAnalyses(self, GlobalProject):
        analysis = self.analysis
        # update rules
        fp = open(analysis.NEWRULES, "a+")
        for hash, arrstr in GlobalProject.libwrappers.items():
            if hash in self.alreadyAnalyse:
                for wstr in arrstr:
                    fp.write(wstr)

                objBinary = GlobalProject.allbinaries[hash]
                # set crypto wrappers
                analysis.setofCryptoWrapper.add(objBinary.name)
                # set namewrappers
                analysis.namewrappers[hash] = GlobalProject.namewrappers[hash]
        fp.close()

        # update analysis files
        for hash in self.alreadyAnalyse:
            objBinary = GlobalProject.allbinaries[hash]

            if (hash in GlobalProject.huniqueSinks):
                # update analysis file
                analysis.fpanalysis.write("\n" + objBinary.toString() + "\n")
                analysis.fpanalysis.write("SAME, %s\n" % (objBinary.firmwareName))

            if (hash in GlobalProject.hmisuseRules):
                # update misuse file
                analysis.fpmisuse.write("\n" + objBinary.toString() + "\n")
                analysis.fpmisuse.write("SAME, %s\n" % (objBinary.firmwareName))

    # update local analysis structure from global
    # for already analyse binaries
    def updateSinkFunctions(self, proj):
        analysis = proj.analysis
        # update local structure
        for hash in proj.alreadyAnalyse:
            for prevuniqueSinks in self.guniqueSinks.values():
                if hash in prevuniqueSinks:
                    analysis.uniqueSinks[hash] = prevuniqueSinks[hash]
                    # only one previous from the others are the same
                    break

            for prevmisRules in self.gmisuseRules.values():
                if hash in prevmisRules:
                    analysis.misuseRules[hash] = prevmisRules[hash]
                    # only one previous from the others are the same
                    break

            for preventries in self.gentries.values():
                if hash in preventries:
                    analysis.entries[hash] = preventries[hash]
                    # only one previous from the others are the same
                    break

        # update global structure
        self.guniqueSinks[proj.firmwareName] = analysis.uniqueSinks
        self.gmisuseRules[proj.firmwareName] = analysis.misuseRules
        self.gentries[proj.firmwareName] = analysis.entries

    def saveLocalBinaryFile(self):

        for binary in self.allbinaries.values():
            # write in file
            self.fpbinaries.write(binary.toString() + "\n")

    def saveLocalCVEFile(self):

        createDir(self.analysisDir / CONFIGURATION.dict["DIR_CVE"])
        fp = open(self.analysisDir / CONFIGURATION.dict["DIR_CVE"] / CONFIGURATION.dict["FILE_CVE"], "w+")
        for binary in self.allbinaries.values():
            if binary.cve is not None:
                # write in file
                fp.write(binary.toString() + "\n")
                json.dump(binary.cve, fp, default=str)
                fp.write("\n")

        fp.close()


# resolve CVE publish date and score
def resolveCVEextra(binary):

    if binary.cve is None:
        return

    lcve = []
    for item in binary.cve.values():
        if item['cve_number'] == "UNKNOWN":
            continue
        # already resolve
        if 'publishdate' in item:
            continue

        lcve.append("-s")
        lcve.append(item["cve_number"])

    if len(lcve) == 0:
        return

    # try to resolve the publish date
    strout = mexec(["python3", CONFIGURATION.dict["CVESEARCH"]] + lcve)

    obj = json.loads(strout)
    for item in binary.cve.values():
        if item['cve_number'] == "UNKNOWN":
            continue
        if 'publishdate' in item:
            continue
        try:
            ld = obj[item["cve_number"]]
            item["publishdate"] = datetime.fromisoformat(ld["publishdate"])
            item["score"] = ld["score"]
            item["cvss_version"] = ld["cvss_version"]
        except:
            log.logEF("CVE NOT FOUND %s" % item["cve_number"])
            continue
