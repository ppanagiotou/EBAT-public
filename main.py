#!/usr/bin/env python3
import multiprocessing
import ntpath
import os
import threading
import time
from datetime import datetime
from pathlib import Path

from modules.log import log

import sys
import argparse
from distutils.dir_util import copy_tree

from modules.project import Project
from modules.binary import Binary
from modules.analysis import Analysis
from modules.helpfunctions import createDir, initPostRules, checkPostOptions, initConfig, checkDirectories, \
    getReleaseOrder, tryCopy, partitionBuckets, getbucketid, mexec
from modules.unpackFirmware import unpackFirmware
from modules.DEFINES import DEFINES, CONFIGURATION
from postmodules.productdb import ProductDB


def getOptions(args=None):
    if args is None:
        args = sys.argv[1:]
    parser = argparse.ArgumentParser(description="Parses command.")
    parser.add_argument("-i", "--input", help="Your input file.", dest='input', required=True)
    parser.add_argument("-o", "--output", help="Folder output.", dest='output', required=True)
    parser.add_argument("-c", "--config", help="Configuration file.", dest='config', required=True)
    parser.add_argument("--save-executables", help="Save files that are analysed into a different directory",
                        action="store_true", default=False, dest="save_exec")
    parser.add_argument("--save-ast", help="Save Abstract Syntax Trees for each binary",
                        action="store_true", default=False, dest="save_ast")
    parser.add_argument("--save-callgraph", help="Save Callgraphs for each binary",
                        action="store_true", default=False, dest="save_callgraph")
    parser.add_argument("--save-ghidra", help="Save Ghidra Projects",
                        action="store_true", default=False, dest="save_ghidra")
    parser.add_argument("--save-analysis", help="Save Analysis total output to a separate file",
                        action="store_true", default=False, dest="save_analysis")
    parser.add_argument("--delete-extract", help="Delete extraction results after analysis",
                        action="store_true", default=False, dest="delete_extract")
    # it takes more time for this analysis due to BAP!! try it only at crypto related binaries
    parser.add_argument("-cwe", "--cwe-checker", help="CWE checker, warning it will take time.",
                        action="store_true", default=False, dest="cwe_checker")
    parser.add_argument("-d", "--debug", help="Debug", action="store_true",
                        default=False, dest="debug")
    # TODO (FUTURE) remove in release version printall
    parser.add_argument("--print-all", help="Debug", action="store_true",
                        default=False, dest="print_all")
    parser.add_argument("-v", "--verbose", help="Verbose", action="store_true",
                        default=False, dest="verbose")
    parser.add_argument("-x", "--exclude-list", help="Apply exclude list", action="store_true",
                        default=False, dest="exclude")
    parser.add_argument("-t", "--threads", help="Number of threads. Omitting the option, system will automatically "
                                                "identify the number of cores.", dest="threads", type=int)
    parser.add_argument("-l", "--level", help="Level of Ghidra Analysis.\n"
                                              "\tLevel = 1: Default analysis\n"
                                              "\tLevel = 2: Decompiler Parameter ID\n"
                                              "\tLevel = 3: Aggressive Instruction search\n",
                        dest="level", type=int, default=1)
    parser.add_argument("-id", "--dates", help="CSV file with release dates on each firmware", dest="inputdates")
    return parser.parse_args(args)


def tryUnpackFirmware(proj):
    objunpackFirmware = unpackFirmware(proj)

    if (objunpackFirmware.objBinary.isBinary()):
        objunpackFirmware.reason.add(unpackFirmware.SINGLEBINARY)
        proj.unpackresults = objunpackFirmware.reason
        return

    objunpackFirmware.tryKnownFormats(objunpackFirmware.newLocation)

    # extract with binwalk
    objunpackFirmware.tryunpackwithBinwalk(proj.extractDir)

    # fail safe for binwalk
    while True:
        # check if the process is alive
        retbool = []
        for proc in objunpackFirmware.processQ:
            retbool.append(not proc.is_alive())

        isfinished = True
        for v in retbool:
            if v == False:
                isfinished = False

        if isfinished:
            objunpackFirmware.reason.add(unpackFirmware.BINWALK)
            break

        try:
            # check extraction size
            # may fail because extraction is still continuing in background
            # strout = mexec(["du", "-s", "-b", proj.extractDir])
            # s = int(strout.split()[0])
            s = sum(f.stat().st_size for f in proj.extractDir.glob('**/*') if (f.is_file() and not f.is_symlink()))
        except:
            # sleep for 1 second
            time.sleep(1)
            continue

        # convert to gigabytes
        gb = s / (1024 ** 3)

        # if it is more than x gb something went wrong
        if gb > float(CONFIGURATION.dict["SAFE_EXTRACTION"]):
            log.logE("Space explode for firmware '%s' ! Check binwalk!" % (proj.firmwareName))
            log.logEF("Space explode for firmware '%s' ! Check binwalk!" % (proj.firmwareName))

            objunpackFirmware.reason.add(unpackFirmware.SPACE_EXPLODE)
            # break
            break
        # sleep for 1 second
        time.sleep(1)

    # terminate all remaining processes
    for proc in objunpackFirmware.processQ:
        proc.terminate()
    objunpackFirmware.processQ.clear()
    objunpackFirmware.processQ = None

    # try unsquashfs official package
    objunpackFirmware.unpackOtherTools(proj.extractDir)

    # save results
    proj.unpackresults = objunpackFirmware.reason

    # TODO (FUTURE): try to unpack with more unpackers, etc
    #  -binaryanalysis-ng (bang-scanner)
    #  -fact extractor


def checkToAdd(bucketarr, GlobalProject, proj):
    for arr in bucketarr:
        root = arr[0]
        files = arr[1]
        for name in files:

            location = Path(os.path.join(root, name))

            tmpBinary = Binary(location, proj.firmwareName, proj.isVerbose(), getTypeOnly=True)
            if not tmpBinary.isBinary():
                proj.addBinaryWithFilter(tmpBinary)
            else:
                # get the hash only
                if (GlobalProject.checkBinary(tmpBinary)):
                    # adding hash to already analysed structure
                    proj.setSameBinary(tmpBinary.hashcode)
                    continue

                # check hash code for current project -> already added continue
                if tmpBinary.hashcode in proj.allbinaries:
                    continue
                # new file analyse
                objBinary = Binary(location, proj.firmwareName, proj.isVerbose(), getTypeOnly=False,
                                   hash_code=tmpBinary.hashcode)

                proj.addBinaryWithFilter(objBinary)


def traverseUnpack(GlobalProject, proj):
    stime = log.start_time()
    # hold counter of traverse files
    counter = 0

    if proj.isVerbose():
        log.logDF("Traversing extract directory:")

    # check utf-8 convert to latin and remove space and commas in dirs (for ghidra)
    for root, dirs, files in os.walk(proj.extractDir, topdown=False):
        for dir in dirs:
            # rename non latin1 characters
            try:
                dir.encode('latin1')
            except UnicodeEncodeError:
                location = os.path.join(root, dir)
                dir = bytes(dir, 'latin1', 'ignore').decode('utf-8', 'ignore')
                newlocation = Path(os.path.join(root, dir))
                if newlocation.exists():
                    newlocation = Path(os.path.join(root, dir + "_new"))
                os.rename(location, str(newlocation))

            # remove spaces and commas in dirs and
            if dir.__contains__(' ') or dir.__contains__(',') or dir.__contains__('\t') \
                    or dir.__contains__('\r') or dir.__contains__('\n'):
                location = os.path.join(root, dir)
                newlocation = Path(os.path.join(root, dir.replace(" ", "_").replace(",", "_").
                                           replace('\t', '_').replace('\r', '_').replace('\n', '_')))
                if newlocation.exists():
                    newlocation = Path(os.path.join(root, dir + "_new"))
                os.rename(location, str(newlocation))

    # buckets depends on number of threads available
    buckets = {}
    i = 0
    # add to buckets
    for root, dirs, files in os.walk(proj.extractDir):
        id = i % proj.numThreads
        if id not in buckets:
            buckets[id] = []
        buckets[id].append([root, files])
        i = i + 1

        counter = counter + len(files)

    threads = []
    for bucketarr in buckets.values():
        t = threading.Thread(target=checkToAdd, args=(bucketarr, GlobalProject, proj,))
        threads.append(t)
        t.start()

    # wait until all threads are finished
    for t in threads:
        t.join()

    proj.times.filter = log.end_time(stime, start="Filter-Files", end=proj.firmwareName, var=proj.times.filter)
    print(" CVE, Libraries, Yara crypto constants and Security hardening Scanner", end="...")

    stime = log.start_time()
    # update CVE, libraries and hardening check
    proj.updateInfoparallel()
    # update binaries structure into different groups
    proj.updateBinariesStructure()
    proj.times.cveandlibs = log.end_time(stime, start="CVE-Libraries", end=proj.firmwareName, var=proj.times.cveandlibs)

    if proj.isVerbose():
        log.logDF("Number of total files found = %d" % counter)


# playing only with absolute paths!!!!
def initialiseDirs(options):
    input = Path(os.path.abspath(options.input))
    output = Path(os.path.abspath(options.output))

    # create folder output
    createDir(output, False)
    # set the output log dir
    log.set_file_logs(output)

    newinputDir = output / CONFIGURATION.dict["DIR_ORIGINAL"]
    createDir(newinputDir)

    if input.is_file():
        # copy original file to original directory
        tryCopy(input, newinputDir)

    # if it is a directory copy all files to our original dir
    if input.is_dir():
        copy_tree(str(input), str(newinputDir))

    # create unpack directory
    extractDir = output / CONFIGURATION.dict["DIR_EXTRACT"]
    createDir(extractDir)

    # create analysis directory
    analysisDir = output / CONFIGURATION.dict["DIR_ANALYSIS"]
    createDir(analysisDir)

    inputdates = ""
    if options.inputdates is not None:
        inputdates = ntpath.basename(options.inputdates)

    numthreads = multiprocessing.cpu_count()
    if options.threads is not None:
        if not isinstance(options.threads, int):
            log.logE("Number of threads must be a real number")
            exit(DEFINES.FAILED)
        if options.threads == 0:
            numthreads = multiprocessing.cpu_count()
        else:
            if options.threads > multiprocessing.cpu_count():
                numthreads = multiprocessing.cpu_count()
            else:
                numthreads = options.threads

    objPostrules = initPostRules()

    return Project(options, input, newinputDir, output, extractDir, analysisDir, releaseFile=inputdates, isGlobal=True,
                   numthreads=numthreads, postRules=objPostrules)


def analyseBundle(arrayofBinaries, proj, analysis):
    for binary in arrayofBinaries:
        if proj.applyExclude():
            if binary.name in CONFIGURATION.excludelist:
                print("\n\t(Exclude list) Skipped: %s at %s\n\t\tCryptolibs: %s\n\t\tAllLibs: %s" % (
                    binary.name, binary.location, binary.vcrypto, binary.libraries))
                continue

        if binary.isLib():
            if (binary.name.split(".")[0] in proj.cryptolibs) \
                    or (binary.name.split("-")[0] in proj.cryptolibs) \
                    or (binary.name in proj.cryptolibs):
                print("\n\tSkipped: %s at %s\n\t\tCryptolibs: %s\n\t\tAllLibs: %s" % (
                    binary.name, binary.location, binary.vcrypto, binary.libraries))
                continue

        # update CWE only if it is not already update and argument is enable
        # need to add it here because of the recursive filter (apply only at crypto binaries)
        proj.updateCWE(binary)

        # perform static taint analysis
        analysis.analyse(binary)

    proj.qanalysis.put(analysis)


def printPossibleFiles(proj):
    print("Possible files found %d" % (len(proj.crypto_libraries) + len(proj.crypto_binaries)))
    print("\tLibraries:%d\n\tExecutables:%d" % (len(proj.crypto_libraries), len(proj.crypto_binaries)))


def printAlreadyAnalysed(proj, prev_lib, prev_exec):
    print("Already analysed files found %d" % (
            (len(proj.crypto_libraries) - prev_lib) + (len(proj.crypto_binaries) - prev_exec)))

    print("\tLibraries:%d\n\tExecutables:%d"
          % (len(proj.crypto_libraries) - prev_lib, len(proj.crypto_binaries) - prev_exec))


# split the binaries to buckets
# binary analyse time depends on binary size
# thus split into bucket with size in mind
def runBundleParallel(arrayofBinaries, proj):
    # no binaries return
    if len(arrayofBinaries) == 0:
        return

    arr = []
    for binary in arrayofBinaries:
        if proj.applyExclude():
            if binary.name in CONFIGURATION.excludelist:
                continue

        if binary.isLib():
            if (binary.name.split(".")[0] in proj.cryptolibs) \
                    or (binary.name.split("-")[0] in proj.cryptolibs) \
                    or (binary.name in proj.cryptolibs):
                continue

        sizeb = Path(binary.location).stat().st_size
        arr.append(sizeb)

    # binaries that are in exclude list only return
    if len(arr) == 0:
        return

    # parallel ghidra runs
    ghidraThreads = int(proj.numThreads / 2)
    if ghidraThreads <= 0:
        ghidraThreads = 1

    # max cores on each ghidra instance
    ghidramaxcores = proj.numThreads
    # int(ghidraThreads / 2)
    if ghidramaxcores <= 0:
        ghidramaxcores = 1

    # ghidra threads / 2
    numbuckets = partitionBuckets(arr, ghidraThreads)

    buckets = {}
    i = 0
    for binary in arrayofBinaries:
        # exclude list is not calculated for buckets but added in thread 0
        # it will be excluded further on
        sizeb = Path(binary.location).stat().st_size

        # find bucket id
        id = getbucketid(numbuckets, sizeb)

        if id not in buckets:
            buckets[id] = []
        buckets[id].append(binary)
        i = i + 1

    assert ghidraThreads >= len(buckets) > 0

    threads = []
    for bucket in buckets.values():
        analysis = Analysis(proj, ghidramaxcores, isGlobal=False)
        analysis.updatePreFromGlobal(proj.analysis)
        t = threading.Thread(target=analyseBundle, args=(bucket, proj, analysis,))
        threads.append(t)
        t.start()

    # wait until all threads are finished
    for t in threads:
        t.join()

    # join array of analysis to global analysis
    proj.analysis.updatePostFromOthers(proj.qanalysis.queue)
    with proj.qanalysis.mutex:
        proj.qanalysis.queue.clear()


def analyseFirmware(GlobalProject, firmwareName, origfile, objDate=None):
    print("\nAnalysing Firmware: %s at '%s'" % (firmwareName, origfile))

    # rename spaces to underscore
    # on Ghidra we have a problem parsing location with spaces
    if str(firmwareName).find(" ") >= 0:
        firmwareName = firmwareName.replace(" ", "_")

    # creating new dir for extraction
    extractednewDir = GlobalProject.extractDir / firmwareName
    createDir(extractednewDir)

    # creating new dir for analysis
    analysisnewDir = GlobalProject.analysisDir / firmwareName
    createDir(analysisnewDir)

    productLine = GlobalProject.getProductLine(firmwareName)

    # create local project one per firmware
    proj = Project(GlobalProject.options, GlobalProject.originalInput, origfile, GlobalProject.projectOutDir,
                   extractednewDir, analysisnewDir,
                   firmwareName=firmwareName, numthreads=GlobalProject.numThreads, postRules=GlobalProject.postRules,
                   releaseDate=objDate, yaraobj=GlobalProject.yaraobj,
                   productLine=productLine)

    # try to unpack the firmware
    print("Extract Firmware", end="...")
    stime = log.start_time()
    tryUnpackFirmware(proj)
    proj.times.extract = log.end_time(stime, start="Extract-Firmware", end=proj.firmwareName, var=proj.times.extract)
    print(" done")

    # analyse begin on each file
    print("Filter Files", end="...")
    traverseUnpack(GlobalProject, proj)
    stime = log.start_time()

    # check crypto libraries version
    proj.updateVersion(GlobalProject)
    # update local All libraries
    proj.updateLocalAllLibraries(GlobalProject)
    # link symbolic links to libraries
    proj.SymbolicLinksToLibs()
    # apply filter after symbolic links
    proj.applyFilterAfterSymbolicLinks()
    # save credentials to file
    proj.saveCredentials()
    print(" done")

    # global analysis object
    proj.analysis = Analysis(proj, proj.numThreads, isGlobal=True)

    # update local project rules from global project rules
    # for every same library found
    # update self crypto wrappers
    proj.updateLocalAnalyses(GlobalProject)

    crypto_libraries_analysed = set()
    bundletoanalyse = proj.crypto_libraries

    print("Producing order of analysis", end="...")
    orderbundles = proj.produceOrder(bundletoanalyse)
    print("done")

    proj.times.filter = log.end_time(stime, start="Filter-Files-Others", end=proj.firmwareName, var=proj.times.filter,
                                     accumulated=True)

    printPossibleFiles(proj)

    print("Analyse Files:")
    print("Analyse Libraries:")

    # recursive until no new wrapper of libraries is added
    while len(crypto_libraries_analysed) != len(proj.crypto_libraries):
        stime = log.start_time()
        # run libraries based on the topological sort in parallel
        for bundle in orderbundles.values():
            runBundleParallel(bundle, proj)
        proj.times.ghidralibs = log.end_time(stime, start="Ghidra-Libs", end=proj.firmwareName,
                                             var=proj.times.ghidralibs, accumulated=True)

        stime = log.start_time()
        crypto_libraries_analysed = proj.crypto_libraries.copy().keys()

        # apply rules to new filter
        proj.applyFilter(proj.analysis.setofCryptoWrapper, DEFINES.WRAPPER)

        samekeys = proj.crypto_libraries.keys() & crypto_libraries_analysed
        if len(samekeys) != len(proj.crypto_libraries.keys()):
            bundletoanalyse = {}
            # get the libraries that are not yet analysed
            for key, value in proj.crypto_libraries.items():
                if key not in crypto_libraries_analysed:
                    bundletoanalyse[key] = value

            orderbundles = proj.produceOrder(bundletoanalyse)

        proj.times.filter = log.end_time(stime, start="Filter-Rec", end=proj.firmwareName, var=proj.times.filter,
                                         accumulated=True)

    print("Final after filter:")
    printPossibleFiles(proj)

    print("\nAnalyse executables binaries:")
    stime = log.start_time()
    runBundleParallel(proj.crypto_binaries.values(), proj)
    proj.times.ghidraexec = log.end_time(stime, start="Ghidra-Exec", end=proj.firmwareName, var=proj.times.ghidraexec)

    prev_lib = len(proj.crypto_libraries)
    prev_exec = len(proj.crypto_binaries)

    # update already analysed binaries to local project
    proj.updateLocalBinaries(GlobalProject)
    # save all found crypto libs versions and analysis

    # update sink functions
    GlobalProject.updateSinkFunctions(proj)

    # update global project
    GlobalProject.updateStructure(proj)

    # print number of files that are already analysed in past firmware
    printAlreadyAnalysed(proj, prev_lib, prev_exec)

    # post options
    checkPostOptions(proj)

    return proj


if __name__ == "__main__":

    system_time = time.time()
    # parse arguments
    options = getOptions()

    # initialise configuration file
    initConfig(options)
    # checking preconfigure directories
    checkDirectories(options)

    # initialization phase
    print("Initialisation directories", end="...")
    GlobalProject = initialiseDirs(options)
    print(" done")
    print("Number of threads:", GlobalProject.numThreads)

    sortRelease = getReleaseOrder(options, GlobalProject.firmwareInput)
    GlobalProject.setProductLine(sortRelease)

    setofAnalysed = set()
    # order of running from oldest to newest firmware
    for firmwareName, obj in sortRelease.items():
        # real location not found
        if not isinstance(obj, list):
            continue
        # obj[0] is equal to path
        # obj[1] is equal to tuple date, product line
        if len(obj) != 2:
            continue

        origfile = Path(obj[0])
        if not isinstance(obj[1], tuple):
            continue

        objDate = obj[1][0]
        setofAnalysed.add(origfile)

        # do not analyse release file
        if firmwareName == GlobalProject.releaseFile:
            continue

        stime = log.start_time()
        proj = analyseFirmware(GlobalProject, firmwareName, origfile, objDate=objDate)
        proj.times.overall = log.end_time(stime, start="Overall", end=proj.firmwareName, var=proj.times.overall)

    for root, dirs, files in os.walk(GlobalProject.firmwareInput):
        for firmwareName in files:
            origfile = Path(os.path.join(root, firmwareName))

            if origfile in setofAnalysed:
                continue

            # do not analyse release file
            if firmwareName == GlobalProject.releaseFile:
                continue

            stime = log.start_time()
            proj = analyseFirmware(GlobalProject, firmwareName, origfile)
            proj.times.overall = log.end_time(stime, start="Overall", end=proj.firmwareName, var=proj.times.overall)

    checkPostOptions(GlobalProject)
    # take overall analysis time
    overall_time = (time.time() - system_time)
    log.logTime("Overall", overall_time)
    GlobalProject.times.overall = overall_time
    print("Run Time: %f" % overall_time)

    db = ProductDB(location=GlobalProject.projectOutDir)
    db.init_database()
    print("Populating database...", end="")
    db.populate_db([GlobalProject])

    # deconstructors
    for firm in GlobalProject.firmwares.values():
        del firm.analysis
        del firm

    del GlobalProject

    print("done")
