import shutil
from distutils.util import strtobool
import json
import ntpath
import copy
from os import path
from pathlib import Path

from modules.DEFINES import DEFINES, CONFIGURATION
from modules.TranslateRules import translateRules, checkPostRules, checkPostMisuseRules, checkPostMisuseRulesOnline, \
    createGroup
from modules.graph import GraphAST, CallGraph
from modules.Rule import Rule, AbstractRule, TaintedMapped, getRuleMnemonic, Sink
from modules.helpfunctions import createDir, normcaseLinux, mexec, tryCopy, mexecGhidra
from modules.log import log
from threading import Lock

# mutex on rules.conf file
mutex = Lock()


class Analysis:
    GHIDRA_PROJECTS = "ghidra_projects"
    GHIDRA_SCRIPTS = "/EBAT/ghidra_scripts/"

    # time in seconds
    MIN_TIMEOUT = 2000
    MAX_TIMEOUT = 20000

    def __init__(self, proj, maxCPUcore, isGlobal=False):

        self.proj = proj

        # Ghidra's max cpu core
        self.maxCPUcore = str(maxCPUcore)

        # store [hash] = dict[addr] of sinks
        self.uniqueSinks = {}

        # store [hash] = array misuse rules
        self.misuseRules = {}

        # store wrappers [hash] = [function names] -> array of rules functions
        self.namewrappers = {}

        # store if entry is found store [hash] = dict entry
        self.entries = {}

        self.isGlobal = isGlobal

        self.ANALYZEPROC = CONFIGURATION.dict["GHIDRADIR"] + "/support/" + CONFIGURATION.dict["GHIDRAANALYSE"]
        self.GHIDRAPROJECT = self.proj.analysisDir / self.GHIDRA_PROJECTS

        self.NEWRULES = self.proj.analysisDir / ntpath.basename(path.abspath(CONFIGURATION.dict["RULES"]))

        self.SAVEASTFIGURES = self.proj.analysisDir / "AST"
        self.SAVECALLGRAPHFIGURES = self.proj.analysisDir / "CallGraphs"
        self.SAVEANALYSISRESULTS = self.proj.analysisDir / "JSON"

        self.POSTRULES = CONFIGURATION.dict["POSTRULES"]

        # hold the new filter crypto wrapper lib
        self.setofCryptoWrapper = set()

        # store wrappers [hash] = (array of update rules.config strings)
        self.libwrappers = {}
        self.setRuleNames = self.proj.setRuleNames

        # store cfg[hash] = [cfg, vertexset, edgeset]
        self.jsoncfg = {}

        if self.isGlobal:
            # create and initialise directories
            createDir(self.GHIDRAPROJECT)

            # copy rules file
            tryCopy(path.abspath(CONFIGURATION.dict["RULES"]), self.proj.analysisDir)

            # create AST dir
            if (self.proj.saveAST()):
                createDir(self.SAVEASTFIGURES)

            # create Callgraph dir
            if (self.proj.saveCallGraphs()):
                createDir(self.SAVECALLGRAPHFIGURES)

            # create Analysis saved results dir
            if (self.proj.saveAnalysisResults()):
                createDir(self.SAVEANALYSISRESULTS)

            self.fpanalysis = open(self.proj.analysisDir / CONFIGURATION.dict["FILE_ANALYSIS"], "w+")

            # header
            self.fpanalysis.write("Name, Type, FileType, Arch, Bit Processor, Endianness, Crypto Libraries, Libraries,"
                                  " Firmware Name, Location, SHA256 Hash\n"
                                  "Function Name, Cryptographic Primitive Type, Called from entry, Address of Sink, "
                                  "Called from Function, Possible Algorithm")

            self.fpmisuse = open(self.proj.analysisDir / CONFIGURATION.dict["FILE_MISUSE"], "w+")

            # header
            self.fpmisuse.write("Name, Type, FileType, Arch, Bit Processor, Endianness, Crypto Libraries, Libraries,"
                                " Firmware Name, Location, SHA256 Hash\n"
                                "Function Name, Misuse Rule, Called from entry, Value, Address of Value, Address of Sink, "
                                "Called from Function, Possible Algorithm, isPhi")

    def __del__(self):
        if self.isGlobal:
            self.fpanalysis.close()
            self.fpmisuse.close()

            # delete Ghidra still remaining projects
            if not self.proj.saveGhidraProjects():
                shutil.rmtree(self.GHIDRAPROJECT, ignore_errors=True)

    def updatePreFromGlobal(self, globalAnalysis):
        self.namewrappers.update(globalAnalysis.namewrappers)
        # store wrappers [hash] = (array of update rules.config strings)
        self.libwrappers.update(globalAnalysis.libwrappers)

    def updatePostFromOthers(self, arranalysis):
        for analysis in arranalysis:
            if analysis is None:
                continue
            # deep copy because of queue is deleted afterwards
            self.uniqueSinks.update(copy.deepcopy(analysis.uniqueSinks))
            self.misuseRules.update(copy.deepcopy(analysis.misuseRules))
            self.entries.update(copy.deepcopy(analysis.entries))
            # hold the new filter crypto wrapper lib
            self.setofCryptoWrapper.update(copy.deepcopy(analysis.setofCryptoWrapper))
            # store wrappers [hash] = (array of update rules.config strings)
            self.libwrappers.update(copy.deepcopy(analysis.libwrappers))
            self.namewrappers.update(copy.deepcopy(analysis.namewrappers))
            self.jsoncfg.update(copy.deepcopy(analysis.jsoncfg))

        # free memory
        for analysis in arranalysis:
            if analysis is None:
                continue
            del analysis

    def checkHighParameter(self, sink, exports):

        getruleid = sink["ruleid"]
        getArg = sink["argIdx"]
        getType = sink["typeofArg"]
        ruleobj = Rule(sink["rule"])

        getfunname = sink["functionName"]
        getfunsig = sink["functionSignatureName"]
        gettotalarg = sink["totalArg"]

        typestr = ruleobj.taintedArgs[str(getArg)].typeToString()

        newrule = '{}; {}; {}; {}; {}'.format(
            getfunname, getfunsig, gettotalarg, ruleobj.ruleType,
            str(DEFINES.NO_ARGUMENTS) + ":" + typestr + ":" + str(getruleid))

        if getArg == DEFINES.NO_ARGUMENTS:
            # filter with export symbols! starts with FUN means local function
            if sink["functionName"] not in exports:
                return []

            return [AbstractRule(newrule, sink["rule"])]

        # check high parameter
        # wrapper comes with multiple inside function calls and then the exports
        # add multiple wrappers
        nodeStack = []
        nodeStack.append(sink)
        returnArules = []

        def checkHigh(node, exports):
            # check for high parameter
            if (node["nodeName"] != "HIGHPARAM"):
                return False

            # filter with export symbols! starts with FUN means local function
            if node["functionName"] not in exports:
                return False

            return True

        def addArule(node):
            # get details
            getfunname = node["functionName"]
            getfunsig = node["functionSignatureName"]
            gettotalarg = node["totalArg"]
            # not counting from zero
            gethighArg = node["argIdx"] + 1

            # create rule
            newrule = '{}; {}; {}; {}; {}'.format(
                getfunname, getfunsig, gettotalarg, ruleobj.ruleType,
                str(gethighArg) + ":" + typestr + ":" + str(getruleid))
            mapped = {}
            mapped[gethighArg] = TaintedMapped(str(getArg), ruleobj)
            return AbstractRule(newrule, sink["rule"], mapped)

        while (len(nodeStack) > 0):
            current_node = nodeStack.pop()

            for node in current_node["children"]:
                if node['nodeName'] == 'PARENTFUNCTION' or node['nodeName'] == 'HIGHPARAM' or node[
                    'nodeName'] == 'FUNCTION' or node['nodeName'] == 'PHIFUNCTION':
                    nodeStack.append(node)

                # append only if
                if (checkHigh(node, exports) == True):
                    returnArules.append(addArule(node))

            for node in current_node["parents"]:
                if node['nodeName'] == 'PARENTFUNCTION' or node['nodeName'] == 'HIGHPARAM' or node[
                    'nodeName'] == 'FUNCTION' or node['nodeName'] == 'PHIFUNCTION':
                    nodeStack.append(node)

                # append only if
                if (checkHigh(node, exports) == True):
                    returnArules.append(addArule(node))

        # high parameter return array
        return returnArules

    # in the extracted part try to see if their are any libraries also included
    # this may help the analysis
    # return only lib that founds name and locations
    def getLocationOfLibraries(self, libraries):

        arrLibLoc = []
        arrLibName = []
        for lib in libraries:
            if lib in self.proj.allLibraries:
                for hashcode in self.proj.allLibraries[lib]:
                    binary = self.proj.allbinaries[hashcode]
                    arrLibLoc.append(normcaseLinux(binary.location))
                    arrLibName.append(lib + "," + binary.name)

        return [arrLibLoc, arrLibName]

    def analyse(self, objBinary, processor=""):

        print("\n\t%s at %s\n\t\tCryptolibs: %s\n\t\tAllLibs: %s" % (
            objBinary.name, objBinary.location, objBinary.vcrypto, objBinary.libraries))

        stime = log.start_time()

        # give timeout proportionally to filesize
        sizebytes = Path(objBinary.location).stat().st_size
        timeoutsec = int(min(self.MIN_TIMEOUT + sizebytes / 100, self.MAX_TIMEOUT))
        LIMIT_PLUS = 20
        # print("TIMEOUT:", timeoutsec, "size:", sizebytes)

        PROJECTNAME = objBinary.name + "-" + objBinary.hashcode
        # truncate to 60 characters max (ghidra valid project name size)
        PROJECTNAME = PROJECTNAME[:60]

        deletearg = ""
        if not self.proj.saveGhidraProjects():
            deletearg = "-deleteProject"

        strLib = ""
        if (objBinary.isLib()):
            strLib = "isLib"

        # for linux
        # for windows use os.path.normcase , and os.path.normpath

        # -max-cpu <max cpu cores to use>
        # Sets the maximum number of CPU cores to use during headless processing (must be an integer).
        # Setting max-cpu to 0 or a negative integer is equivalent to setting the maximum number of cores to 1.

        if processor == "":
            # create a project with the binary you want to analyse
            # single quotes used for escaping special characters
            strout = mexecGhidra(
                [self.ANALYZEPROC, normcaseLinux(self.GHIDRAPROJECT), PROJECTNAME,
                 "-import", normcaseLinux(objBinary.location),
                 "-analysisTimeoutPerFile", str(timeoutsec),
                 "-scriptPath", self.GHIDRA_SCRIPTS,
                 "-max-cpu", self.maxCPUcore,
                 "-preScript", "setOptionsPre.java", strLib, "level", self.proj.level,
                 "-postScript", "FindUndefinedFunctions.java",
                 "-postScript", "FindMain.java"], verbose=self.proj.isVerbose(), isGhidra=True, timeout=str(timeoutsec + LIMIT_PLUS))
        else:
            # processor argument on decompile failed
            # create a project with the binary you want to analyse
            # single quotes used for escaping special characters
            strout = mexecGhidra(
                [self.ANALYZEPROC, normcaseLinux(self.GHIDRAPROJECT), PROJECTNAME,
                 "-import", normcaseLinux(objBinary.location),
                 "-analysisTimeoutPerFile", str(timeoutsec),
                 "-scriptPath", self.GHIDRA_SCRIPTS,
                 "-max-cpu", self.maxCPUcore,
                 "-processor", processor,
                 "-preScript", "setOptionsPre.java", strLib, "level", self.proj.level,
                 "-postScript", "FindUndefinedFunctions.java",
                 "-postScript", "FindMain.java"], verbose=self.proj.isVerbose(), isGhidra=True, timeout=str(timeoutsec + LIMIT_PLUS))

        debugarr = self.getPrintAllArr()

        # ret_bool = boolean (true or false)
        # ret_main_id = mainid (if is found from previous script return the main function id)
        # haserror = decompiler warnings and/or errors
        ret_bool, ret_main_id, haserrors, garch = self.checkFirstAnalysis(strout, objBinary)
        # decompile errors maybe wrong architecture found on ghidra
        if haserrors and garch != "" and processor == "":
            arr = garch.split(':')
            barch = str(objBinary.arch)
            ischanged = False
            if barch.__contains__('PowerPC'):
                barch = "PowerPc"
                ischanged = True
            elif barch.__contains__('ARM'):
                barch = "ARM"
                # adding aarch64
                if objBinary.getBitMnemonic() == "64":
                    barch = "AARCH64"
                ischanged = True
            elif barch.__contains__('MIPS'):
                barch = "MIPS"
                ischanged = True
            newarch = barch + ":" + objBinary.getEndiannessMnemonic() + ":" + objBinary.getBitMnemonic()
            garchcmp = arr[0] + ":" + arr[1] + ":" + arr[2]
            # check architecture
            if newarch.lower() != garchcmp.lower() and ischanged:
                # delete project
                shutil.rmtree(str(self.GHIDRAPROJECT / (PROJECTNAME + '.rep')), ignore_errors=True)
                # rerun
                self.analyse(objBinary, processor=newarch + ":default")
                return

        if not ret_bool:
            analysis_option = "-noanalysis"

            strout = mexecGhidra(
                [self.ANALYZEPROC, normcaseLinux(self.GHIDRAPROJECT), PROJECTNAME, analysis_option,
                 "-process", objBinary.name,
                 "-scriptPath", self.GHIDRA_SCRIPTS,
                 "-max-cpu", self.maxCPUcore,
                 "-postScript", "CheckAnalysis.java", "input", normcaseLinux(self.NEWRULES)],
                verbose=self.proj.isVerbose(), isGhidra=False, timeout=str(timeoutsec + LIMIT_PLUS))

            if (self.checkAnalysis(strout, objBinary) == False):
                log.end_time(stime, start="Ghidra1:" + PROJECTNAME, end=self.proj.firmwareName)
                return

        log.end_time(stime, start="Ghidra1:" + PROJECTNAME, end=self.proj.firmwareName)

        stime = log.start_time()
        # Starting backward trace on rules (also find main before may fail the first time)
        strout = mexecGhidra(
            [self.ANALYZEPROC, normcaseLinux(self.GHIDRAPROJECT), PROJECTNAME, deletearg,
             "-process", objBinary.name,
             "-analysisTimeoutPerFile", str(timeoutsec),
             "-scriptPath", self.GHIDRA_SCRIPTS,
             "-max-cpu", self.maxCPUcore,
             "-preScript", "setOptionsPre.java", strLib, "level", self.proj.level,
             "-postScript", "FindMain.java", ret_main_id,
             # "-postScript", "EBATCFG.java",
             "-postScript", "TaintAnalysis.java", "input", normcaseLinux(self.NEWRULES),
             "crypto", normcaseLinux(self.POSTRULES)] + debugarr, verbose=True, isGhidra=False, timeout=str(timeoutsec + LIMIT_PLUS))

        log.end_time(stime, start="Ghidra2:" + PROJECTNAME, end=self.proj.firmwareName)

        stime = log.start_time()
        self.getAnalysisResults(objBinary, strout, PROJECTNAME, objBinary.isLib())
        log.end_time(stime, start="Results:" + PROJECTNAME, end=self.proj.firmwareName)

    def getPrintAllArr(self):
        if (self.proj.isDebugPrintAll() == False):
            return []

        return ["-postScript", "PRINTALL.java"]

    def checkFirstAnalysis(self, strout, objBinary):

        checkUndefined = False
        checkMain = False
        haserrors = False
        garch = ""
        mainid = ""
        # check if exec executes successfully
        if not isinstance(strout, str):
            log.logW(
                "Something went wrong during analysis of " + objBinary.name)
            return (checkUndefined or checkMain), mainid, haserrors, garch

        mainid = ""
        for line in strout.splitlines():

            if line.startswith('WARN  Decompiling'):
                haserrors = True
            if line.startswith('INFO  REPORT: Import succeeded with language'):
                garch = line.split('"')[1].strip()

            if line.startswith("CHECKUNDEFINED"):
                # print(lines)
                arr = line.split("=")
                if (len(arr) == 2):
                    checkUndefined = strtobool(arr[1])

            if line.startswith("CHECKMAIN"):
                # print(lines)
                arr = line.split("=")
                if (len(arr) == 2):
                    arrid = arr[1].split(',')
                    if (len(arrid) == 2):
                        checkMain = strtobool(arrid[0])
                        if arrid[1] != "null":
                            mainid = arrid[1]

        return (checkUndefined or checkMain), mainid, haserrors, garch

    def checkAnalysis(self, strout, objBinary):
        # check if exec executes successfully
        if (isinstance(strout, str) == False):
            log.logW(
                "Something went wrong during analysis of " + objBinary.name)
            return False

        checkAnalysis = False
        for lines in strout.splitlines():
            if lines.startswith("CHECKANALYSIS"):
                # print(lines)
                arr = lines.split("=")
                if (len(arr) == 2):
                    checkAnalysis = strtobool(arr[1])

        return checkAnalysis

    def getAnalysisResults(self, objBinary, strout, PROJECTNAME, isLib):

        # check if exec executes successfully
        if (isinstance(strout, str) == False):
            log.logW(
                "Something went wrong during analysis of " + PROJECTNAME + "," + self.proj.firmwareName +
                ". Error in TaintAnalysis.java, please see the log files for more")
            log.logWF(
                "Something went wrong during analysis of " + PROJECTNAME + "," + self.proj.firmwareName +
                ". Error in TaintAnalysis.java, please see the log files for more")
            return

        getjsonAST = "{}"
        getjsonCallGraph = "{}"
        getjsonCFGvertexset = "{}"
        getjsonCFGedgeset = "{}"
        getjsonCFGedges = "{}"
        getjsonEntry = "{}"
        getjsonExports = "{}"
        for lines in strout.splitlines():
            if lines.startswith("JSONAST;"):
                getjsonAST = lines[8:]
            if lines.startswith("JSONCFG-VERTEX;"):
                getjsonCFGvertexset = lines[15:]
            if lines.startswith("JSONCFG-EDGE;"):
                getjsonCFGedgeset = lines[13:]
            if lines.startswith("JSONCFG;"):
                getjsonCFGedges = lines[8:]
            if lines.startswith("JSONCALLGRAPH;"):
                getjsonCallGraph = lines[14:]
            if lines.startswith("JSONCALLINGSINKS;"):
                getjsonEntry = lines[17:]
            if lines.startswith("JSONEXPORTS;"):
                getjsonExports = lines[12:]

        if (getjsonAST == "{}") or (getjsonCallGraph == "{}"):
            log.logW(
                "Something went wrong during analysis of " + PROJECTNAME + "," + self.proj.firmwareName +
                ". Getting JSON string failed, please see the log files for more")
            log.logWF(
                "Something went wrong during analysis of " + PROJECTNAME + "," + self.proj.firmwareName +
                ". Getting JSON string failed, please see the log files for more")
            return

        try:
            arrAST = json.loads(getjsonAST)
            callgraph = json.loads(getjsonCallGraph)
            entryfound = json.loads(getjsonEntry)
            exports = json.loads(getjsonExports)
            cfgvertexset = json.loads(getjsonCFGvertexset)
            cfgedgeset = json.loads(getjsonCFGedgeset)
            cfg = json.loads(getjsonCFGedges)

            if self.proj.saveAnalysisResults():
                # create the directory
                createDir(self.SAVEANALYSISRESULTS / PROJECTNAME)
                fp = open(self.SAVEANALYSISRESULTS / PROJECTNAME / "json.txt", "w+")
                fp.write(objBinary.toString() + "\n")
                fp.write("JSONAST;" + getjsonAST + "\n")
                fp.write("JSONCALLGRAPH;" + getjsonCallGraph + "\n")
                fp.write("JSONCALLINGSINKS;" + getjsonEntry + "\n")
                fp.write("JSONEXPORTS;" + getjsonExports + "\n")
                fp.close()

        except ValueError as e:
            log.logW(
                "Something went wrong during analysis of " + PROJECTNAME + "," + self.proj.firmwareName
                + ". Parsing JSON string failed, please see the log files for more")
            log.logWF(
                "Something went wrong during analysis of " + PROJECTNAME + "," + self.proj.firmwareName
                + ". Parsing JSON string failed, please see the log files for more")
            return

        # No sinks are found
        if len(arrAST) == 0:
            return

        self.jsoncfg[objBinary.hashcode] = [cfg, cfgvertexset, cfgedgeset]

        # init
        listofG = {}
        i = 0
        Libmisuse = []
        lmisuserules = {}
        luniqueSinks = {}

        # for every sink
        for ast in arrAST:

            # check if we found any sinks
            if (ast["nodeName"] == "SINK"):

                checkDefinedStringsandAlgorithms(ast)

                # check if it is a library and uses high parameter
                if (isLib == True):
                    retch = self.checkHighParameter(ast, exports)
                    for arule in retch:
                        # do not update rules if there already exists
                        if arule.rule.FunctionName in self.setRuleNames:
                            continue
                        Libmisuse.append(arule)

                self.addUniqueSinksOnly(luniqueSinks, ast, entryfound, isLib, objBinary)

                convertToHMAC(luniqueSinks[ast["addr"]], ast)
                # get all misuse rules
                translateRules(ast, lmisuserules, bitarch=objBinary.bit, verbose=self.proj.isVerbose())

                if (self.proj.saveAST()):
                    # if is argIdx = 0 means no AST just the function call
                    # do not print it -> to many results
                    if (ast["argIdx"] != 0):
                        # add to a graph for printing the AST to dot files
                        listofG[i] = GraphAST(objBinary, ast)

                        i = i + 1

        # update by ref
        self.uniqueSinks[objBinary.hashcode] = luniqueSinks
        # update entries
        self.entries[objBinary.hashcode] = entryfound
        # check misuses
        self.foundMisuse(objBinary, lmisuserules)

        if isLib:
            self.updateRules(Libmisuse, objBinary)

        if (self.proj.saveAST()):
            # save AST
            # create dir to save graphs
            createDir(self.SAVEASTFIGURES / PROJECTNAME)
            for i, G in listofG.items():
                G.save_graph(self.SAVEASTFIGURES / PROJECTNAME)

        # create and save the call graph
        if (self.proj.saveCallGraphs()):
            self.createCallGraph(objBinary, callgraph, PROJECTNAME)

    def foundMisuse(self, objBinary, lmisuserules):

        # update all algorithms check post rules
        checkPostMisuseRules(self, self.uniqueSinks[objBinary.hashcode], lmisuserules)

        # if len(lmisuserules) > 0:
        #    self.fpmisuse.write("\n\n" + objBinary.toString())
        #    print("\tFound Misuses:")

        for hashcode, absrule in lmisuserules.items():
            for objmis in absrule.abstract:
                # check for post rules
                checkPostMisuseRulesOnline(self, objmis)

                # log to file
                # self.fpmisuse.write(
                #    "\n%s, %s, %s, %s, %s, %s, %s, %s, %s, %s" % (
                #        str(objmis.targetFunc), str(getRuleMnemonic(objmis.ruleID)), entryfound[objmis.fromFunc],
                #        str(objmis.constValue), str(objmis.constAddress), str(objmis.atAddress), str(objmis.fromFunc),
                #        ";".join(objmis.algorithm.keys()), ";".join([str(i) for i in objmis.algorithm.values()]),
                #        str(objmis.isPhi)))

                # do not print dependent values
                # if objmis.ruleID == CONFIGURATION.rules["DEPENDENT"]:
                #    continue

                # print(
                #   "\t\tMisuse rule '%s' at function '%s' '@%s' from function '%s', with const value '%s' (%s) '@%s'" % (
                #       str(getRuleMnemonic(objmis.ruleID)), str(objmis.targetFunc), str(objmis.atAddress),
                #       str(objmis.fromFunc),
                #       str(objmis.constValue), str.encode(str(objmis.constValue)), str(objmis.constAddress)))

        self.misuseRules[objBinary.hashcode] = lmisuserules

    def updateGroupSinks(self):
        for sinks in self.uniqueSinks.values():
            for addr, sink in sinks.items():
                createGroup(self, sink)

    def saveMisuseFile(self, proj):
        for hashcode, lmisuserules in self.misuseRules.items():
            self.fpmisuse.write("\n\n" + proj.allbinaries[hashcode].toString())
            for addr, absrule in lmisuserules.items():
                for objmis in absrule.abstract:
                    # log to file
                    self.fpmisuse.write(
                        "\n%s, %s, %s, %s, %s, %s, %s, %s, %s, %s" % (
                            str(objmis.targetFunc), str(getRuleMnemonic(objmis.ruleID)),
                            self.entries[hashcode][objmis.fromFunc],
                            str(objmis.constValue), str(objmis.constAddress), str(objmis.atAddress),
                            str(objmis.fromFunc),
                            ";".join(objmis.algorithm.keys()), ";".join([str(i) for i in objmis.algorithm.values()]),
                            str(objmis.isPhi)))

    def saveUniqueSinksFile(self, proj):
        for hashcode, sinks in self.uniqueSinks.items():
            self.fpanalysis.write("\n\n" + proj.allbinaries[hashcode].toString())
            for addr, sink in sinks.items():
                self.fpanalysis.write(
                    "\n%s, %s, %s, 0x%s, %s, %s, %s" % (
                        sink.targetFunc, getRuleMnemonic(sink.rule.ruleType), sink.isEntry,
                        addr, sink.fromFunc, ";".join(sink.algorithm.keys()),
                        ";".join([str(i) for i in sink.algorithm.values()])))

    def createCallGraph(self, objBinary, callgraph, PROJECTNAME):
        createDir(self.SAVECALLGRAPHFIGURES / PROJECTNAME)
        gcallGraph = CallGraph(objBinary.name)
        for edges in callgraph:
            nodefrom = edges["edgeList"][0]["FunctionName"] + "\n" + "@" + hex(edges["edgeList"][0]["EntryPoint"])
            nodeto = edges["edgeList"][1]["FunctionName"] + "\n" + "@" + hex(edges["edgeList"][1]["EntryPoint"])
            gcallGraph.addEdge(nodefrom, nodeto, edges["isIndirect"])

        gcallGraph.save_graph(self.SAVECALLGRAPHFIGURES / PROJECTNAME)

    def updateFilter(self, objBinary):
        self.setofCryptoWrapper.add(objBinary.name)
        for sym in objBinary.setofSymbolicNames:
            self.setofCryptoWrapper.add(sym)

    def updateRules(self, Libmisuse, objBinary):

        dictrules = {}
        # try to get rules
        for objrule in Libmisuse:
            if (objrule is None):
                continue
            name = objrule.rule.FunctionName

            if (name in dictrules):
                # same function merge
                rule1 = objrule.rule
                rule2 = dictrules[name].rule

                if (dictrules[name].mapped != None):
                    if objrule.mapped != None:
                        # merged mapped
                        dictrules[name].mapped.update(objrule.mapped)
                elif (objrule.mapped != None):
                    dictrules[name].mapped = objrule.mapped

                # update tainted arguments
                for arg, type in rule1.taintedArgs.items():
                    rule2.taintedArgs[arg] = type

                # update description
                for des in objrule.abstract:
                    dictrules[name].addAbstract(des)

            else:
                dictrules[name] = objrule

        # update successors if any
        for name, objrule in dictrules.items():
            if objrule.mapped != None:
                # for every mapped argument
                for arg, mapped in objrule.mapped.items():
                    successors = mapped.rule.taintedArgs[str(mapped.argFrom)].successors
                    # check if a mapped argument has successors
                    if len(successors) > 0:
                        targetFunction = mapped.rule.FunctionName
                        # for every successor
                        for s in successors:
                            # check for every other argument with the same function name
                            for larg, lmapped in dictrules[name].mapped.items():
                                if larg == arg:
                                    continue
                                if lmapped.argFrom == s and lmapped.rule.FunctionName == targetFunction:
                                    dictrules[name].rule.taintedArgs[str(arg)].successors.add(str(larg))

        if len(dictrules) > 0:

            # update filter
            self.updateFilter(objBinary)
            self.libwrappers[objBinary.hashcode] = []
            lnamewrappers = {}
            mutex.acquire()
            try:
                # update rules
                fp = open(self.NEWRULES, "a+")
                wstr = "\n# Updating rules from: " + objBinary.toString() + "\n"
                self.libwrappers[objBinary.hashcode].append(wstr)

                fp.write(wstr)
                for name, objrule in dictrules.items():
                    setofnames = set()
                    # write comments
                    for msg in objrule.abstract:
                        wstr = "# " + str(msg) + "\n"
                        self.libwrappers[objBinary.hashcode].append(wstr)
                        # update set of name wrappers
                        obj = Rule(msg)
                        if (obj.isRule):
                            setofnames.add(obj.FunctionName)

                        fp.write(wstr)
                    # write rules
                    wstr = objrule.rule.toString() + "\n"
                    # update local name wrappers
                    lnamewrappers[objrule.rule.FunctionName] = setofnames
                    # update libwrappers
                    self.libwrappers[objBinary.hashcode].append(wstr)
                    fp.write(wstr)
                # flashes and close
                fp.close()
            finally:
                mutex.release()
            # update name wrappers
            self.namewrappers[objBinary.hashcode] = lnamewrappers

    def addUniqueSinksOnly(self, dict, sink, entryfound, isLib, objBinary):

        getaddr = sink["addr"]

        # check post rules
        # no need to handle return pass by reference
        # handle CTYPE and CTX
        # and other meta analysis options
        checkPostRules(self, sink, bitarch=objBinary.bit)

        getAlgorithm = {}
        if ("algorithm" in sink):
            getAlgorithm = sink["algorithm"]

        metarule = {}
        if "metarule" in sink:
            metarule = sink["metarule"]

        extrameta = []
        if "extrameta" in sink:
            extrameta = sink["extrameta"]

        ishmac = False
        if "isHMAC" in sink:
            ishmac = sink["isHMAC"]

        if getaddr not in dict:
            getFrom = sink["functionName"]
            getSink = sink["targetFunctionName"]
            objrule = Rule(sink["rule"])

            # if (self.proj.isVerbose()):
            #    print("\t\t'%s' at address '@0x%X' from function '%s'" % (sink["targetFunctionName"],
            #                                                              int(sink["addr"], 16), sink["functionName"]))

            bupdated = False
            for hash, lnamewrappers in self.namewrappers.items():

                # check if lib is included in binary
                if (self.checkWrapperLib(getSink, lnamewrappers, hash, objBinary)):
                    dict[getaddr] = Sink(objrule, getFrom, getSink, getaddr, getAlgorithm,
                                         isEntry=entryfound[getFrom], isLib=isLib, isWrapper=False, metarule=metarule,
                                         extrameta=extrameta, isHMAC=ishmac)
                    i = 1
                    for wrappername in lnamewrappers[getSink]:
                        dict[getaddr + "-" + str(i)] = Sink(objrule, getFrom, wrappername, getaddr, getAlgorithm,
                                                            isEntry=entryfound[getFrom], isLib=isLib,
                                                            isWrapper=True, metarule=metarule, extrameta=extrameta,
                                                            isHMAC=ishmac)
                        i = i + 1
                        bupdated = True

            if bupdated == False:
                dict[getaddr] = Sink(objrule, getFrom, getSink, getaddr, getAlgorithm,
                                     isEntry=entryfound[getFrom], isLib=isLib, isWrapper=False, metarule=metarule,
                                     extrameta=extrameta, isHMAC=ishmac)

        else:
            s = dict[getaddr]
            s.algorithm.update(getAlgorithm)
            # update ref for misuse
            sink["algorithm"] = s.algorithm
            # update metarule
            s.metarule.update(metarule)
            sink["metarule"] = s.metarule
            # update extrameta
            if len(extrameta) > 0:
                for i in extrameta:
                    s.extrameta.append(i)

            sink["extrameta"] = s.extrameta.copy()

            # change hmac
            s.isHMAC |= ishmac

    def checkWrapperLib(self, getSink, lnamewrappers, hash, objBinary):
        if (getSink in lnamewrappers):

            if (hash in self.proj.crypto_libraries):
                lbinary = self.proj.crypto_libraries[hash]
                # set
                arrnames = lbinary.setofSymbolicNames
                arrnames.add(lbinary.name)

                # check if is disjoint
                if (objBinary.libraries.isdisjoint(arrnames) == False):
                    return True

        return False


def convertToHMAC(s, ast):
    if not s.isHMAC:
        return

    mapped = {'HASH_FUNCTIONS_UNKEYED': 'HASH_FUNCTIONS_KEYED',
              'HASH_FUNCTIONS_UNKEYED_CONSTANT_HASH_INPUT': 'HASH_FUNCTIONS_KEYED_CONSTANT_HASH_INPUT',
              'HASH_FUNCTIONS_UNKEYED_WEAK_DIGEST_FUN': 'HASH_FUNCTIONS_KEYED'}

    sym = getRuleMnemonic(s.rule.ruleType)
    if sym in mapped:
        # change rule id
        newruleid = CONFIGURATION.rules[mapped[sym]]
        s.rule.ruleType = newruleid

    ruleid = ast['ruleid']
    sym = getRuleMnemonic(ruleid)
    if sym in mapped:
        # change rule id
        newruleid = CONFIGURATION.rules[mapped[sym]]
        ast['ruleid'] = newruleid
        # change rule
        objrule = Rule(ast["rule"])
        objrule.ruleType = newruleid
        ast['rule'] = objrule.toString()


# TODO (FUTURE) make it more general
def checkDefinedStringsandAlgorithms(ast):
    arrsinks = ['srand', 'srand48', 'srandom']
    if ast['targetFunctionName'] in arrsinks:
        for s in ast['dstrings']:
            appends = "STR:" + str(s)
            ast['algorithm'][appends] = False

    ruleid = ast['ruleid']
    if CONFIGURATION.rules['SYMMETRIC_KEY_ENCRYPTION'] <= ruleid < (
            CONFIGURATION.rules['AUTHENTICATED_ENCRYPTION'] * 10):
        auth = ['gcm', 'ccm', 'ocb', 'chacha20_poly1305', 'cbc_hmac', 'aead']
        isauth = False
        for alg in ast['algorithm'].keys():
            for a in auth:
                if alg.__contains__(a):
                    isauth = True
                    break
            if isauth:
                break

        # change rule
        if isauth:
            mapped = {'SYMMETRIC_KEY_ENCRYPTION': 'AUTHENTICATED_ENCRYPTION',
                      'SYMMETRIC_KEY_ENCRYPTION_CONSTANT_KEYS': 'AUTHENTICATED_ENCRYPTION_CONSTANT_KEY',
                      'SYMMETRIC_KEY_ENCRYPTION_CONSTANT_IV': 'AUTHENTICATED_ENCRYPTION_CONSTANT_IV'}

            sym = getRuleMnemonic(ruleid)
            if sym in mapped:
                # change rule id
                newruleid = CONFIGURATION.rules[mapped[sym]]
                ast['ruleid'] = newruleid
                # change rule
                objrule = Rule(ast["rule"])
                objrule.ruleType = newruleid
                ast['rule'] = objrule.toString()
