import numpy
import base64
import collections
import copy
import os
import queue
import shutil
from pathlib import Path

from matplotlib import ticker
from modules.DEFINES import *
from modules.Rule import getRuleMnemonic
from modules.Version import Version
from modules.analysis import Analysis
from modules.binary import Binary
from modules.helpfunctions import createDir, mexec
from modules.log import log
import operator


def isBase64(sb):
    try:
        if isinstance(sb, str):
            # If there's any unicode here, an exception will be thrown and the function will return false
            sb_bytes = bytes(sb, 'utf-8')
        elif isinstance(sb, bytes):
            sb_bytes = sb
        else:
            raise ValueError("Argument must be string or bytes")
        return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
    except Exception:
        return False


class GlobalProject:
    def __init__(self, outputDir):
        self.outputDir = outputDir / "post-results"
        createDir(self.outputDir, False)
        # set the output log dir
        log.set_file_logs(self.outputDir)
        self.products = queue.Queue()

    def reportEmptyLOG(self):

        # list that is already check
        # possible ENCRYPTED after a particular version!
        excludelist = ["DAP-1610", 'iprobot3', 'AC9', 'AC18', 'W268R', 'NBG-318S', 'NBG334W', 'NBG318S_v2']
        for product in self.products.queue:

            if product.name in excludelist:
                continue

            first = product.isEmpty()

            for firm in product.firmwares.values():
                if firm.isEmpty() != first:
                    log.logEF("FIRMWARE PRODUCT EMPTY ERROR %s, %s " % (product.name, firm.name))

    def reportEmpty(self):

        fp = open(self.outputDir / CONFIGURATION.dict["GLOBAL_REPORT_EMPTY_PRODUCT"], "w+")

        for product in self.products.queue:
            fp.write("%s, %s, %s, %s\n" % (product.typeName, product.vendorName, product.name, product.isEmpty()))

        fp.close()

        fp = open(self.outputDir / CONFIGURATION.dict["GLOBAL_REPORT_EMPTY_FIRMWARES"], "w+")

        for product in self.products.queue:
            fp.write("%s, %s, %s, " % (product.typeName, product.vendorName, product.name))
            for firm in product.firmwares.values():
                fp.write("%s, " % (firm.name))

            fp.write("\n , , %s, " % (product.isEmpty()))

            for firm in product.firmwares.values():
                fp.write("%s, " % firm.isEmpty())

            fp.write("\n\n")

        fp.close()

    def reportTimes(self):

        fp = open(self.outputDir / CONFIGURATION.dict["GLOBAL_REPORT_TIMES"], "w+")
        fp.write(
            "Product Type, Vendor Name, Product Name, Extract Time (s), Filter Time (s), Ghidra Time (s), "
            "Analysis Time (s), Overall Time(s)\n")

        for product in self.products.queue:

            if product.isEmpty():
                continue

            fp.write("%s, %s, %s, %f, %f, %f, %f, %f\n" % (product.typeName, product.vendorName, product.name,
                                                           product.overallExtract, product.overallFilter,
                                                           product.overallGhidra, product.overallResults,
                                                           product.overallTime))

        fp.close()

    def reportStatistics(self):

        fp = open(self.outputDir / CONFIGURATION.dict["GLOBAL_REPORT_STATISTICS"], "w+")

        total_firms = 0
        total_run_firms = 0
        total_run_products = 0
        for product in self.products.queue:
            total_firms = len(product.firmwares) + total_firms
            if not product.isEmpty():
                total_run_firms = len(product.firmwares) + total_run_firms
                total_run_products = total_run_products + 1

        fp.write("Total Number of Firmwares, %d\n" % (total_firms))
        fp.write("Total Number of Products, %d\n" % (len(self.products.queue)))
        fp.write("Total Number of run Firmwares, %d\n" % (total_run_firms))
        fp.write("Total Number of run Products, %d\n\n" % (total_run_products))

        total_run_time = 0.0
        total_time = 0.0
        for product in self.products.queue:
            total_time = total_time + product.overallTime
            if product.isEmpty():
                continue
            total_run_time = total_run_time + product.overallTime

        fp.write("Total Time, %.2f, %.2f, %.2f, %.2f\n" % (
            total_time, total_time / 60, total_time / (60 * 60), total_time / (60 * 60 * 24)))
        fp.write("Total run Time, %.2f, %.2f, %.2f, %.2f\n\n" % (
            total_run_time, total_run_time / 60, total_run_time / (60 * 60), total_run_time / (60 * 60 * 24)))

        # get architectures
        carch = {}
        ctype = {}
        cendinannes = {}
        cbit = {}
        cgen = {}
        countercredentials = {}
        for product in self.products.queue:

            maxarch = maxbit = maxtype = maxendiannes = ""
            for firmware in product.firmwares.values():
                if len(firmware.counters.arch) > 0:
                    maxarch = max(firmware.counters.arch, key=lambda key: firmware.counters.arch[key])
                    maxbit = max(firmware.counters.bit, key=lambda key: firmware.counters.bit[key])
                    maxtype = max(firmware.counters.file, key=lambda key: firmware.counters.file[key])
                    maxendiannes = max(firmware.counters.endianness, key=lambda key: firmware.counters.endianness[key])
                    break

            for key, count in product.countercredentials.items():
                if key not in countercredentials:
                    countercredentials[key] = 0

                countercredentials[key] = countercredentials[key] + count

            if (maxarch == ""):
                continue

            strgen = maxarch + "-" + maxbit + "-" + maxendiannes + "-" + maxtype
            if (strgen not in cgen):
                cgen[strgen] = 0

            cgen[strgen] = cgen[strgen] + 1

            if (maxarch not in carch):
                carch[maxarch] = 0
            carch[maxarch] = carch[maxarch] + 1

            if (maxbit not in cbit):
                cbit[maxbit] = 0
            cbit[maxbit] = cbit[maxbit] + 1

            if (maxtype not in ctype):
                ctype[maxtype] = 0
            ctype[maxtype] = ctype[maxtype] + 1

            if (maxendiannes not in cendinannes):
                cendinannes[maxendiannes] = 0
            cendinannes[maxendiannes] = cendinannes[maxendiannes] + 1

        fp.write("\nGeneral diff:\n")
        for key, count in cgen.items():
            fp.write("\t%s: %d\n" % (key, count))

        fp.write("\nDiff Architectures:\n")
        for key, count in carch.items():
            fp.write("\t%s: %d\n" % (key, count))

        fp.write("\nDiff Endianness:\n")
        for key, count in cendinannes.items():
            fp.write("\t%s: %d\n" % (key, count))

        fp.write("\nDiff Bits:\n")
        for key, count in cbit.items():
            fp.write("\t%s: %d\n" % (key, count))

        fp.write("\nDiff types:\n")
        for key, count in ctype.items():
            fp.write("\t%s: %d\n" % (key, count))

        fp.write("\nDiff Credentials:\n")
        for key, count in countercredentials.items():
            fp.write("\t%s: %d\n" % (key, count))

        # Print MISUSES!
        fp.write("\nFor products:\n")
        counterRules = copy.copy(CONFIGURATION.rules)
        for key in counterRules.keys():
            counterRules[key] = 0

        counterNoviolationP = 0
        for product in self.products.queue:
            if product.isEmpty():
                continue
            isViolation = False
            for key, value in product.usedDict.items():
                if (CONFIGURATION.rules[key] < 10):
                    continue
                if (value == True):
                    counterRules[key] = counterRules[key] + 1
                    if key == "PSEUDORANDOM_NUMBER_GENERATORS_WEAK_PRNG":
                        continue
                    isViolation = True

            if isViolation == False:
                counterNoviolationP = counterNoviolationP + 1

        for key, value in counterRules.items():
            if (CONFIGURATION.rules[key] < 10):
                continue
            fp.write("%s , %d\n" % (key, value))

        fp.write("NO VIOLATION, %d\n" % counterNoviolationP)

        fp.write("\nFor firmwares:\n")
        counterRules = copy.copy(CONFIGURATION.rules)
        for key in counterRules.keys():
            counterRules[key] = 0

        counterNoviolationF = 0
        for product in self.products.queue:
            for firm in product.firmwares.values():
                if firm.isEmpty():
                    continue

                isViolation = False
                for key, value in firm.usedDict.items():
                    if (CONFIGURATION.rules[key] < 10):
                        continue
                    if (value == True):
                        counterRules[key] = counterRules[key] + 1
                        if key == "PSEUDORANDOM_NUMBER_GENERATORS_WEAK_PRNG":
                            continue
                        isViolation = True

                if isViolation == False:
                    counterNoviolationF = counterNoviolationF + 1

        for key, value in counterRules.items():
            if (CONFIGURATION.rules[key] < 10):
                continue
            fp.write("%s , %d\n" % (key, value))

        fp.write("NO VIOLATION, %d\n" % counterNoviolationF)

        fp.write("\n")
        fp.write("\n")

        uniqueConstants = copy.copy(CONFIGURATION.rules)
        for key in uniqueConstants.keys():
            uniqueConstants[key] = set()

        for product in self.products.queue:
            for key, sv in product.uniqueConstant.items():
                for v in sv:
                    uniqueConstants[key].add(v)

        for key, vs in uniqueConstants.items():
            fp.write(key + ", ")
            for v in vs:
                if isBase64(v):
                    if isinstance(v, str):
                        # If there's any unicode here, an exception will be thrown and the function will return false
                        sb_bytes = bytes(v, 'utf-8')
                    elif isinstance(v, bytes):
                        sb_bytes = v
                    fp.write("%s (%s) ," % (v, base64.b64decode(sb_bytes)))
                else:
                    fp.write("%s ," % v)
            fp.write("\n")

        fp.close()

    def reportMisuse(self):

        fp = open(self.outputDir / CONFIGURATION.dict["GLOBAL_REPORT_RULES_MATRIX"], "w+")
        fp.write("\n")
        columnheader = set()
        for key, value in CONFIGURATION.rules.items():
            columnheader.add(key)

        scolumnheader = sorted(columnheader)

        fp.write(", , , %s\n" % (", ".join(scolumnheader)))

        # report misuses in products
        for product in self.products.queue:
            fp.write("%s, %s, %s, " % (product.typeName, product.vendorName, product.name))
            for key in scolumnheader:
                wstr = "0"
                if (product.usedDict[key] == True):
                    wstr = "1"
                fp.write("%s ," % (wstr))
            fp.write("\n")

        fp.close()
