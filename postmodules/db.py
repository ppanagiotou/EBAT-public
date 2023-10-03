import argparse
import collections
import re
import shutil
import sqlite3
import os

# database defaults
import statistics
import sys
from datetime import datetime
from pathlib import Path

try:
    import ssdeep
except:
    print("ignoring for now...")
    pass

from modules.DEFINES import CONFIGURATION
from modules.Rule import getRuleMnemonic, getMappedKey
from modules.helpfunctions import createDir
from postmodules.dbhelp import hashfirmware, hashproduct, maptypes

DISK_LOCATION_DEFAULT = os.path.join(os.path.expanduser("~"), ".cache", "EBAT")


class GlobalDB:
    CACHEDIR = DISK_LOCATION_DEFAULT

    def __init__(self, argname="", disk_location=DISK_LOCATION_DEFAULT):

        if argname != "":
            DBNAME = argname + "_global.db"
        else:
            DBNAME = "global.db"

        # save database name
        self.db_only_name = DBNAME

        # vendor name
        self.vendorName = argname

        # set up the db if needed
        self.disk_location = disk_location
        self.dbname = os.path.join(self.disk_location, DBNAME)
        self.connection = None

        os.makedirs(self.disk_location, exist_ok=True)

        self.outputDir = None

    def init_database(self):
        """ Initialize db tables used for storing cve/version data """
        conn = sqlite3.connect(self.dbname)
        db_cursor = conn.cursor()

        table = """CREATE TABLE IF NOT EXISTS products (
        pid TEXT NOT NULL,
        name TEXT NOT NULL,
        vendor TEXT NOT NULL,
        type TEXT NOT NULL,
        PRIMARY KEY(pid)
        )
        """
        db_cursor.execute(table)

        table = """CREATE TABLE IF NOT EXISTS firmwares (
        fid TEXT NOT NULL,
        name TEXT NOT NULL,
        date DATE NOT NULL,
        unpackReason TEXT NOT NULL,
        PRIMARY KEY(fid)
        )
        """
        db_cursor.execute(table)

        table = """CREATE TABLE IF NOT EXISTS pidfidmap (
        pid TEXT NOT NULL,
        fid TEXT NOT NULL,
        PRIMARY KEY(fid, pid),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        table = """CREATE TABLE IF NOT EXISTS binaries (
        hashcode TEXT NOT NULL,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        filetype INTEGER NOT NULL,
        arch INTEGER NOT NULL,
        lbit INTEGER NOT NULL,
        endianess INTEGER NOT NULL,
        cryptolibs TEXT NOT NULL,
        libraries TEXT NOT NULL,
        location TEXT NOT NULL,
        ssdeep TEXT NOT NULL,
        hardening TEXT NOT NULL,
        pid TEXT NOT NULL,
        fid TEXT NOT NULL,
        oldfid TEXT NOT NULL,
        PRIMARY KEY(hashcode,fid, pid),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid),
        FOREIGN KEY(oldfid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        table = """CREATE TABLE IF NOT EXISTS timelog (
        overall FLOAT NOT NULL,
        extract FLOAT NOT NULL,
        filter FLOAT NOT NULL,
        cveandlibs FLOAT NOT NULL,
        ghidralibs FLOAT NOT NULL,
        ghidraexec FLOAT NOT NULL,
        pid TEXT NOT NULL,
        fid TEXT NOT NULL,
        PRIMARY KEY(fid, pid),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        table = """CREATE TABLE IF NOT EXISTS libraries (
        hashcode INTEGER NOT NULL,
        fid TEXT NOT NULL,
        pid TEXT NOT NULL,
        version TEXT NOT NULL,
        type TEXT NOT NULL,
        foundwith INT NOT NULL,
        PRIMARY KEY(hashcode, fid, pid, type, version, foundwith),
        FOREIGN KEY(hashcode) REFERENCES binaries(hashcode),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        table = """CREATE TABLE IF NOT EXISTS cve (
        fid TEXT NOT NULL,
        pid TEXT NOT NULL,
        hashcode TEXT NOT NULL,
        product TEXT NOT NULL,
        version TEXT NOT NULL,
        cve_number TEXT NOT NULL,
        severity TEXT NOT NULL,
        publishdate DATE,
        score INTEGER,
        cvss_version INTEGER,
        foundwith INT NOT NULL,
        PRIMARY KEY(cve_number, hashcode, version, fid, pid, foundwith),
        FOREIGN KEY(hashcode) REFERENCES binaries(hashcode),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        table = """CREATE TABLE IF NOT EXISTS credentials (
        indexid INTEGER NOT NULL,
        name TEXT NOT NULL,
        location TEXT NOT NULL,
        type TEXT NOT NULL,
        hashcode TEXT NOT NULL,
        output TEXT NOT NULL,
        pid TEXT NOT NULL,
        fid TEXT NOT NULL,
        PRIMARY KEY(indexid, hashcode, fid, pid),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        table = """CREATE TABLE IF NOT EXISTS allsinks (
        rule TEXT NOT NULL,
        ruleid TEXT NOT NULL,
        targetFunction TEXT NOT NULL,
        address TEXT NOT NULL,
        callerFunction TEXT NOT NULL,
        algorithms TEXT NOT NULL,
        isPhi_algorithms TEXT NOT NULL,
        isLib INTEGER NOT NULL,
        isEntry INTEGER NOT NULL,
        isWrapper INTEGER NOT NULL,
        hashcode TEXT NOT NULL,
        pid TEXT NOT NULL,
        fid TEXT NOT NULL,
        PRIMARY KEY(address, hashcode, fid, pid),
        FOREIGN KEY(hashcode) REFERENCES binaries(hashcode),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        table = """CREATE TABLE IF NOT EXISTS allmisuses (
        rule TEXT NOT NULL,
        ruleid TEXT NOT NULL,
        ruleType TEXT NOT NULL,
        argument INTEGER NOT NULL,
        constAddress TEXT NOT NULL,
        constValue TEXT NOT NULL,
        isPhi INTEGER NOT NULL,
        targetFunction TEXT NOT NULL,
        address TEXT NOT NULL,
        callerFunction TEXT NOT NULL,
        hashcode TEXT NOT NULL,
        pid TEXT NOT NULL,
        fid TEXT NOT NULL,
        PRIMARY KEY(ruleid, constValue, argument, address, hashcode, fid, pid),
        FOREIGN KEY(address, hashcode, fid, pid) REFERENCES allsinks(address, hashcode, fid, pid),
        FOREIGN KEY(hashcode) REFERENCES binaries(hashcode),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        table = """CREATE TABLE IF NOT EXISTS groupsinks (
        library TEXT,
        algorithm TEXT,
        keysize INTEGER,
        ivsize INTEGER,
        modeofoperation TEXT,
        isEncrypt INTEGER,
        isVerify INTEGER,
        targetFunction TEXT NOT NULL,
        isPhi INTEGER,
        address TEXT NOT NULL,
        hashcode TEXT NOT NULL,
        pid TEXT NOT NULL,
        fid TEXT NOT NULL,
        PRIMARY KEY(targetFunction, algorithm, address, hashcode, fid, pid, keysize, ivsize, modeofoperation, 
        isEncrypt, isVerify, isPhi),
        FOREIGN KEY(address, hashcode, fid, pid) REFERENCES allsinks(address, hashcode, fid, pid),
        FOREIGN KEY(hashcode) REFERENCES binaries(hashcode),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        table = """CREATE TABLE IF NOT EXISTS entries (
        function TEXT NOT NULL,
        fromentry INT NOT NULL,
        hashcode TEXT NOT NULL,
        pid TEXT NOT NULL,
        fid TEXT NOT NULL,
        PRIMARY KEY(function, hashcode, fid, pid),
        FOREIGN KEY(hashcode) REFERENCES binaries(hashcode),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        table = """CREATE TABLE IF NOT EXISTS cfg (
        cfg TEXT NOT NULL,
        vertexset TEXT NOT NULL,
        edgeset TEXT NOT NULL,
        hashcode TEXT NOT NULL,
        pid TEXT NOT NULL,
        fid TEXT NOT NULL,
        PRIMARY KEY(hashcode, fid, pid),
        FOREIGN KEY(hashcode) REFERENCES binaries(hashcode),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        table = """CREATE TABLE IF NOT EXISTS yaracrypto (
        cryptoconstants TEXT NOT NULL,
        strings TEXT NOT NULL,
        hashcode TEXT NOT NULL,
        pid TEXT NOT NULL,
        fid TEXT NOT NULL,
        PRIMARY KEY(hashcode, fid, pid),
        FOREIGN KEY(hashcode) REFERENCES binaries(hashcode),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        # TODO: (FUTURE) check what we want to save
        table = """CREATE TABLE IF NOT EXISTS cwe (
        cwe TEXT NOT NULL,
        hashcode TEXT NOT NULL,
        pid TEXT NOT NULL,
        fid TEXT NOT NULL,
        PRIMARY KEY(hashcode, fid, pid),
        FOREIGN KEY(hashcode) REFERENCES binaries(hashcode),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        table = """CREATE TABLE IF NOT EXISTS otherbinaries (
        hashcode TEXT NOT NULL,
        name TEXT NOT NULL,
        location TEXT NOT NULL,
        pid TEXT NOT NULL,
        fid TEXT NOT NULL,
        oldfid TEXT NOT NULL,
        PRIMARY KEY(hashcode,fid, pid),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid),
        FOREIGN KEY(oldfid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        table = """CREATE TABLE IF NOT EXISTS othercve (
        fid TEXT NOT NULL,
        pid TEXT NOT NULL,
        hashcode TEXT NOT NULL,
        product TEXT NOT NULL,
        version TEXT NOT NULL,
        cve_number TEXT NOT NULL,
        severity TEXT NOT NULL,
        publishdate DATE,
        score INTEGER,
        cvss_version INTEGER,
        PRIMARY KEY(cve_number, hashcode, fid, pid),
        FOREIGN KEY(hashcode) REFERENCES otherbinaries(hashcode),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        table = """CREATE TABLE IF NOT EXISTS otherlibraries (
        hashcode INTEGER NOT NULL,
        fid TEXT NOT NULL,
        pid TEXT NOT NULL,
        version TEXT NOT NULL,
        type TEXT NOT NULL,
        PRIMARY KEY(hashcode, fid, pid, type, version),
        FOREIGN KEY(hashcode) REFERENCES otherbinaries(hashcode),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        conn.commit()
        self.connection = conn
        return conn

    def delete_database(self):
        if os.path.exists(self.dbname):
            os.remove(self.dbname)

    def initTables(self):
        """ Initialize db extra tables """
        conn = sqlite3.connect(self.dbname)
        db_cursor = conn.cursor()

        table = """CREATE TABLE IF NOT EXISTS librariesDates (
        hashcode INTEGER NOT NULL,
        fid TEXT NOT NULL,
        pid TEXT NOT NULL,
        version TEXT NOT NULL,
        type TEXT NOT NULL,
        foundwith INT NOT NULL,
        publishdate DATE NOT NULL,
        eol DATE,
        PRIMARY KEY(hashcode, fid, pid),
        FOREIGN KEY(hashcode) REFERENCES binaries(hashcode),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        table = """CREATE TABLE IF NOT EXISTS updatetable (
        percentage FLOAT NOT NULL,
        pid TEXT NOT NULL,
        fid TEXT NOT NULL,
        PRIMARY KEY(fid, pid),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        table = """CREATE TABLE IF NOT EXISTS cupdatetable (
        percentage FLOAT NOT NULL,
        pid TEXT NOT NULL,
        fid TEXT NOT NULL,
        PRIMARY KEY(fid, pid),
        FOREIGN KEY(pid) REFERENCES products(pid),
        FOREIGN KEY(fid) REFERENCES firmwares(fid)
        )
        """
        db_cursor.execute(table)

        conn.commit()
        self.connection = conn
        return conn

    def delete_database(self):
        if os.path.exists(self.dbname):
            os.remove(self.dbname)

    def open(self, tomemory=False):

        if tomemory:
            print("Opening connection to memory for", self.dbname)
            # open a connection in memory
            source = sqlite3.connect(self.dbname)
            try:
                dst = sqlite3.connect(':memory:')
                source.backup(dst)
            except:
                print("DATABASE NOT OPEN TO MEMORY SUCCESSFULLY")
                print("--------------------------------------")
                print(self.dbname)
                print("--------------------------------------")
                exit(1)

            self.connection = dst
        else:
            """ Opens connection to sqlite database."""
            self.connection = sqlite3.connect(self.dbname)

    def closeDB(self):
        if self.connection is not None:
            print("Closing db for", self.dbname, flush=True)
            self.connection.close()

    def populate_db(self, qproduct):

        if self.connection is None:
            self.open()

        cursor = self.connection.cursor()

        q = "INSERT or REPLACE INTO products(pid, name, vendor, type) VALUES (?, ?, ?, ?)"
        for product in qproduct:
            pcounter = hashproduct(product)
            cursor.execute(
                q,
                [
                    pcounter,
                    product.name,
                    product.vendorName,
                    product.typeName,
                ],
            )

            oldfcounter = {}
            for firm in product.firmwares.values():

                if firm.releaseDate is None:
                    # defaults date
                    firm.releaseDate = datetime.strptime("01/01/1970", '%d/%m/%Y')

                fcounter = hashfirmware(product, firm)
                oldfcounter[firm.firmwareName] = fcounter
                qf = "INSERT or REPLACE INTO firmwares(fid, name, date, unpackReason, pid) VALUES (?, ?, ?, ?, ?)"
                cursor.execute(
                    qf,
                    [
                        fcounter,
                        firm.firmwareName,
                        firm.releaseDate,
                        # convert to set with ast.literal_eval
                        str(firm.unpackresults),
                        pcounter,
                    ],
                )

                self.init_binaries(firm, cursor, pcounter, fcounter, oldfcounter)
                self.init_times(firm, cursor, pcounter, fcounter)
                # self.init_rules(firm, cursor, pcounter, fcounter)
                self.init_credentials(firm, cursor, pcounter, fcounter)

                # update analysis tables
                self.init_anaysis(firm, cursor, pcounter, fcounter)

        self.connection.commit()

    def init_anaysis(self, firm, cursor, pcounter, fcounter):

        q = "INSERT or REPLACE INTO allsinks(rule, ruleid, sinkFunction, address, callerFunction, algorithms, isPhi_algorithms, isLib, isEntry, " \
            "isWrapper, hashcode, fid, pid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

        for hashcode, d in firm.analysis.uniqueSinks.items():
            for address, obj in d.items():
                cursor.execute(
                    q,
                    [
                        obj.rule.toString(),
                        getRuleMnemonic(obj.rule.ruleType),
                        obj.sinkFunc,
                        address,
                        obj.fromFunc,
                        ";".join(obj.algorithm.keys()),
                        ";".join([str(i) for i in obj.algorithm.values()]),
                        obj.isLib,
                        obj.isEntry,
                        obj.isWrapper,
                        hashcode,
                        fcounter,
                        pcounter,
                    ],
                )

        q = "INSERT or REPLACE INTO groupsinks(library, algorithm, keysize, ivsize, modeofoperation, isEncrypt, isVerify, " \
            "sinkFunction, address, hashcode, fid, pid) " \
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

        for hashcode, d in firm.analysis.uniqueSinks.items():
            for address, obj in d.items():
                for cr in obj.cryptoGroup:
                    cursor.execute(
                        q,
                        [
                            cr.library,
                            getMappedKey(cr.algorithm, CONFIGURATION.algorithms),
                            cr.keysize,
                            cr.ivsize,
                            cr.modeofoperation,
                            cr.isEncrypt,
                            cr.isVerify,
                            cr.funcName,
                            address,
                            hashcode,
                            fcounter,
                            pcounter,
                        ],

                    )

        q = "INSERT or REPLACE INTO allmisuses(rule, ruleid, ruleType, argument, constAddress, constValue, isPhi, " \
            "sinkFunction, address, callerFunction, hashcode, fid, pid) " \
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

        for hashcode, lmisuserules in firm.analysis.misuseRules.items():
            for absrule in lmisuserules.values():
                for objmis in absrule.abstract:
                    cursor.execute(
                        q,
                        [
                            absrule.rule.toString(),
                            getRuleMnemonic(objmis.ruleID),
                            objmis.ruleType,
                            objmis.getArg,
                            str(objmis.constAddress),
                            str(objmis.constValue),
                            objmis.isPhi,
                            objmis.sinkFunc,
                            str(objmis.atAddress),
                            objmis.fromFunc,
                            hashcode,
                            fcounter,
                            pcounter,
                        ],
                    )

        q = "INSERT or REPLACE INTO entries(function, fromentry, hashcode, fid, pid) VALUES (?, ?, ?, ?, ?)"

        for hashcode, lentries in firm.analysis.entries.items():
            for func, fromentry in lentries.items():
                cursor.execute(
                    q,
                    [
                        func,
                        fromentry,
                        hashcode,
                        fcounter,
                        pcounter,
                    ],
                )

    def init_rules(self, firm, cursor, pcounter, fcounter):

        for r, item in firm.usedDict.items():
            q = "INSERT or REPLACE INTO ruletable(rule, violated, pid, fid) " \
                "VALUES (?, ?, ?, ?)"
            cursor.execute(
                q,
                [
                    r,
                    item,
                    pcounter,
                    fcounter,
                ],
            )

    def init_times(self, firm, cursor, pcounter, fcounter):

        q = "INSERT or REPLACE INTO timelog(overall, extract, filter, cveandlibs, ghidralibs, ghidraexec, pid, fid) " \
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        cursor.execute(
            q,
            [
                firm.times.overall,
                firm.times.extract,
                firm.times.filter,
                firm.times.cveandlibs,
                firm.times.ghidralibs,
                firm.times.ghidraexec,
                pcounter,
                fcounter,
            ],
        )

    def init_credentials(self, firm, cursor, pcounter, fcounter):

        q = "INSERT or REPLACE INTO credentials(indexid, type, output, name, location, hashcode, pid, fid) " \
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"

        for hashcode, cred in firm.credentials.items():
            for index, type in cred.type.items():
                t = cred.getMnemonic(cred.type[index])
                try:
                    retstr = str(cred.output[index].decode('utf-8')) + "\n"
                except:
                    retstr = str(cred.output[index]) + "\n"

                cursor.execute(
                    q,
                    [
                        index,
                        t,
                        retstr,
                        cred.name,
                        str(cred.copyLocation),
                        hashcode,
                        pcounter,
                        fcounter,
                    ],
                )

    def init_binaries(self, firm, cursor, pcounter, fcounter, oldfcounter):

        for binary in firm.allbinaries.values():
            # safety feature because of fixes in release files
            oldfc = fcounter
            if binary.firmwareName in oldfcounter:
                oldfc = oldfcounter[binary.firmwareName]

            qb = "INSERT or REPLACE INTO binaries(hashcode, name, type, filetype, arch, lbit, endianess, " \
                 "cryptolibs, libraries, location, ssdeep, hardening, pid, fid, oldfid) " \
                 "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            cursor.execute(
                qb,
                [
                    binary.hashcode,
                    binary.name,
                    binary.getTypeMnemonic(),
                    binary.getFileMnemonic(),
                    binary.arch,
                    binary.getBitMnemonic(),
                    binary.getEndiannessMnemonic(),
                    "; ".join(binary.vcrypto),
                    "; ".join(binary.libraries),
                    binary.location,
                    binary.hashssdeep,
                    str(binary.security_hard),
                    pcounter,
                    fcounter,
                    oldfc,
                ],
            )

            # update Libraries
            if binary.version is not None:
                ql = "INSERT or REPLACE INTO libraries(hashcode, fid, pid, version, type, foundwith) " \
                     "VALUES (?, ?, ?, ?, ?, ?)"
                cursor.execute(
                    ql,
                    [
                        binary.hashcode,
                        fcounter,
                        pcounter,
                        binary.version.VersionToString(),
                        binary.version.getMnemonic(),
                        binary.version.where,
                    ],
                )

            if len(binary.crypto_constants) > 0:
                ql = "INSERT or REPLACE INTO yaracrypto(cryptoconstants, hashcode, fid, pid) " \
                     "VALUES (?, ?, ?, ?)"
                cursor.execute(
                    ql,
                    [
                        str(binary.crypto_constants),
                        binary.hashcode,
                        fcounter,
                        pcounter,
                    ],
                )

            if binary.cve is not None:
                # save to database
                ql = "INSERT or REPLACE INTO cve(hashcode, fid, pid, product, version, cve_number, severity, publishdate) " \
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"

                for item in binary.cve:

                    if item['cve_number'] == "UNKNOWN":
                        continue

                    cursor.execute(
                        ql,
                        [
                            binary.hashcode,
                            fcounter,
                            pcounter,
                            item['package'],
                            item['version'],
                            item['cve_number'],
                            item['severity'],
                            item["publishdate"],
                        ],
                    )

    def updateDatabase(self, firmwareEmptyList, firmwarePartialyList):
        self.initTables()
        self.initCryptoLibrariesDates()
        self.updateGlobalUpdatePercentage(firmwareEmptyList, firmwarePartialyList)
        self.updateCryptoUpdatePercentage(firmwareEmptyList, firmwarePartialyList)

    def updateGlobalUpdatePercentage(self, firmwareEmptyList, firmwarePartialyList):

        if self.connection is None:
            self.open()

        print("\nInit Global code update percentage:", self.dbname)

        cursor = self.connection.cursor()
        query = """SELECT pid type FROM products"""

        cursor.execute(query)
        allproducts = cursor.fetchall()
        currentp = 0
        for product in allproducts:
            pid = product[0]

            currentp = currentp + 1
            print("\r %d%% " % ((currentp / len(allproducts)) * 100), end="")

            # query = """SELECT fid, date FROM firmwares WHERE pid = ? ORDER by date DESC"""
            query = """SELECT firmwares.fid, firmwares.date FROM firmwares INNER JOIN pidfidmap 
            ON pidfidmap.pid = ?
            AND pidfidmap.fid = firmwares.fid  ORDER BY firmwares.date DESC"""
            cursor.execute(query, [pid])

            firmwares = cursor.fetchall()

            for firm in firmwares:
                cfid = firm[0]
                cfirmwareDate = datetime.strptime(firm[1], "%Y-%m-%d %X")

                if cfid in firmwareEmptyList or cfid in firmwarePartialyList:
                    continue

                # get all binaries
                query = """SELECT hashcode, ssdeep  FROM binaries WHERE fid = ?"""
                cursor.execute(query, [cfid])
                cbinaries = cursor.fetchall()

                # no binaries found discard to next one
                if len(cbinaries) == 0:
                    continue

                # for every other firmware
                dpercentage = {}
                for firm in firmwares:
                    fid = firm[0]
                    firmwareDate = datetime.strptime(firm[1], "%Y-%m-%d %X")

                    if fid in firmwareEmptyList or fid in firmwarePartialyList:
                        continue

                    # continue to older firmware
                    if firmwareDate >= cfirmwareDate:
                        continue

                    # found an new one get all binaries
                    query = """SELECT hashcode, ssdeep  FROM binaries WHERE fid = ?"""
                    cursor.execute(query, [fid])
                    binaries = cursor.fetchall()

                    # if no binaries found discard to next one
                    if len(binaries) == 0:
                        continue

                    ldpercentage = {}
                    for cbinary in cbinaries:

                        chashcode = cbinary[0]
                        csignature = cbinary[1]

                        percentage = 0
                        # check if we have the same digest
                        for binary in binaries:
                            hashcode = binary[0]

                            if chashcode == hashcode:
                                percentage = 100

                        if percentage != 100:
                            maxscore = 0
                            # check fuzzy hashing
                            for binary in binaries:
                                signature = binary[1]
                                # compare with ssdeep
                                score = ssdeep.compare(csignature, signature)
                                if score > maxscore:
                                    maxscore = score

                            percentage = maxscore

                        ldpercentage[chashcode] = percentage

                    # from ldpercentage to dpercentage (for all older firmwares get maximum similarity)
                    for hashcode, percentage in ldpercentage.items():
                        if hashcode not in dpercentage:
                            dpercentage[hashcode] = percentage

                        dpercentage[hashcode] = max(dpercentage[hashcode], percentage)

                totalpercentage = 0
                if len(dpercentage) > 0:
                    for hashcode, percentage in dpercentage.items():
                        totalpercentage = percentage + totalpercentage

                    totalpercentage = totalpercentage / len(dpercentage)

                if len(cbinaries) != 0:
                    q = "INSERT OR REPLACE INTO updatetable(fid, pid, percentage) VALUES (?, ?, ?)"
                    cursor.execute(
                        q,
                        [
                            cfid,
                            pid,
                            totalpercentage,
                        ],
                    )

        self.connection.commit()

    # same as global just filter only crypto binaries
    def updateCryptoUpdatePercentage(self, firmwareEmptyList, firmwarePartialyList):

        if self.connection is None:
            self.open()

        print("\nInit crypto code update percentage:", self.dbname)

        cursor = self.connection.cursor()
        query = """SELECT pid type FROM products"""

        cursor.execute(query)
        allproducts = cursor.fetchall()
        currentp = 0
        for product in allproducts:
            pid = product[0]

            currentp = currentp + 1
            print("\r %d%% " % ((currentp / len(allproducts)) * 100), end="")

            # query = """SELECT fid, date FROM firmwares WHERE pid=? ORDER by date DESC"""
            query = """SELECT firmwares.fid, firmwares.date FROM firmwares INNER JOIN pidfidmap 
            ON pidfidmap.pid = ?
            AND pidfidmap.fid = firmwares.fid  ORDER BY firmwares.date DESC"""
            cursor.execute(query, [pid])

            firmwares = cursor.fetchall()

            for firm in firmwares:
                cfid = firm[0]
                cfirmwareDate = datetime.strptime(firm[1], "%Y-%m-%d %X")

                if cfid in firmwareEmptyList or cfid in firmwarePartialyList:
                    continue

                query = """SELECT hashcode, ssdeep  FROM binaries WHERE fid=? AND (type=? OR type=?)"""
                cursor.execute(query, [cfid, "EXECUTABLE - Crypto", "LIBRARY - Crypto"])
                cbinaries = cursor.fetchall()

                if len(cbinaries) == 0:
                    continue

                dpercentage = {}
                for firm in firmwares:
                    fid = firm[0]
                    firmwareDate = datetime.strptime(firm[1], "%Y-%m-%d %X")

                    if fid in firmwareEmptyList or fid in firmwarePartialyList:
                        continue

                    if firmwareDate >= cfirmwareDate:
                        continue

                    query = """SELECT hashcode, ssdeep FROM binaries WHERE fid=? """
                    cursor.execute(query, [fid])
                    binaries = cursor.fetchall()

                    if len(binaries) == 0:
                        continue

                    ldpercentage = {}
                    for cbinary in cbinaries:

                        chashcode = cbinary[0]
                        csignature = cbinary[1]

                        percentage = 0
                        # check if we have the same digest
                        for binary in binaries:
                            hashcode = binary[0]

                            if chashcode == hashcode:
                                percentage = 100

                        if percentage != 100:
                            maxscore = 0
                            # check fuzzy hashing
                            for binary in binaries:
                                signature = binary[1]
                                # compare with ssdeep
                                score = ssdeep.compare(csignature, signature)
                                if score > maxscore:
                                    maxscore = score

                            percentage = maxscore

                        ldpercentage[chashcode] = percentage

                    # from ldpercentage to dpercentage (for all older firmwares get maximum similarity)
                    for hashcode, percentage in ldpercentage.items():
                        if hashcode not in dpercentage:
                            dpercentage[hashcode] = percentage

                        dpercentage[hashcode] = max(dpercentage[hashcode], percentage)

                totalpercentage = 0
                if len(dpercentage) > 0:
                    for hashcode, percentage in dpercentage.items():
                        totalpercentage = percentage + totalpercentage

                    totalpercentage = totalpercentage / len(dpercentage)

                if len(cbinaries) != 0:
                    q = "INSERT OR REPLACE INTO cupdatetable(fid, pid, percentage) VALUES (?, ?, ?)"
                    cursor.execute(
                        q,
                        [
                            cfid,
                            pid,
                            totalpercentage,
                        ],
                    )

        self.connection.commit()

    def open_to_memory(self):
        if self.connection is None:
            self.open(tomemory=True)

    def init_directories(self, options):
        if self.connection is None:
            self.open()

        cursor = self.connection.cursor()
        query = """SELECT pid, name, vendor, type FROM products"""

        cursor.execute(query)
        allproducts = cursor.fetchall()
        self.outputDir = Path(os.path.abspath(options.output))

        #if self.outputDir.exists():
        #    shutil.rmtree(self.outputDir)

        createDir(self.outputDir / "CVEs", False)
        createDir(self.outputDir / "Libraries", False)
        createDir(self.outputDir / "JSON", False)

        for product in allproducts:
            pid = product[0]
            productName = product[1]
            productVendor = product[2]
            productType = product[3]

            createDir(self.outputDir / "Firmwares" / productType / productVendor / productName, False)
            createDir(self.outputDir / "Vendors" / productVendor, False)

    def initCryptoLibrariesDates(self):

        if self.connection is None:
            self.open()

        cursor = self.connection.cursor()

        print("\nInit Libraries Dates for:", self.dbname)

        query = """SELECT pid FROM products"""

        setothers = set()

        cursor.execute(query)
        allproducts = cursor.fetchall()
        currentp = 0
        for product in allproducts:
            pid = product[0]

            currentp = currentp + 1
            print("\r %d%% " % ((currentp / len(allproducts)) * 100), end="")

            query = """SELECT firmwares.fid, firmwares.date FROM firmwares INNER JOIN pidfidmap 
            ON pidfidmap.pid = ?
            AND pidfidmap.fid = firmwares.fid ORDER BY firmwares.date"""
            # query = """SELECT fid, date  FROM firmwares WHERE pid = ? """
            cursor.execute(query, [pid])

            firmwares = cursor.fetchall()
            for firm in firmwares:
                fid = firm[0]
                firmwareDate = datetime.strptime(firm[1], "%Y-%m-%d %X")

                query = """SELECT libraries.hashcode, libraries.version, libraries.type, libraries.foundwith 
                FROM libraries INNER JOIN binaries ON 
                binaries.pid = libraries.pid AND binaries.fid = libraries.fid AND binaries.hashcode = libraries.hashcode
                AND (binaries.type = 'LIBRARY - Crypto' OR binaries.type = 'LIBRARY')
                WHERE libraries.fid = ?"""
                cursor.execute(query, [fid])
                libs = cursor.fetchall()

                if len(libs) == 0:
                    continue

                for lib in libs:
                    hashcode = lib[0]
                    version = lib[1]
                    libtype = lib[2]
                    foundwith = lib[3]

                    # discards libraries with yara signatures
                    if foundwith == 3:
                        continue

                    if libtype == "Libmcrypt":
                        libtype = "MCRYPT"

                    if libtype not in maptypes:
                        setothers.add(libtype)
                        continue

                    if version == "..":
                        continue

                    dname = maptypes[libtype]

                    # adding fips support
                    hasChanged = False
                    prevVersion = version
                    if dname == "openssl-release":
                        # Ok remove fips
                        if version.endswith("-fips"):
                            version = version.replace("-fips", "")
                            hasChanged = True

                    publishdate = None
                    eol = None
                    try:
                        publishdate = CONFIGURATION.libsrelease[dname][version][0]
                        eol = CONFIGURATION.libsrelease[dname][version][1]
                    except:
                        print("Error version", version, dname)
                        continue

                    if hasChanged:
                        version = prevVersion

                    if publishdate is not None:

                        if publishdate >= firmwareDate:
                            print("publishdate >= firmwareDate", fid, pid, version, dname, publishdate, firmwareDate)
                            continue

                        assert publishdate <= firmwareDate

                    q = """INSERT OR REPLACE INTO librariesDates(hashcode, fid, pid, version, type, 
                                foundwith, publishdate, eol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"""

                    cursor.execute(
                        q,
                        [
                            hashcode,
                            fid,
                            pid,
                            version,
                            libtype,
                            foundwith,
                            publishdate,
                            eol,
                        ],
                    )

        print("\nNot found set dates:", setothers)

        self.connection.commit()
