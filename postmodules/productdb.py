import sqlite3
import os

# database defaults
from datetime import datetime
from modules.DEFINES import CONFIGURATION, DEFINES
from modules.Rule import getRuleMnemonic, getMappedKey
from postmodules.dbhelp import hashproduct, hashfirmware

DISK_LOCATION_DEFAULT = os.path.join(os.path.expanduser("~"), ".cache", "EBAT")
DBNAME = "product.db"


class ProductDB:
    CACHEDIR = DISK_LOCATION_DEFAULT

    def __init__(self, location=""):

        if location != "":
            self.disk_location = location
        else:
            # set up the db if needed
            self.disk_location = DISK_LOCATION_DEFAULT
        self.dbname = os.path.join(self.disk_location, DBNAME)
        self.connection = None

        os.makedirs(self.disk_location, exist_ok=True)

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

    def open(self):
        """ Opens connection to sqlite database."""
        self.connection = sqlite3.connect(self.dbname)

    def populate_db(self, qproduct):

        if self.connection is None:
            self.open()

        cursor = self.connection.cursor()

        mapped = {}

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
                # for mapping table
                if pcounter not in mapped:
                    mapped[pcounter] = set()
                mapped[pcounter].add(fcounter)

                oldfcounter[firm.firmwareName] = fcounter
                qf = "INSERT or REPLACE INTO firmwares(fid, name, date, unpackReason) VALUES (?, ?, ?, ?)"
                cursor.execute(
                    qf,
                    [
                        fcounter,
                        firm.firmwareName,
                        firm.releaseDate,
                        # convert to set with ast.literal_eval
                        str(firm.unpackresults),
                    ],
                )

                self.init_binaries(firm, cursor, pcounter, fcounter, oldfcounter)
                self.init_otherbinaries(firm, cursor, pcounter, fcounter, oldfcounter)
                self.init_times(firm, cursor, pcounter, fcounter)
                self.init_credentials(firm, cursor, pcounter, fcounter)

                # update analysis tables
                self.init_anaysis(firm, cursor, pcounter, fcounter)

        # add extra product lines
        q = "INSERT or REPLACE INTO products(pid, name, vendor, type) VALUES (?, ?, ?, ?)"
        for product in qproduct:
            for firm in product.firmwares.values():
                for pname in firm.productLine:
                    pcounter = hashproduct(product, name=pname)
                    fcounter = hashfirmware(product, firm, name=pname)

                    # for mapping table
                    if pcounter not in mapped:
                        # creating new product if is not already created
                        cursor.execute(
                            q,
                            [
                                pcounter,
                                pname,
                                product.vendorName,
                                product.typeName,
                            ],
                        )
                        mapped[pcounter] = set()
                    mapped[pcounter].add(fcounter)

        q = "INSERT or REPLACE INTO pidfidmap(pid, fid) VALUES (?, ?)"
        for pid, lfid in mapped.items():
            for fid in lfid:
                cursor.execute(
                    q,
                    [
                        pid,
                        fid,
                    ],
                )

        self.connection.commit()

    def init_anaysis(self, firm, cursor, pcounter, fcounter):

        q = "INSERT or REPLACE INTO allsinks(rule, ruleid, targetFunction, address, callerFunction, algorithms, " \
            "isPhi_algorithms, isLib, isEntry, " \
            "isWrapper, hashcode, fid, pid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

        for hashcode, d in firm.analysis.uniqueSinks.items():
            for address, obj in d.items():
                cursor.execute(
                    q,
                    [
                        obj.rule.toString(),
                        getRuleMnemonic(obj.rule.ruleType),
                        obj.targetFunc,
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
            "targetFunction, isPhi, address, hashcode, fid, pid) " \
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

        for hashcode, d in firm.analysis.uniqueSinks.items():
            for address, obj in d.items():
                for cr in obj.cryptoGroup:

                    if cr.funcName.startswith('NOT-FOUND:') or cr.funcName == "" or cr.funcName.startswith('NOT FOUND') \
                            or cr.funcName.startswith('STR:'):
                        continue

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
                            cr.isPhi,
                            address,
                            hashcode,
                            fcounter,
                            pcounter,
                        ],

                    )

        q = "INSERT or REPLACE INTO allmisuses(rule, ruleid, ruleType, argument, constAddress, constValue, isPhi, " \
            "targetFunction, address, callerFunction, hashcode, fid, pid) " \
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
                            objmis.targetFunc,
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

        q = "INSERT or REPLACE INTO cfg(cfg, vertexset, edgeset, hashcode, fid, pid) VALUES (?, ?, ?, ?, ?, ?)"

        for hashcode, arr in firm.analysis.jsoncfg.items():
            cursor.execute(
                q,
                [
                    str(arr[0]),
                    str(arr[1]),
                    str(arr[2]),
                    hashcode,
                    fcounter,
                    pcounter,
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

            if binary.typeNum == DEFINES.UNKNOWN or binary.errcode == DEFINES.FAILED:
                continue

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
            for version in binary.version:
                ql = "INSERT or REPLACE INTO libraries(hashcode, fid, pid, version, type, foundwith) " \
                     "VALUES (?, ?, ?, ?, ?, ?)"
                cursor.execute(
                    ql,
                    [
                        binary.hashcode,
                        fcounter,
                        pcounter,
                        version.VersionToString(),
                        version.getMnemonic(),
                        version.where,
                    ],
                )

            if len(binary.crypto_constants) > 0:
                ql = "INSERT or REPLACE INTO yaracrypto(cryptoconstants, strings, hashcode, fid, pid) " \
                     "VALUES (?, ?, ?, ?, ?)"
                cursor.execute(
                    ql,
                    [
                        str(binary.crypto_constants),
                        binary.strings,
                        binary.hashcode,
                        fcounter,
                        pcounter,
                    ],
                )

            if binary.cve is not None:
                # save to database
                ql = "INSERT or REPLACE INTO cve(hashcode, fid, pid, product, version, cve_number, severity, " \
                     "publishdate, score, cvss_version, foundwith) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

                for item in binary.cve.values():

                    if item['cve_number'] == "UNKNOWN":
                        continue

                    porp = 'package'
                    if 'product' in item:
                        porp = 'product'

                    cursor.execute(
                        ql,
                        [
                            binary.hashcode,
                            fcounter,
                            pcounter,
                            item[porp],
                            item['version'],
                            item['cve_number'],
                            item['severity'],
                            item["publishdate"],
                            item["score"],
                            item["cvss_version"],
                            item["foundWith"],
                        ],
                    )

            if binary.cwe is not None:
                ql = "INSERT or REPLACE INTO cwe(cwe, hashcode, fid, pid) " \
                     "VALUES (?, ?, ?, ?)"
                cursor.execute(
                    ql,
                    [
                        str(binary.cwe),
                        binary.hashcode,
                        fcounter,
                        pcounter,
                    ],
                )

    def init_otherbinaries(self, firm, cursor, pcounter, fcounter, oldfcounter):

        for binary in firm.otherbinaries.values():
            # safety feature because of fixes in release files
            oldfc = fcounter
            if binary.firmwareName in oldfcounter:
                oldfc = oldfcounter[binary.firmwareName]

            qb = "INSERT or REPLACE INTO otherbinaries(hashcode, name, location, pid, fid, oldfid)" \
                 "VALUES (?, ?, ?, ?, ?, ?)"
            cursor.execute(
                qb,
                [
                    binary.hashcode,
                    binary.name,
                    binary.location,
                    pcounter,
                    fcounter,
                    oldfc,
                ],
            )

            # update Libraries
            for version in binary.version:
                ql = "INSERT or REPLACE INTO otherlibraries(hashcode, fid, pid, version, type) " \
                     "VALUES (?, ?, ?, ?, ?)"
                cursor.execute(
                    ql,
                    [
                        binary.hashcode,
                        fcounter,
                        pcounter,
                        version.VersionToString(),
                        version.getMnemonic(),
                    ],
                )

            if binary.cve is not None:
                # save to database
                ql = "INSERT or REPLACE INTO othercve(hashcode, fid, pid, product, version, cve_number, severity, " \
                     "publishdate, score, cvss_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

                for item in binary.cve.values():

                    if item['cve_number'] == "UNKNOWN":
                        continue

                    porp = 'package'
                    if 'product' in item:
                        porp = 'product'

                    cursor.execute(
                        ql,
                        [
                            binary.hashcode,
                            fcounter,
                            pcounter,
                            item[porp],
                            item['version'],
                            item['cve_number'],
                            item['severity'],
                            item["publishdate"],
                            item["score"],
                            item["cvss_version"],
                        ],
                    )
