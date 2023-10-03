import os
import re
from pathlib import Path

from modules.DEFINES import CONFIGURATION, DEFINES
from modules.helpfunctions import mexecQuietwithInput, mexec, mexecQuiet, createDir, tryCopy
from modules.log import log

class Credentials:
    DELIMITER = "CREDENTIALS:"

    EXTENSIONS = [".pkcs12", ".pfx", ".p12", ".key", ".pem", ".csr", ".der", ".cert", ".der",
                  ".crt", ".p7b", ".keystore", ".crl", ".pub", ".ovpn"]
    MIMETYPES = ["application/pgp-keys", "application/x-x509-ca-cert", "application/pgp-encrypted",
                 "application/pgp-signature"]

    DEFINETYPES = dict(UNKNOWN=0,
                       PRIVATE_KEY=1,
                       PRIVATE_KEY_ENCRYPTED=2,
                       PRIVATE_KEY_ENCRYPTED_DECRYPTED=3,
                       PUBLIC_KEY=4,
                       CERTIFICATE=5,
                       CERTIFICATE_SIGNING_REQUEST=6,
                       PARAMETERS=7,
                       EMPTY_FILE=8,
                       SSH_PUBLIC_KEY=9,
                       SSH_PRIVATE_KEY=10,
                       SSH_PRIVATE_KEY_ENCRYPTED=11,
                       SSH_PRIVATE_KEY_ENCRYPTED_DECRYPTED=12,
                       PGP_SIGNATURES=13,
                       PKCS12=14,
                       PKCS12_ENCRYPTED=15,
                       PKCS12_ENCRYPTED_DECRYPTED=16,
                       PGP_CREDENTIALS=17,
                       )

    PASSWORDLIST = ['password', 'whatever', 'deadbeef', 'root', 'root12345', 'admin', 'N3z0y93', 'ThiSIsTHePASSphr4s3',
                    'ThiSISEncryptioNKeY', 'this_is_a_passphrase', 'tw007', 'amittima']

    def __init__(self, binary, copyLocation, mimetype, file_extension, extractDir=None, analysisDir=None,
                 verbose=False):

        self.binary = binary
        self.verbose = verbose
        self.name = binary.name
        self.copyLocation = copyLocation
        self.type = {}
        self.output = {}
        index = 0

        sizeinbytes = Path(binary.location).stat().st_size
        if sizeinbytes == 0:
            self.type[index] = Credentials.DEFINETYPES['EMPTY_FILE']
            self.output[index] = ""
            return

        sshret = isSSHKey(binary.location)
        if sshret == 1:

            self.type[index] = Credentials.DEFINETYPES['SSH_PUBLIC_KEY']
            ret = mexecQuiet(
                [CONFIGURATION.dict["SSH-KEYGEN"], "-y", "-P", CONFIGURATION.dict["PASSWORD"], "-f", binary.location])
            if ret == DEFINES.FAILED:

                # try to decrypt
                for password in self.PASSWORDLIST:
                    ret = mexecQuiet(
                        [CONFIGURATION.dict["SSH-KEYGEN"], "-y", "-P", password, "-f",
                         binary.location])
                    if ret == DEFINES.SUCCESS:
                        strout = mexec(
                            [CONFIGURATION.dict["SSH-KEYGEN"], "-y", "-P", password, "-f",
                             binary.location])
                        if (isinstance(strout, str) == True):
                            self.output[index] = "Password:" + password + "\n" + strout
                            index = index + 1

                            with open(binary.location) as fp:
                                self.type[index] = Credentials.DEFINETYPES['SSH_PRIVATE_KEY_ENCRYPTED_DECRYPTED']
                                self.output[index] = str("".join(fp.readlines()))
                                index = index + 1

                self.type[index] = Credentials.DEFINETYPES['SSH_PRIVATE_KEY_ENCRYPTED']
                self.output[index] = ""
                index = index + 1
            else:
                strout = mexec([CONFIGURATION.dict["SSH-KEYGEN"], "-y", "-P", CONFIGURATION.dict["PASSWORD"], "-f",
                                binary.location])
                if (isinstance(strout, str) == True):
                    self.output[index] = strout
                    index = index + 1

                    with open(binary.location) as fp:
                        self.type[index] = Credentials.DEFINETYPES['SSH_PRIVATE_KEY']
                        self.output[index] = str("".join(fp.readlines()))
                        index = index + 1

        if sshret == 2:
            strout = mexec([CONFIGURATION.dict["DROPBEARKEY"], "-y", "-f", binary.location])
            if isinstance(strout, str):
                self.output[index] = strout
                self.type[index] = Credentials.DEFINETYPES['SSH_PUBLIC_KEY']
                index = index + 1

                newlocation = binary.location + "_convert.key"
                ret = mexecQuiet(
                    [CONFIGURATION.dict["DROPBEARCONVERT"], "dropbear", "openssh", binary.location, newlocation])
                if ret == DEFINES.SUCCESS:
                    # use in metaanalysis already converted
                    if extractDir is not None:
                        rel = os.path.dirname(os.path.relpath(newlocation, extractDir))
                        copylocation = analysisDir / CONFIGURATION.dict["DIR_CREDENTIALS"] / rel
                        createDir(copylocation)
                        tryCopy(newlocation, copylocation)

                    with open(newlocation, "r") as fp:
                        self.type[index] = Credentials.DEFINETYPES['SSH_PRIVATE_KEY']
                        self.output[index] = str("".join(fp.readlines()))
                        index = index + 1

                        binary.location = newlocation

                else:
                    log.logWF("dropbearconvert ERROR in %s" % binary.location)

        bbegin = False
        bend = False
        capturestr = ""
        with open(binary.location, "r") as fp:
            try:
                line = fp.readline()
            except:
                line = None

            while line:
                if (line.find("-BEGIN") >= 0):
                    bbegin = True
                    bend = False
                    capturestr = ""

                elif (line.find("-END") >= 0):
                    bbegin = False
                    bend = True
                    capturestr = capturestr + line

                if (bbegin == True):
                    capturestr = capturestr + line

                elif (bend == True):
                    # check rsa key
                    if (line.find("PRIVATE KEY-") >= 0):
                        strout = mexecQuietwithInput(
                            [CONFIGURATION.dict["OPENSSL"], "pkey", "-passin", "pass:" + CONFIGURATION.dict["PASSWORD"],
                             "-check", "-text"], inputA=capturestr.encode())

                        if (isinstance(strout, bytes) == True):
                            self.type[index] = Credentials.DEFINETYPES['PRIVATE_KEY']
                            self.output[index] = strout
                            index = index + 1
                            if self.verbose:
                                log.logDF(
                                    "{} : {} , {}, {}\n".format(binary.name,
                                                                self.getMnemonic(
                                                                    Credentials.DEFINETYPES['PRIVATE_KEY']),
                                                                binary.location, mimetype))
                        else:
                            # decrypted
                            for password in self.PASSWORDLIST:
                                strout = mexecQuietwithInput(
                                    [CONFIGURATION.dict["OPENSSL"], "pkey", "-passin",
                                     "pass:" + password,
                                     "-check", "-text"], inputA=capturestr.encode())

                                if isinstance(strout, bytes):
                                    self.type[index] = Credentials.DEFINETYPES['PRIVATE_KEY_ENCRYPTED_DECRYPTED']
                                    self.output[index] = b"Password:" + bytes(password.encode('utf8')) + b"\n" + strout
                                    index = index + 1
                                    if self.verbose:
                                        log.logDF(
                                            "{} : {} , {}, {}\n".format(binary.name,
                                                                        self.getMnemonic(
                                                                            Credentials.DEFINETYPES[
                                                                                'PRIVATE_KEY_ENCRYPTED_DECRYPTED']),
                                                                        binary.location, mimetype))

                            self.type[index] = Credentials.DEFINETYPES['PRIVATE_KEY_ENCRYPTED']
                            self.output[index] = ""
                            index = index + 1
                            if self.verbose:
                                log.logDF("{} : {} , {}, {}\n".format(binary.name,
                                                                      self.getMnemonic(
                                                                          Credentials.DEFINETYPES[
                                                                              'PRIVATE_KEY_ENCRYPTED']),
                                                                      binary.location, mimetype))


                    elif (line.find("PUBLIC KEY-") >= 0):
                        strout = mexecQuietwithInput([CONFIGURATION.dict["OPENSSL"], "pkey", "-pubin", "-pubcheck",
                                                      "-text"],
                                                     inputA=capturestr.encode())

                        if (isinstance(strout, bytes) == True):
                            self.type[index] = Credentials.DEFINETYPES['PUBLIC_KEY']
                            self.output[index] = strout
                            index = index + 1
                            if self.verbose:
                                log.logDF("{} : {} , {}, {}\n".format(binary.name, self.getMnemonic(
                                    Credentials.DEFINETYPES['PUBLIC_KEY']),
                                                                      binary.location, mimetype))
                        else:
                            # special case for old RSA public keys
                            strout = mexecQuietwithInput([CONFIGURATION.dict["OPENSSL"], "rsa", "-RSAPublicKey_in",
                                                          "-text"],
                                                         inputA=capturestr.encode())

                            if (isinstance(strout, bytes) == True):
                                self.type[index] = Credentials.DEFINETYPES['PUBLIC_KEY']
                                self.output[index] = strout
                                index = index + 1
                                if self.verbose:
                                    log.logDF(
                                        "{} : {} , {}, {}\n".format(binary.name,
                                                                    self.getMnemonic(
                                                                        Credentials.DEFINETYPES['PUBLIC_KEY']),
                                                                    binary.location, mimetype))

                    elif (line.find("PARAMETERS-") >= 0):
                        strout = mexecQuietwithInput([CONFIGURATION.dict["OPENSSL"], "pkeyparam", "-text"],
                                                     inputA=capturestr.encode())

                        if (isinstance(strout, bytes) == True):
                            self.type[index] = Credentials.DEFINETYPES['PARAMETERS']
                            self.output[index] = strout
                            index = index + 1
                            if self.verbose:
                                log.logDF("{} : {} , {}, {}\n".format(binary.name, self.getMnemonic(
                                    Credentials.DEFINETYPES['PARAMETERS']),
                                                                      binary.location, mimetype))

                    elif (line.find("CERTIFICATE-") >= 0):
                        strout = mexecQuietwithInput([CONFIGURATION.dict["OPENSSL"], "x509", "-text"],
                                                     inputA=capturestr.encode())

                        if (isinstance(strout, bytes) == True):
                            self.type[index] = Credentials.DEFINETYPES['CERTIFICATE']
                            self.output[index] = strout
                            index = index + 1
                            if self.verbose:
                                log.logDF(
                                    "{} : {} , {}, {}\n".format(binary.name,
                                                                self.getMnemonic(
                                                                    Credentials.DEFINETYPES['CERTIFICATE']),
                                                                binary.location, mimetype))


                    elif (line.find("CERTIFICATE REQUEST-") >= 0):
                        # certificate signing request
                        strout = mexecQuietwithInput(
                            [CONFIGURATION.dict["OPENSSL"], "req", "-text", "-verify"],
                            inputA=capturestr.encode())

                        if (isinstance(strout, bytes) == True):
                            self.type[index] = Credentials.DEFINETYPES['CERTIFICATE_SIGNING_REQUEST']
                            self.output[index] = strout
                            index = index + 1
                            if self.verbose:
                                log.logDF("{} : {} , {}, {}\n".format(binary.name, self.getMnemonic(
                                    Credentials.DEFINETYPES['CERTIFICATE_SIGNING_REQUEST']), binary.location, mimetype))

                    elif (line.find("-END PGP PUBLIC KEY BLOCK-") >= 0):
                        strout = mexecQuietwithInput([CONFIGURATION.dict["PGPDUMP"]], inputA=capturestr.encode())

                        if (isinstance(strout, bytes) == True):
                            self.type[index] = Credentials.DEFINETYPES['PUBLIC_KEY']
                            self.output[index] = strout
                            index = index + 1
                            if self.verbose:
                                log.logDF("{} : {} , {}, {}\n".format(binary.name, self.getMnemonic(
                                    Credentials.DEFINETYPES['PUBLIC_KEY']),
                                                                      binary.location, mimetype))

                    bbegin = False
                    bend = False
                    capturestr = ""

                try:
                    line = fp.readline()
                except:
                    line = None

        if len(self.type) == 0:

            if file_extension == ".der":
                outfile = binary.location + ".to.pem"
                ret = mexecQuiet(
                    [CONFIGURATION.dict["OPENSSL"], "x509", "-inform", "der", "-in", binary.location, "-out", outfile])
                if ret == DEFINES.SUCCESS:
                    strout = mexecQuietwithInput(
                        [CONFIGURATION.dict["OPENSSL"], "x509", "-text", "-in", outfile],
                        inputA=b"\n")

                    if (isinstance(strout, bytes) == True):
                        self.type[index] = Credentials.DEFINETYPES['CERTIFICATE']
                        self.output[index] = strout
                        index = index + 1
                        if self.verbose:
                            log.logDF(
                                "{} : {} , {}, {}\n".format(binary.name,
                                                            self.getMnemonic(Credentials.DEFINETYPES['CERTIFICATE']),
                                                            binary.location, mimetype))

            if mimetype == "application/x-pkcs12" or file_extension == ".p12":
                strout = mexecQuietwithInput(
                    [CONFIGURATION.dict["OPENSSL"], "pkcs12", "-nodes", "-passin",
                     "pass:" + CONFIGURATION.dict["PASSWORD"],
                     "-info", "-in", binary.location], inputA=b"\n")

                if isinstance(strout, bytes):
                    self.type[index] = Credentials.DEFINETYPES['PKCS12']
                    self.output[index] = strout
                    index = index + 1
                    if self.verbose:
                        log.logDF(
                            "{} : {} , {}, {}\n".format(binary.name,
                                                        self.getMnemonic(Credentials.DEFINETYPES['PKCS12']),
                                                        binary.location, mimetype))
                else:
                    # try to decrypt
                    for password in self.PASSWORDLIST:
                        strout = mexecQuietwithInput(
                            [CONFIGURATION.dict["OPENSSL"], "pkcs12", "-nodes", "-passin",
                             "pass:" + password,
                             "-info", "-in", binary.location], inputA=b"\n")

                        if isinstance(strout, bytes):
                            self.type[index] = Credentials.DEFINETYPES['PKCS12_ENCRYPTED_DECRYPTED']
                            self.output[index] = b"Password:" + bytes(password.encode('utf8')) + b"\n" + strout
                            index = index + 1
                            if self.verbose:
                                log.logDF(
                                    "{} : {} , {}, {}\n".format(binary.name,
                                                                self.getMnemonic(Credentials.DEFINETYPES[
                                                                                     'PKCS12_ENCRYPTED_DECRYPTED']),
                                                                binary.location, mimetype))

                    self.type[index] = Credentials.DEFINETYPES['PKCS12_ENCRYPTED']
                    self.output[index] = ""
                    index = index + 1
                    if self.verbose:
                        log.logDF("{} : {} , {}, {}\n".format(binary.name,
                                                              self.getMnemonic(
                                                                  Credentials.DEFINETYPES['PKCS12_ENCRYPTED']),
                                                              binary.location, mimetype))

            pgpmime = ["application/pgp-signature", "PGP Secret", "application/pgp-keys", "PGP/GPG"]

            pgpfound = False
            for ext in pgpmime:
                if re.search(ext, mimetype, re.IGNORECASE):
                    pgpfound = True

            if pgpfound:
                strout = mexecQuietwithInput([CONFIGURATION.dict["PGPDUMP"], binary.location], inputA=b"\n")

                if isinstance(strout, bytes):
                    if mimetype == "application/pgp-signature":
                        self.type[index] = Credentials.DEFINETYPES['PGP_SIGNATURES']
                    else:
                        self.type[index] = Credentials.DEFINETYPES['PGP_CREDENTIALS']
                    self.output[index] = strout
                    index = index + 1
                    if self.verbose:
                        log.logDF("{} : {} , {}, {}\n".format(binary.name,
                                                              self.getMnemonic(Credentials.DEFINETYPES['PUBLIC_KEY']),
                                                              binary.location, mimetype))

            if (file_extension == ".cert") or (mimetype == "application/x-java-keystore"):
                strout = mexecQuietwithInput(
                    [CONFIGURATION.dict["KEYTOOL"], "-v", "-list", "-keystore", binary.location],
                    inputA=b"\n")

                if (isinstance(strout, bytes) == True):
                    self.type[index] = Credentials.DEFINETYPES['CERTIFICATE']
                    self.output[index] = strout
                    index = index + 1
                    if self.verbose:
                        log.logDF(
                            "{} : {} , {}, {}\n".format(binary.name,
                                                        self.getMnemonic(Credentials.DEFINETYPES['CERTIFICATE']),
                                                        binary.location,
                                                        mimetype))
                else:
                    log.logWF(
                        "Credentials: {} : {} , {}, {}\n".format(binary.name,
                                                                 self.getMnemonic(Credentials.DEFINETYPES['UNKNOWN']),
                                                                 binary.location,
                                                                 mimetype))

        if len(self.type) == 0:
            log.logWF("Credentials: {} : {} , {}, {}\n".format(binary.name,
                                                               self.getMnemonic(Credentials.DEFINETYPES['UNKNOWN']),
                                                               binary.location,
                                                               mimetype))

    def isEmpty(self):
        return len(self.type) == 0

    def toString(self):
        retstr = Credentials.DELIMITER
        for index, type in self.type.items():
            retstr = retstr + "{}, {}, {}\n".format(self.getMnemonic(self.type[index]), self.binary.name,
                                                    self.binary.location)
            try:
                retstr = retstr + str(self.output[index].decode('utf-8')) + "\n"
            except:
                retstr = retstr + str(self.output[index]) + "\n"
            if (self.type[index] == Credentials.DEFINETYPES['UNKNOWN']):
                log.logWF("Credentials: {} : {} , {}\n".format(self.binary.name,
                                                               self.getMnemonic(Credentials.DEFINETYPES['UNKNOWN']),
                                                               self.binary.location))

        return retstr

    def getMnemonic(self, type):
        for key, value in self.DEFINETYPES.items():
            if value == type:
                return key

        return "UNKNOWN"


def isSSHKey(location):
    location = Path(location)
    # check the size of the key to be less than 1Mbyte
    MAXLIMIT = pow(2, 20)
    try:
        if location.stat().st_size > MAXLIMIT:
            return 0
    except:
        return 0

    # get permissions
    oldperm = location.stat().st_mode
    # change permission not to be too broad
    location.chmod(0o400)

    ret = mexecQuiet([CONFIGURATION.dict["SSH-KEYGEN"], "-l", "-f", str(location)])
    if ret == DEFINES.SUCCESS:
        return 1

    ret = mexecQuiet([CONFIGURATION.dict["DROPBEARKEY"], "-y", "-f", str(location)])

    if ret == DEFINES.SUCCESS:
        return 2

    # change back permissions if is not an ssh key
    location.chmod(oldperm)
    return 0


# search openssl, ssh, dropbear commands
class ScriptCMDs:
    SEARCHFOR = ["openssl", "ssh", "dropbear", "password", "pass:"]

    def __init__(self, binary):

        self.binary = binary
        self.cmd = {}
        self.isNone = True

        sizeinbytes = Path(binary.location).stat().st_size
        if (sizeinbytes == 0):
            return

        with open(binary.location, "r") as fp:
            try:
                line = fp.readline()
            except:
                line = None
            linenum = 1
            while line:

                for pattern in self.SEARCHFOR:
                    if line.find(pattern) >= 0:
                        self.addCMD(line, linenum)

                linenum = linenum + 1

                try:
                    line = fp.readline()
                except:
                    line = None

    def addCMD(self, line, linenum):
        self.cmd[linenum] = line.strip()
        self.isNone = False

    def toString(self):
        retstr = self.binary.name + ", " + self.binary.location + "\n"

        for linenum, line in self.cmd.items():
            retstr = retstr + str(linenum) + ":" + "'" + line + "'" + "\n"

        return retstr
