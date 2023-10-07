import os
import re
import shutil
import subprocess
import threading
from multiprocessing import Process
import binwalk
import zipfile
import time

import rarfile
import tarfile
import lzma
import gzip
import mimetypes

from pathlib import Path

from modules.DEFINES import CONFIGURATION, DEFINES
from modules.binary import Binary
from modules.helpfunctions import createDir, mexecQuiet, mexec, sha256
from modules.log import log

from modules.unpack.ArchiveLib import archive7, archGzip


class unpackFirmware():
    UNKNOWN = 0
    DECOMPRESSED = 1
    BINWALK = 2
    DECRYPTED = 3
    UNSQUASHFS = 4
    SINGLEBINARY = 5
    SPACE_EXPLODE = 6
    GPG_DECRYPT = 7
    LINUX_ROM = 8
    # add support for more mime type to ignore
    excludeMimeList = ["application/pdf", "application/msword", "text/css", "image/gif",
                       "application/javascript", "application/java-vm", "text/plain", "image/jpeg", "image/png",
                       "text/x-component", "application/xml", "text/html", "application/vnd.ms-officetheme"]

    # Product line DIR-882, DIR-3060
    DLinkMagic = bytes([0x53, 0x48, 0x52, 0x53])
    # Product line DIR-882, DIR-3060
    DLinkSymmetricKey = "c05fbf1936c99429ce2a0781f08d6ad8"

    def __init__(self, proj):
        # fail safe on matryoshka binwalk spawn on a different process
        self.processQ = []
        self.numThreads = proj.numThreads
        self.isVerbose = proj.isVerbose()
        self.isDebug = proj.isDebug()
        self.extractDir = proj.extractDir
        self.objBinary = Binary(proj.firmwareInput, verbose=self.isVerbose, getTypeOnly=True)

        # copy the firmware to extract in order to start extraction
        self.newLocation = Path(shutil.copy2(proj.firmwareInput, proj.extractDir))
        # rename if space
        if self.newLocation.name.find(" ") >= 0:
            renamedLoc = Path(self.newLocation.parent / self.newLocation.name.replace(" ", "_"))
            self.newLocation.rename(renamedLoc)
            self.newLocation = renamedLoc

        mimetypes.init()

        self.alreadyChecked = set()

        self.reason = set()

    def isKnown(self, file):
        try:
            # last argument True to get only the mime type
            testbinary = Binary(file, verbose=self.isVerbose, getTypeOnly=True)
            if (testbinary.isBinary()):
                self.alreadyChecked.add(str(file))
                return True

            if (testbinary.isSymbolic() or testbinary.isinode()):
                self.alreadyChecked.add(str(file))
                return True

            mime = mimetypes.guess_type(str(file))
            if self.isVerbose:
                log.logDF("Mime = " + str(mime[0]))

            if mime[0] in unpackFirmware.excludeMimeList:
                self.alreadyChecked.add(str(file))
                return True
        except:
            pass

        return False

    def traverseList(self, extractList):
        for item in extractList:
            if (os.path.isfile(item)):
                # recursive extraction
                self.tryUnCompressRec(item)

    def tryKnownFormats(self, file):
        self.tryUnCompressRec(file)
        self.tryGPGdecrypt()
        self.tryDecryptModule()

    def tryUnCompressRec(self, file):
        try:
            strtype = mexec([CONFIGURATION.dict["FILECMD"], "--brief", "--mime-type", "--mime-encoding",
                             str(file)])
            mime = strtype.strip().split(";")
            mime = [x.strip() for x in mime]
            # mime = mimetypes.guess_type(str(file))
            isCompress = False
            obj = None

            # gzip compress
            if mime[0] == 'application/gzip':
                try:
                    # possibly gzip try with gzip
                    tmp = gzip.GzipFile(str(file))
                    obj = archGzip(str(file))
                    isCompress = True
                except:
                    pass
            # check 7zip compress
            elif mime[0] == "application/x-7z-compressed":
                try:
                    # possibly 7z try with py7zr
                    obj = archive7(str(file))
                    isCompress = True
                except:
                    pass

            if not isCompress:
                # check zip file
                if (zipfile.is_zipfile(str(file))):
                    obj = zipfile.ZipFile(file)
                    isCompress = True
                # check rar file
                elif (rarfile.is_rarfile(str(file))):
                    obj = rarfile.RarFile(str(file))
                    isCompress = True
                # check tar file
                elif (tarfile.is_tarfile(str(file))):
                    mime = mimetypes.guess_type(str(file))
                    # check for the compression method first
                    if mime[1] == "xz":
                        objlzma = lzma.open(str(file))
                        obj = tarfile.TarFile(fileobj=objlzma)
                    elif mime[1] == "gz" or mime[1] == "gzip":
                        objgz = gzip.open(str(file))
                        obj = tarfile.TarFile(fileobj=objgz)
                    else:
                        obj = tarfile.TarFile(str(file))

                    isCompress = True

            if isCompress:
                # extract all to directory name
                obj.extractall(file.parent)
                extractList = []
                self.reason.add(unpackFirmware.DECOMPRESSED)
                self.alreadyChecked.add(str(file))
                if tarfile.is_tarfile(str(file)):
                    namelist = []
                    memb = obj.getmembers()
                    for tarinfo in memb:
                        namelist.append(tarinfo.name)
                else:
                    namelist = obj.namelist()

                for f in namelist:
                    extractList.append(file.parent / f)

                obj.close()
                # recursive extraction
                self.traverseList(extractList)
        except:
            # try with 7zip if exception occurred
            cwd = os.getcwd()
            # create dir
            filename = "7z" + sha256(file)
            createDir(file.parent / filename)
            # change the dir to extract it
            os.chdir(file.parent / filename)
            # with dummy password if requested
            ret = mexecQuiet([CONFIGURATION.dict["SEVENZIP"], "-y", "-p" + CONFIGURATION.dict["PASSWORD"], "x", str(file)])
            # return back
            os.chdir(cwd)
            if (ret == DEFINES.FAILED):
                log.logW("tryUnCompressRec : " + str(file))
                log.logWF("tryUnCompressRec : " + str(file))
                return

            self.reason.add(unpackFirmware.DECOMPRESSED)
            extractList = []
            for root, dirs, files in os.walk(file.parent / filename):
                for name in files:
                    location = Path(os.path.join(root, name))
                    extractList.append(location)

            # recursive extraction
            self.traverseList(extractList)

    def tryunpackwithBinwalk(self, dir):
        for root, dirs, files in os.walk(dir):
            for name in files:
                file = Path(os.path.join(root, name))
                if str(file) not in self.alreadyChecked:
                    if not self.isKnown(file):
                        # run fork process
                        p = Process(target=self.unpackwithBinwalk, args=(str(file), str(root),))
                        # self.unpackwithBinwalk(str(file), str(root)))
                        p.start()
                        self.processQ.append(p)

                        # Limits the active process
                        while True:
                            countalive = 0
                            for proc in self.processQ:
                                if proc.is_alive():
                                    countalive += 1

                            # print(countalive)
                            if countalive < self.numThreads:
                                break

                            try:
                                # check extraction size
                                s = sum(f.stat().st_size for f in self.extractDir.glob('**/*') if
                                        (f.is_file() and not f.is_symlink()))
                            except:
                                # sleep for 1 second
                                time.sleep(1)
                                continue

                            # convert to gigabytes
                            gb = s / (1024 ** 3)

                            # if it is more than x gb something went wrong
                            if gb > float(CONFIGURATION.dict["SAFE_EXTRACTION"]):
                                log.logE("Space explode for firmware '%s' ! Check binwalk!" % (str(self.extractDir)))
                                log.logEF("Space explode for firmware '%s' ! Check binwalk!" % (str(self.extractDir)))

                                self.reason.add(unpackFirmware.SPACE_EXPLODE)
                                # break
                                break
                            # sleep for 1 second
                            time.sleep(1)

    # try official unsquashfs for newer squashfs files
    # try cramfsck for Linux Compressed ROM File
    def threadotherTools(self, bucketarr):
        for arr in bucketarr:
            root = arr[0]
            files = arr[1]
            for name in files:
                file = Path(os.path.join(root, name))
                if str(file) not in self.alreadyChecked:
                    if not self.isKnown(file):
                        # not a race condition OK!!
                        self.alreadyChecked.add(str(file))

                        strtype = mexec([CONFIGURATION.dict["FILECMD"], "--brief",
                                         str(file)], False)

                        if (isinstance(strtype, str) == False):
                            log.logW("Something went wrong in unSquashFS()")
                            return DEFINES.FAILED

                        if re.search("symbolic", strtype, re.IGNORECASE):
                            continue
                        # more aggressive with img
                        if re.search("squashfs", strtype, re.IGNORECASE) or str(file).endswith('.img'):
                            os.chown(file, os.getuid(), os.getgid())
                            extract_dir = file.parent / str(file.name + "-" + sha256(str(file)))
                            mexecQuiet([CONFIGURATION.dict["UNSQUASHFS"], "-d", str(extract_dir), str(file)])
                            extract_dir = file.parent / str('sas_' + file.name + "-" + sha256(str(file)))
                            mexecQuiet([CONFIGURATION.dict["SASQUATCH"], "-d", str(extract_dir), str(file)])
                            self.reason.add(unpackFirmware.UNSQUASHFS)

                        if re.search("Linux Compressed ROM", strtype, re.IGNORECASE) or str(file).endswith('.cfs'):
                            os.chown(file, os.getuid(), os.getgid())
                            extract_dir = file.parent / str('rom_' + file.name + "-" + sha256(str(file)))
                            mexecQuiet([CONFIGURATION.dict["CRAMFSCK"], "-x", str(extract_dir), str(file)])
                            self.reason.add(unpackFirmware.LINUX_ROM)

    # unsquashFs and Linux Compressed ROM File System data (cramfsck)
    def unpackOtherTools(self, dir):

        # buckets depends on number of threads available
        buckets = {}
        i = 0
        for root, dirs, files in os.walk(dir):
            id = i % self.numThreads
            if id not in buckets:
                buckets[id] = []
            buckets[id].append([root, files])
            i = i + 1

        threads = []
        for bucketarr in buckets.values():
            t = threading.Thread(target=self.threadotherTools, args=(bucketarr,))
            threads.append(t)
            t.start()

        # wait until all threads are finished
        for t in threads:
            t.join()

    def unpackwithBinwalk(self, file, root):
        # if the type is unknown then try to unpack with binwalk
        # sometimes binwalk extract it to cwd
        cwd = os.getcwd()
        try:

            # change the dir to extract it
            os.chdir(root)
            binout = binwalk.scan(file, signature=True, quiet=True, matryoshka=True, extract=True, **{'run-as' : 'root'})

            isnotError = True
            for module in binout:
                if self.isVerbose:
                    log.logF("%s Results:" % module.name)
                    for result in module.results:
                        if result.file.path in module.extractor.output:
                            # These are files that binwalk carved out of the original firmware image, a la dd
                            if result.offset in module.extractor.output[result.file.path].carved:
                                log.logF("Carved data from offset 0x%X to %s" % (
                                    result.offset, module.extractor.output[result.file.path].carved[result.offset]))
                            # These are files/directories created by extraction utilities (gunzip, tar, unsquashfs, etc)
                            if result.offset in module.extractor.output[result.file.path].extracted:
                                if len(module.extractor.output[result.file.path].extracted[result.offset].files) > 0:
                                    log.logF("Extracted %d files from offset 0x%X to '%s' using '%s'" % (
                                        len(module.extractor.output[result.file.path].extracted[result.offset].files),
                                        result.offset,
                                        module.extractor.output[result.file.path].extracted[result.offset].files[0],
                                        module.extractor.output[result.file.path].extracted[result.offset].command))

                for errors in module.errors:
                    isnotError = False
                    log.logWF("Errors %s" % (errors))
            # return back
            os.chdir(cwd)
            self.reason.add(unpackFirmware.BINWALK)
            return isnotError
        except binwalk.ModuleException as e:
            # return back
            os.chdir(cwd)
            log.logE("Critical failure of " + file + ":" + str(e))
            log.logEF("Critical failure of " + file + " :" + str(e))
            return False

    def tryDecryptModule(self):

        for root, dirs, files in os.walk(self.extractDir):
            for name in files:
                file = Path(os.path.join(root, name))
                if str(file) not in self.alreadyChecked:
                    if not self.isKnown(file):
                        fp = open(file, "rb")
                        # read 4 bytes
                        data = fp.read(4)

                        if self.DLinkMagic == data:
                            length1 = fp.read(4)
                            length2 = fp.read(4)
                            # get IV
                            iv = fp.read(16)
                            # digest SHA512
                            digest1 = fp.read(64)
                            digest2 = fp.read(64)
                            digest3 = fp.read(64)

                            # check size possible false positive?
                            if int(length2.hex(), 16) > file.stat().st_size:
                                continue

                            # skip 0x6dc
                            mexecQuiet(["dd", "if=" + str(file), "of=" + str(file.parent / "meta6dc.bin"), "bs=1",
                                        "count=" + str(int(length2.hex(), 16)), "skip=1756"])

                            # decrypt with known key and found IV
                            mexecQuiet(
                                ["openssl", "aes-128-cbc", "-d", "-nopad", "-nosalt", "-K", self.DLinkSymmetricKey,
                                 "-iv", iv.hex(), "-in", str(file.parent / "meta6dc.bin"), "-out",
                                 str(file.parent / "dec.bin")])

                            self.reason.add(unpackFirmware.DECRYPTED)

                        fp.close()

    def tryGPGdecrypt(self):

        for root, dirs, files in os.walk(self.extractDir):
            for name in files:
                file = Path(os.path.join(root, name))
                if str(file) not in self.alreadyChecked:
                    if not self.isKnown(file):
                        # verify GPG - gpg --verify
                        args = [CONFIGURATION.dict["GPG"], "--decrypt", "--yes", "--always-trust", "--passphrase",
                                CONFIGURATION.dict["PASSWORD"], str(file)]
                        out = subprocess.run(args, capture_output=True)

                        if len(out.stdout) == 0:
                            continue

                        fp = open(str(file.parent) + "/dec_" + file.name, 'wb')
                        fp.write(out.stdout)
                        fp.close()
                        self.reason.add(unpackFirmware.GPG_DECRYPT)
