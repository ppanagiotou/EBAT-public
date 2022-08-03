import ast
import hashlib
import os.path
import subprocess
import shutil
from collections import OrderedDict
from datetime import datetime
from os import path
import configparser

from modules.DEFINES import DEFINES, CONFIGURATION
from modules.log import log
from modules.postanalysis import PostRules


def createDir(name, verbose=False):
    if not os.path.exists(name):
        os.makedirs(name, exist_ok=True)
    else:
        if verbose:
            log.logDF("Folder %s already exists" % name)


def tryCopy(src, dst):
    try:
        # preserves all metadata
        shutil.copy2(src, dst)
        return
    except:
        pass

    # try with permission metadata
    try:
        shutil.copy(src, dst)
        return
    except:
        pass

    # change owner
    os.chown(src, os.getuid(), os.getgid())
    # else use copyfile no metadata
    if os.path.isdir(dst):
        dst = os.path.join(dst, os.path.basename(src))

    shutil.copyfile(src, dst)


def sha256(fname, blocksize=8192):
    hash_sha256 = hashlib.sha256()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(blocksize), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


def mexecGhidra(args, verbose=False, isGhidra=False, timeout=None):

    eargs = []
    if timeout is not None:
        # added timeout and kill after initial signal
        eargs = ['timeout', '-k', '1', timeout]

    if verbose:
        log.logDF(subprocess.list2cmdline(eargs + args))

    out = subprocess.run(eargs + args, capture_output=True)
    strout = str(out.stdout, 'utf-8')

    if out.returncode != DEFINES.SUCCESS:
        # ghidra may fail on multiple run's on some binaries for unknown reasons
        # (possibly for multiple threads).. try again one more time
        if isGhidra:
            return mexecGhidra(args, verbose=verbose, isGhidra=False, timeout=timeout)

        log.logWF(
            "Error in subprocess '%s', with return code %d " % (subprocess.list2cmdline(args), out.returncode))
        log.logEF(
            "Error in subprocess '%s', with return code %d \n %s \n" % (subprocess.list2cmdline(args), out.returncode,
                                                                        str(out.stderr, 'utf-8')))
        if verbose:
            log.logW(
                "Error in subprocess '%s', with return code %d " % (subprocess.list2cmdline(args), out.returncode))
        return DEFINES.FAILED

    if verbose:
        log.logDF(strout)
        if out.stderr != b'':
            log.logDF(
                "stderr from subprocess '%s', with return code %d \n %s \n" % (subprocess.list2cmdline(args),
                                                                               out.returncode,
                                                                               str(out.stderr, 'utf-8')))

    return strout


def mexec(args, verbose=False):
    if verbose:
        log.logDF(subprocess.list2cmdline(args))

    out = subprocess.run(args, capture_output=True)
    strout = str(out.stdout, 'utf-8')

    if out.returncode != DEFINES.SUCCESS:
        log.logWF(
            "Error in subprocess '%s', with return code %d " % (subprocess.list2cmdline(args), out.returncode))
        log.logEF(
            "Error in subprocess '%s', with return code %d \n %s \n" % (subprocess.list2cmdline(args), out.returncode,
                                                                        str(out.stderr, 'utf-8')))
        if verbose:
            log.logW(
                "Error in subprocess '%s', with return code %d " % (subprocess.list2cmdline(args), out.returncode))
        return DEFINES.FAILED

    if verbose:
        log.logDF(strout)
        if out.stderr != b'':
            log.logDF(
                "stderr from subprocess '%s', with return code %d \n %s \n" % (subprocess.list2cmdline(args),
                                                                               out.returncode,
                                                                               str(out.stderr, 'utf-8')))
    return strout


def mexecQuiet(args):
    out = subprocess.run(args, capture_output=True)

    if out.returncode != DEFINES.SUCCESS:
        return DEFINES.FAILED

    return DEFINES.SUCCESS


def mexecQuietwithInput(args, inputA=None):
    out = subprocess.run(args, capture_output=True, input=inputA)

    if (out.returncode != DEFINES.SUCCESS):
        return DEFINES.FAILED

    return out.stdout


def checkPostOptions(proj):
    if proj.options.delete_extract:
        # delete original and extract folder
        shutil.rmtree(proj.extractDir, ignore_errors=True)
        # for original folder
        if proj.firmwareInput.is_file():
            os.remove(proj.firmwareInput)
        elif proj.firmwareInput.is_dir():
            shutil.rmtree(proj.firmwareInput, ignore_errors=True)


def getReleaseOrder(options, firmwareInput):
    if (options.inputdates is None):
        return {}

    releasedict = {}

    inputdates = os.path.abspath(options.inputdates)

    with open(inputdates) as fp:
        lines = [line.rstrip() for line in fp]
        for line in lines:

            if line.strip().startswith("#"):
                continue

            arr = line.strip().split(";")
            if len(arr) != 3:
                continue

            dtobj = None
            try:
                dtobj = datetime.strptime(arr[1].strip(), '%d/%m/%y')
            except ValueError:
                try:
                    dtobj = datetime.strptime(arr[1].strip(), '%d/%m/%Y')
                except ValueError:
                    continue

            setofproduct = set()
            try:
                setofproduct = ast.literal_eval(arr[2].strip())
            except:
                pass

            releasedict[str(arr[0])] = dtobj, setofproduct.copy()

    # dictionary sorted by value
    sortRelease = OrderedDict(sorted(releasedict.items(), key=lambda t: t[1]))

    for root, dirs, files in os.walk(firmwareInput):
        for firmwareName in files:
            origfile = os.path.join(root, firmwareName)

            if firmwareName in sortRelease:
                sortRelease[firmwareName] = [origfile, sortRelease[firmwareName]]

    return sortRelease


def checkDirectories(options):
    # check Ghidra Directory
    if (path.exists(CONFIGURATION.dict["GHIDRADIR"]) == False):
        log.logE("Please configure Ghidra path")
        exit(DEFINES.FAILED)

    input = os.path.abspath(options.input)
    if (path.exists(input) == False):
        log.logE("Input file '%s' not found" % (input))
        exit(DEFINES.FAILED)

    if (path.isfile(CONFIGURATION.dict["RULES"]) == False):
        log.logE("Please configure the rules file")
        exit(DEFINES.FAILED)

    if (path.isfile(CONFIGURATION.dict["POSTRULES"]) == False):
        log.logE("Please configure the post rules file")
        exit(DEFINES.FAILED)

    if not path.isfile(CONFIGURATION.dict["YARA_CRYPTO_CONSTANT_RULES"]) or not \
            path.isfile(CONFIGURATION.dict["YARA_CREDENTIAL_RULES"]) or not \
            path.isfile(CONFIGURATION.dict["YARA_SOFTWARE_COMPONENTS_RULES"]):
        log.logE("Please configure the yara rules file")
        exit(DEFINES.FAILED)

    output = os.path.abspath(options.output)
    if (path.exists(output) == True):
        log.logE("Output directory " + output + " already exists")
        exit(DEFINES.FAILED)

    # release dates check
    if (options.inputdates is not None):
        inputdates = os.path.abspath(options.inputdates)
        if (path.isfile(inputdates) == False):
            log.logE("CSV release file with dates not found")
            exit(DEFINES.FAILED)

    if options.cwe_checker:
        if path.exists(CONFIGURATION.dict["CWE_CHECKER"]):
            log.logE("Please configure the cwe_checker binary.")
            exit(DEFINES.FAILED)


def normcaseLinux(path):
    ret_path = []
    for ch in str(path):
        if ch == '(' or ch == ')' or ch == '\\' or ch == '&':
            ret_path.append('\\')

        ret_path.append(ch)

    return ''.join(ret_path)


def createLibReleases(config):
    arrreleases = ["openssl-release", "wolfssl-release", "libgcrypt-release", "gnutls-release",
                   "mbedtls-release", "mcrypt-release", "nettle-release", "libsodium-release"]
    for name in arrreleases:
        if name in config:
            drt = {}
            for key, value in config[name].items():
                drt[key.strip()] = datetime.strptime(value.strip(), "%d/%m/%Y")

            CONFIGURATION.libsrelease[name] = drt.copy()


def initConfig(options):
    fconfig = os.path.abspath(options.config)

    if (os.path.exists(fconfig) and os.path.isfile(fconfig)):
        config = configparser.ConfigParser()
        config.read(fconfig)

        for key, value in config['constants'].items():
            CONFIGURATION.dict[key.strip().upper()] = value.strip()

        for key, value in config['rules'].items():
            CONFIGURATION.rules[key.strip().upper()] = int(value.strip())

        for key, value in config['configuration'].items():
            CONFIGURATION.dict[key.strip().upper()] = value.strip()

        if ("crypto-algorithms" in config):
            for key, value in config['crypto-algorithms'].items():
                CONFIGURATION.algorithms[key.strip().upper()] = int(value.strip())
        if ("weak-ciphers" in config):
            for key, value in config['weak-ciphers'].items():
                CONFIGURATION.weakciphers[key.strip().upper()] = int(value.strip())
        if ("weak-modes-of-operation" in config):
            for key, value in config['weak-modes-of-operation'].items():
                CONFIGURATION.weakmodesofoperation[key.strip().upper()] = int(value.strip())
        if ("crypto-modes-of-operation" in config):
            for key, value in config['crypto-modes-of-operation'].items():
                CONFIGURATION.modesofoperation[key.strip().upper()] = int(value.strip())
        if ("weak-hmac-digests" in config):
            for key, value in config['weak-hmac-digests'].items():
                CONFIGURATION.weakdigesthmac[key.strip().upper()] = int(value.strip())
        if ("weak-kdf-digests" in config):
            for key, value in config['weak-kdf-digests'].items():
                CONFIGURATION.weakkdfdigest[key.strip().upper()] = int(value.strip())
        if ("weak-public-digests" in config):
            for key, value in config['weak-public-digests'].items():
                CONFIGURATION.weakpublicdigest[key.strip().upper()] = int(value.strip())

        createLibReleases(config)

    else:
        log.logE("Please check the path to the configuration file")
        exit(DEFINES.FAILED)

    # post process
    if ("CRYPTOLIST" in CONFIGURATION.dict):
        arr = CONFIGURATION.dict["CRYPTOLIST"].split(",")
        for elem in arr:
            if elem.strip() != "":
                CONFIGURATION.cryptolibs.add(elem.strip())

    if ("EXCLUDELIST" in CONFIGURATION.dict):
        arr = CONFIGURATION.dict["EXCLUDELIST"].split(",")
        for elem in arr:
            if elem.strip() != "":
                CONFIGURATION.excludelist.add(elem.strip())


def initPostRules():
    if (os.path.exists(CONFIGURATION.dict["POSTRULES"]) and os.path.isfile(CONFIGURATION.dict["POSTRULES"])):
        config = configparser.ConfigParser()
        config.optionxform = str
        config.read(CONFIGURATION.dict["POSTRULES"])

        return PostRules(config)

    else:
        log.logE("Please check the path to the post configuration file")
        exit(DEFINES.FAILED)


# K-partition problem -> np complete
def partitionBuckets(arr, maxbuckets):
    # sort array in descending order
    arr.sort(reverse=True)

    assert maxbuckets >= 1

    # initialise buckets
    buckets = {}
    for i in range(0, maxbuckets):
        buckets[i] = []

    while len(arr) > 0:
        # get item
        item = arr.pop(0)

        smin = sum(buckets[0])
        fid = 0
        # get the bucket that has the minimum sum
        for id, bucket in buckets.items():
            s = sum(bucket)
            if s < smin:
                smin = s
                fid = id
        # add to bucket
        buckets[fid].append(item)

    #    for id, bucket in buckets.items():
    #        print("%d - %d" % (id, sum(bucket)))

    return buckets


def getbucketid(numbuckets, sizeb):
    for id, b in numbuckets.items():
        for a in b:
            if a == sizeb:
                return id
    # not found just add to 0
    return 0
