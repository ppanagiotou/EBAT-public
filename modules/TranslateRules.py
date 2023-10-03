import ast
import copy
import ctypes
import math
import struct

from modules.Rule import Rule, AbstractRule, Misuse, getMappedKey
from modules.DEFINES import DEFINES, CONFIGURATION
from modules.log import log
from postmodules.group import CryptoGroup


def translateRules(sink, lmisuserules, bitarch=DEFINES.BIT32, verbose=False):
    getruleid = sink["ruleid"]
    # need tainted parameters which are greater than 10
    # also 0 is the dependent parameter
    if (getruleid < 10) and (getruleid != 0):
        return None

    createAbstractRuleL(sink, lmisuserules, bitarch=bitarch, verbose=verbose)


def createAbstractRuleL(sink, lmisuserules, bitarch=DEFINES.BIT32, verbose=False):
    getaddr = sink["addr"]

    getruleid = sink["ruleid"]
    getFrom = sink["functionName"]
    getSink = sink["targetFunctionName"]

    getrule = sink["rule"]

    getArg = sink["argIdx"]
    getType = sink["typeofArg"]

    getAlgorithm = {}
    if ("algorithm" in sink):
        getAlgorithm = sink["algorithm"]

    if getaddr not in lmisuserules:
        lmisuserules[getaddr] = AbstractRule(getrule)

    abstractRule = lmisuserules[getaddr]

    objmis = Misuse(getruleid, getFrom, getSink, getaddr, getType, getAlgorithm, getArg)

    if (getArg == DEFINES.NO_ARGUMENTS):
        abstractRule.addAbstract(objmis)
        return

    # pass by reference
    abstractRule = DFS(sink, abstractRule, objmis, bitarch=bitarch, verbose=verbose)


def createAbstractRule(sink, bitarch=DEFINES.BIT32, verbose=False):
    getruleid = sink["ruleid"]
    getFrom = sink["functionName"]
    getSink = sink["targetFunctionName"]

    getrule = sink["rule"]
    getaddr = sink["addr"]

    getArg = sink["argIdx"]
    getType = sink["typeofArg"]

    getAlgorithm = {}
    if ("algorithm" in sink):
        getAlgorithm = sink["algorithm"]

    abstractRule = AbstractRule(getrule)

    objmis = Misuse(getruleid, getFrom, getSink, getaddr, getType, getAlgorithm, getArg)

    if (getArg == DEFINES.NO_ARGUMENTS):
        abstractRule.addAbstract(objmis)
        return abstractRule

    abstractRule = DFS(sink, abstractRule, objmis, bitarch=bitarch, verbose=verbose)

    return abstractRule


def isWeakHMACdigest(cr):
    if cr.algorithm is None or cr.algorithm == CONFIGURATION.algorithms["UNKNOWN"]:
        return CONFIGURATION.algorithms["UNKNOWN"]

    for key, value in CONFIGURATION.weakdigesthmac.items():
        if value == cr.algorithm:
            return value

    return CONFIGURATION.algorithms["UNKNOWN"]


def isWeaKDFdigest(cr):
    if cr.algorithm is None or cr.algorithm == CONFIGURATION.algorithms["UNKNOWN"]:
        return CONFIGURATION.algorithms["UNKNOWN"]

    for key, value in CONFIGURATION.weakkdfdigest.items():
        if value == cr.algorithm:
            return value

    return CONFIGURATION.algorithms["UNKNOWN"]


def isWeaPublicdigest(cr):
    if cr.algorithm is None or cr.algorithm == CONFIGURATION.algorithms["UNKNOWN"]:
        return CONFIGURATION.algorithms["UNKNOWN"]

    for key, value in CONFIGURATION.weakpublicdigest.items():
        if value == cr.algorithm:
            return value

    return CONFIGURATION.algorithms["UNKNOWN"]


def isWeakCipher(cr):
    if cr.algorithm == CONFIGURATION.algorithms["UNKNOWN"] or cr.algorithm is None:
        return CONFIGURATION.algorithms["UNKNOWN"]

    for key, value in CONFIGURATION.weakciphers.items():
        if value == cr.algorithm:
            return value

    return CONFIGURATION.algorithms["UNKNOWN"]


def isWeakModeOfOperation(cr):
    if cr.modeofoperation is None:
        return CONFIGURATION.modesofoperation["UNKNOWN"]

    for key, value in CONFIGURATION.weakmodesofoperation.items():
        if key.lower() == cr.modeofoperation.lower():
            return value

    return CONFIGURATION.modesofoperation["UNKNOWN"]


def checkWeakEntropy(analysis, uniqueSinks, lmisuserules):
    weakentropy = dict()
    # check if weak cipher is only in uniqueSinks and create new rule
    for addr, sink in uniqueSinks.items():
        if sink.rule.ruleType != CONFIGURATION.rules['PSEUDORANDOM_NUMBER_GENERATORS']:
            continue
        getSink = sink.targetFunc
        if getSink not in analysis.proj.postRules.rules:
            continue

        for argid in sink.rule.taintedArgs.keys():
            getArg = int(argid)
            if getArg not in analysis.proj.postRules.rules[getSink].arg:
                continue

            proceed = True
            for alg, isPhi in sink.algorithm.items():
                if alg.__contains__("/dev/urandom") or alg.__contains__("/dev/random"):
                    proceed = False
                    break

            if not proceed:
                continue

            for alg, isPhi in sink.algorithm.items():
                talg = alg
                if alg.startswith('NOT-FOUND:'):
                    arsp = alg.split(':')
                    if len(arsp) >= 1:
                        talg = arsp[1].strip()

                isWeak = False
                if 'UNSECURE_FUNCTIONS' in analysis.proj.postRules.rules[getSink].arg[getArg]:
                    for uf in analysis.proj.postRules.rules[getSink].arg[getArg]['UNSECURE_FUNCTIONS'].split(','):
                        if talg.lower() == uf.strip().lower():
                            isWeak = True
                            break

                if isWeak:
                    if addr not in weakentropy:
                        weakentropy[addr] = []
                    weakentropy[addr].append([talg, isPhi])

    # add the new misuse
    for addr, arr in weakentropy.items():
        for item in arr:
            talg = item[0]
            isPhi = item[1]
            # if addr not in misuse rules then create abstract
            if addr not in lmisuserules:
                objs = uniqueSinks[addr]
                lmisuserules[addr] = AbstractRule(objs.rule.toString())

            # add object misuse
            absrule = lmisuserules[addr]
            objs = uniqueSinks[addr]
            #
            misrule = -1
            if objs.rule.ruleType == CONFIGURATION.rules["PSEUDORANDOM_NUMBER_GENERATORS"]:
                misrule = CONFIGURATION.rules["PSEUDORANDOM_NUMBER_GENERATORS_WEAK_ENTROPY"]
            else:
                log.logEF("ERROR checkWeakCiphers!")
                continue

            objmis = Misuse(misrule, objs.fromFunc,
                            objs.targetFunc, addr, "weak-entropy", talg, 0, constValue=[talg], isPhi=isPhi)
            absrule.addAbstract(objmis)


def checkWeakCiphers(uniqueSinks, lmisuserules):
    weakciphers = dict()
    # check if weak cipher is only in uniqueSinks and create new rule
    for addr, sink in uniqueSinks.items():
        for cr in sink.cryptoGroup:
            ret = CONFIGURATION.algorithms["UNKNOWN"]
            if sink.rule.ruleType == CONFIGURATION.rules["SYMMETRIC_KEY_ENCRYPTION"]:
                ret = isWeakCipher(cr)
            elif sink.rule.ruleType == CONFIGURATION.rules["HASH_FUNCTIONS_KEYED"]:
                ret = isWeakHMACdigest(cr)
            elif sink.rule.ruleType == CONFIGURATION.rules["KDFS_AND_PASSWORD_HASH"]:
                ret = isWeaKDFdigest(cr)
            elif sink.rule.ruleType == CONFIGURATION.rules["PUBLIC_KEY_CRYPTOGRAPHY"]:
                ret = isWeaPublicdigest(cr)
            elif sink.rule.ruleType == CONFIGURATION.rules["HASH_FUNCTIONS_UNKEYED"]:
                ret = isWeaPublicdigest(cr)

            if ret != CONFIGURATION.algorithms["UNKNOWN"]:
                if addr not in weakciphers:
                    weakciphers[addr] = []
                weakciphers[addr].append([ret, cr])

    # add the new misuse
    for addr, arr in weakciphers.items():
        for item in arr:
            value = item[0]
            cr = item[1]
            # if addr not in misuse rules then create abstract
            if addr not in lmisuserules:
                objs = uniqueSinks[addr]
                lmisuserules[addr] = AbstractRule(objs.rule.toString())

            # add object misuse
            absrule = lmisuserules[addr]
            objs = uniqueSinks[addr]
            #
            misrule = -1
            if objs.rule.ruleType == CONFIGURATION.rules["SYMMETRIC_KEY_ENCRYPTION"]:
                misrule = CONFIGURATION.rules["SYMMETRIC_KEY_ENCRYPTION_WEAK_CIPHER"]
            elif objs.rule.ruleType == CONFIGURATION.rules["HASH_FUNCTIONS_KEYED"]:
                misrule = CONFIGURATION.rules["HASH_FUNCTIONS_KEYED_WEAK_DIGEST_FUN"]
            elif objs.rule.ruleType == CONFIGURATION.rules["HASH_FUNCTIONS_UNKEYED"]:
                misrule = CONFIGURATION.rules["HASH_FUNCTIONS_UNKEYED_WEAK_DIGEST_FUN"]
            elif objs.rule.ruleType == CONFIGURATION.rules["KDFS_AND_PASSWORD_HASH"]:
                misrule = CONFIGURATION.rules["KDFS_AND_PASSWORD_HASH_WEAK_DIGEST_FUN"]
            elif objs.rule.ruleType == CONFIGURATION.rules["PUBLIC_KEY_CRYPTOGRAPHY"]:
                for ld in objs.rule.taintedArgs.values():
                    if int(ld.ruleid) == CONFIGURATION.rules["PUBLIC_KEY_CRYPTOGRAPHY_X509_DIGEST"]:
                        misrule = CONFIGURATION.rules["PUBLIC_KEY_CRYPTOGRAPHY_X509_WEAK_DIGEST"]
                        break
                    elif int(ld.ruleid) == CONFIGURATION.rules["PUBLIC_KEY_CRYPTOGRAPHY_DIGITAL_SIGNATURE_DIGEST"]:
                        misrule = CONFIGURATION.rules["PUBLIC_KEY_CRYPTOGRAPHY_DIGITAL_SIGNATURE_WEAK_DIGEST"]
                        break
            else:
                log.logEF("ERROR checkWeakCiphers!")
                continue

            objmis = Misuse(misrule, objs.fromFunc,
                            objs.targetFunc, addr, "weak", objs.algorithm, 0,
                            constValue=[getMappedKey(cr.algorithm, CONFIGURATION.algorithms)], isPhi=cr.isPhi)
            absrule.addAbstract(objmis)


def checkECBMode(uniqueSinks, lmisuserules):
    ecbmode = {}
    # check if ecb mode is only in uniqueSinks and create new rule
    for addr, sink in uniqueSinks.items():
        if sink.rule.ruleType == CONFIGURATION.rules["SYMMETRIC_KEY_ENCRYPTION"]:
            for cr in sink.cryptoGroup:
                ret = isWeakModeOfOperation(cr)
                if ret != CONFIGURATION.modesofoperation["UNKNOWN"]:
                    if addr not in ecbmode:
                        ecbmode[addr] = []

                    ecbmode[addr].append(cr)

    for addr, arr in ecbmode.items():
        for cr in arr:
            if addr not in lmisuserules:
                objs = uniqueSinks[addr]
                lmisuserules[addr] = AbstractRule(objs.rule.toString())

            isECB = False
            absrule = lmisuserules[addr]
            for objmis in absrule.abstract:
                if objmis.ruleID == CONFIGURATION.rules["SYMMETRIC_KEY_ENCRYPTION_USING_ECB_MODE"]:
                    isECB = True
                    break

            if isECB:
                continue

            objs = uniqueSinks[addr]
            objmis = Misuse(CONFIGURATION.rules["SYMMETRIC_KEY_ENCRYPTION_USING_ECB_MODE"], objs.fromFunc,
                            objs.targetFunc, addr, "ECB", objs.algorithm, 0,
                            constValue=[getMappedKey(cr.algorithm, CONFIGURATION.algorithms)], isPhi=cr.isPhi)
            absrule.addAbstract(objmis)


def checkPostMisuseRules(analysis, uniqueSinks, lmisuserules):
    # first update algorithms
    for absrule in lmisuserules.values():
        for objmis in absrule.abstract:
            if objmis.atAddress in uniqueSinks:
                objmis.algorithm = uniqueSinks[objmis.atAddress].algorithm

    # check other rules
    for hashcode, absrule in lmisuserules.items():
        extrarr = []
        for objmis in absrule.abstract:
            # crypt
            if objmis.ruleID == CONFIGURATION.rules["KDFS_AND_PASSWORD_HASH_CONSTANT_SALTS"]:
                checkCryptKDF(analysis, objmis)

        for objmis in extrarr:
            absrule.addAbstract(objmis)

    # create groups
    analysis.updateGroupSinks()

    # check ECB mode
    checkECBMode(uniqueSinks, lmisuserules)

    # check weak ciphers
    checkWeakCiphers(uniqueSinks, lmisuserules)

    # check weak entropy source
    checkWeakEntropy(analysis, uniqueSinks, lmisuserules)


def checkCryptKDF(analysis, objmis):
    argobj = getPostRule(analysis, objmis)
    if argobj is not None:
        # check which function are you using
        if objmis.targetFunc == "crypt" or objmis.targetFunc == "crypt_r":
            if isinstance(objmis.constValue, list):
                # remove all empty values from the list
                objmis.constValue = list(filter(lambda a: a != "", objmis.constValue))
                if len(objmis.constValue) == 0:
                    return

                isFound = False
                md = argobj.arg[objmis.getArg]
                for c in objmis.constValue:
                    if isinstance(c, str):
                        for key, value in md.items():
                            if c.startswith(value):
                                objmis.algorithm[key] = objmis.isPhi
                                isFound = True

                if not isFound:
                    # use of DES
                    objmis.algorithm["KDF_DES"] = objmis.isPhi


def getPostRule(analysis, objmis):
    if objmis.targetFunc in analysis.proj.postRules.rules:
        argobj = analysis.proj.postRules.rules[objmis.targetFunc]
        if objmis.getArg in argobj.arg:
            return argobj

    return None


def checkPostMisuseRulesOnline(analysis, objmis):
    # iterations
    if objmis.ruleID == CONFIGURATION.rules["KDFS_AND_PASSWORD_HASH_ITERATIONS"]:
        argobj = getPostRule(analysis, objmis)
        if argobj is not None:
            for constValue in objmis.constValue:
                # check SAFE iteration
                if (isinstance(constValue, int)):
                    if (constValue < argobj.arg[objmis.getArg]["SAFE_ITERATION"]):
                        objmis.ruleID = CONFIGURATION.rules["KDFS_AND_PASSWORD_HASH_WEAK_ITERATIONS"]
                        return

    elif objmis.ruleID == CONFIGURATION.rules["PUBLIC_KEY_CRYPTOGRAPHY_RSA_PADDING"]:
        argobj = getPostRule(analysis, objmis)
        if argobj is not None:
            for constValue in objmis.constValue:
                if isinstance(constValue, int):
                    # print(objmis.constValue)
                    # find padding
                    padding = getMappedKey(constValue, argobj.arg[objmis.getArg])
                    objmis.algorithm[padding] = objmis.isPhi
                    # add it to constant
                    con = objmis.constValue
                    objmis.constValue = []
                    objmis.constValue.append(con)
                    objmis.constValue.append(padding)
                    # check if it is weak
                    for weak in ast.literal_eval(argobj.arg[objmis.getArg]["WEAK_PADDINGS"]):
                        if padding == weak:
                            objmis.ruleID = CONFIGURATION.rules["PUBLIC_KEY_CRYPTOGRAPHY_RSA_WEAK_PADDING"]
                            return

                    return

    # Hmac weak keysize
    if objmis.ruleID == CONFIGURATION.rules["HASH_FUNCTIONS_KEYED_KEYSIZE"]:
        argobj = getPostRule(analysis, objmis)
        if argobj is not None:
            # check SAFE iteration
            for constValue in objmis.constValue:
                if (isinstance(constValue, int)):
                    if constValue > 0:
                        # convert to bits
                        if ((constValue * 8) < argobj.arg[objmis.getArg]["SAFE_KEY_SIZE"]):
                            objmis.ruleID = CONFIGURATION.rules["HASH_FUNCTIONS_KEYED_WEAK_KEYSIZE"]
                            return


def checkPostRules(analysis, sink, bitarch=DEFINES.BIT32):
    # check CTX and CTYPE
    checkCTXandCTYPE(analysis, sink, bitarch=bitarch)
    # check others meta general rules
    checkOtherTaint(analysis, sink, bitarch=bitarch)


def createGroup(analysis, sink):
    grouparr = []

    crsink = CryptoGroup(sink.targetFunc, sink.rule.ruleType, analysis.proj.postRules)
    if not crsink.isFound:
        crsink = CryptoGroup(sink.targetFunc.upper(), sink.rule.ruleType, analysis.proj.postRules)

    for rule, value in sink.metarule.items():
        if rule == "ENCRYPT":
            crsink.isEncrypt = True

        if rule == "DECRYPT":
            crsink.isEncrypt = False

        if rule == "KEYSIZE":
            crsink.keysize = value

        if rule == "IVSIZE":
            crsink.ivsize = value
    grouparr.append(crsink)

    for alg, phi in sink.algorithm.items():
        cr = CryptoGroup(alg, sink.rule.ruleType, analysis.proj.postRules, isPhi=phi)
        if not cr.isFound:
            cr = CryptoGroup(str(alg).upper(), sink.rule.ruleType, analysis.proj.postRules, isPhi=phi)
        grouparr.append(cr)

    for e in sink.extrameta:
        for rule, value in e.items():
            cr = CryptoGroup(sink.targetFunc, sink.rule.ruleType, analysis.proj.postRules)
            if not cr.isFound:
                cr = CryptoGroup(sink.targetFunc.upper(), sink.rule.ruleType, analysis.proj.postRules)

            if rule == "ENCRYPT":
                cr.isEncrypt = True

            if rule == "DECRYPT":
                cr.isEncrypt = False

            if rule == "KEYSIZE":
                cr.keysize = value

            if rule == "IVSIZE":
                cr.ivsize = value

            grouparr.append(cr)

    sink.cryptoGroup = grouparr.copy()


def checkOtherTaint(analysis, sink, bitarch=DEFINES.BIT32):
    # if not dependent and rule < 10
    getruleid = sink["ruleid"]

    getType = sink["typeofArg"]
    if getType == "CTX" or getType == "CTYPE":
        return

    # check if is in the meta analysis rules
    getSink = sink["targetFunctionName"]
    if getSink not in analysis.proj.postRules.rules:
        return

    getArg = sink["argIdx"]
    if getArg not in analysis.proj.postRules.rules[getSink].arg:
        return

    # find the const value
    abstractRule = createAbstractRule(sink, bitarch=bitarch, verbose=analysis.proj.isVerbose())

    # get the meta rule
    mapobj = analysis.proj.postRules.rules[getSink].arg[getArg]

    metarule = {}
    if "metarule" in sink:
        metarule = sink["metarule"]

    def addtometarule(d, key, value, sink):

        if key == 'NOT FOUND':
            return

        if key not in d:
            d[key] = value
        else:
            if "extrameta" not in sink:
                sink["extrameta"] = []

            newadd = True
            for item in sink["extrameta"]:
                for k, v in item.items():
                    if k == key and v == value:
                        newadd = False

                    if k == key and d[key] == v:
                        newadd = False

            if newadd:
                sink["extrameta"].append({key: value})
                # print('extra', sink["extrameta"])

        return

    for objmis in abstractRule.abstract:
        for constValue in objmis.constValue:
            if isinstance(constValue, int):
                if "KEYSIZE" in mapobj:
                    # convert to bits
                    if mapobj["KEYSIZE"] == "bytes":
                        # metarule["KEYSIZE"] = objmis.constValue * 8
                        addtometarule(metarule, "KEYSIZE", constValue * 8, sink)
                    else:
                        # metarule["KEYSIZE"] = objmis.constValue
                        addtometarule(metarule, "KEYSIZE", constValue, sink)
                elif "IVSIZE" in mapobj:
                    # convert to bits
                    if mapobj["IVSIZE"] == "bytes":
                        # metarule["IVSIZE"] = objmis.constValue * 8
                        addtometarule(metarule, "IVSIZE", constValue * 8, sink)
                    else:
                        # metarule["IVSIZE"] = objmis.constValue
                        addtometarule(metarule, "IVSIZE", constValue, sink)
                else:
                    # adding with mapped taint values to constants
                    # metarule[getMappedKey(objmis.constValue, mapobj)] = objmis.isPhi
                    addtometarule(metarule, getMappedKey(constValue, mapobj), objmis.isPhi, sink)
            elif isinstance(constValue, str):
                if "HASH_FUNCTION" in mapobj or "CIPHER" in mapobj:
                    addTaintToAlgorithm(sink, constValue, objmis)

    sink["metarule"] = metarule


def addTaintToAlgorithm(sink, constValue, objmis):
    getAlgorithm = {}
    if ("algorithm" in sink):
        getAlgorithm = sink["algorithm"]

    setofalg = getAlgorithm
    setofalg[constValue] = objmis.isPhi

    setofalg.update(objmis.algorithm)

    sink["algorithm"] = setofalg


def checkCTXandCTYPE(analysis, sink, bitarch=DEFINES.BIT32):
    getType = sink["typeofArg"]
    if getType != "CTX" and getType != "CTYPE":
        return

    getSink = sink["targetFunctionName"]

    if getSink not in analysis.proj.postRules.rules:
        return

    getArg = sink["argIdx"]
    if getArg not in analysis.proj.postRules.rules[getSink].arg:
        return

    mapobj = analysis.proj.postRules.rules[getSink].arg[getArg]

    abstractRule = createAbstractRule(sink, bitarch=bitarch, verbose=analysis.proj.isVerbose())

    getAlgorithm = {}
    if ("algorithm" in sink):
        getAlgorithm = sink["algorithm"]

    setofalg = getAlgorithm
    for objmis in abstractRule.abstract:
        for constValue in objmis.constValue:
            if isinstance(constValue, int):
                # adding to get algorithm
                v = getMappedKey(constValue, mapobj)
                setofalg[v] = objmis.isPhi
                setofalg.update(objmis.algorithm)
                # special HMAC case flag
                if v == 'GCRY_MD_FLAG_HMAC' or v == 'MBEDTLS_HMAC':
                    sink["isHMAC"] = True

    sink["algorithm"] = setofalg


def addtoMisuse(objmis, item):
    newobj = copy.copy(objmis)
    newobj.isPhi = item["isPhi"]
    if item['isStr']:
        newobj.constValue = item['value']
        newobj.constAddress = item['addr']
        newobj.constLength = item['valuesLength']
    else:
        newobj.constValue = item['value']

    return newobj


def DFS(sink, abstractRule, objmis, bitarch=DEFINES.BIT32, verbose=False):
    # Preorder Traversal
    for node in sink["children"]:
        res = checkNode(node, bitarch=bitarch, verbose=verbose)
        if res is not None:
            if isinstance(res, list):
                for item in res:
                    abstractRule.addAbstract(addtoMisuse(objmis, item))
            else:
                abstractRule.addAbstract(addtoMisuse(objmis, res))

    for node in sink["parents"]:
        res = checkNode(node, bitarch=bitarch, verbose=verbose)
        if res is not None:
            if isinstance(res, list):
                for item in res:
                    abstractRule.addAbstract(addtoMisuse(objmis, item))
            else:
                abstractRule.addAbstract(addtoMisuse(objmis, res))

    return abstractRule


def checkNode(node, bitarch=DEFINES.BIT32, verbose=False):
    # REMOVE THIS overwrite now for test
    # verbose = True
    # CONST
    if (node["nodeName"] == "CONST"):
        return checkConst(node)
    # PHI const
    if (node["nodeName"] == "PHICONST"):
        return checkConst(node)
    # high argument of a function
    elif (node["nodeName"] == "HIGHPARAM"):
        if (checkLengthToLog(node, 0, parent=True, plen=len(node['parents']), checkchild=False, verbose=verbose)):
            return None

        arr = []
        for pch in node['parents']:
            l = checkNode(pch, bitarch=bitarch, verbose=verbose)
            if l is not None:
                for item in l:
                    arr.append(item)

        if len(arr) > 0:
            return arr

        return None

    elif (node["nodeName"] == "PARENTFUNCTION") or (node["nodeName"] == "FUNCTION") or (
            node["nodeName"] == "PHIFUNCTION"):
        if (checkLengthToLog(node, 1, parent=False, verbose=verbose)):
            return None
        return checkNode(node['children'][0], bitarch=bitarch, verbose=verbose)
    # library function call
    elif (node["nodeName"] == "THUNK"):
        return None
    elif (node["nodeName"] == "OPERATION"):
        if (node["opIDMnemonic"] == "CALL") or (node["opIDMnemonic"] == "BRANCH"):
            if (checkLengthToLog(node, 1, parent=False, verbose=verbose)):
                return None
            return checkNode(node['children'][0], bitarch=bitarch, verbose=verbose)
        # resolve some cases internally to ghidra
        if (node["opIDMnemonic"] == "BRANCHIND") or (node["opIDMnemonic"] == "CALLIND"):
            if (checkLengthToLog(node, 1, parent=False, verbose=verbose)):
                return None
            return checkNode(node['children'][0], bitarch=bitarch, verbose=verbose)
        if (node["opIDMnemonic"] == "CBRANCH"):
            # if (input1) goto input0;
            if (checkLengthToLog(node, 2, parent=False, verbose=verbose)):
                return None

            ln1 = checkNode(node['children'][1], bitarch=bitarch, verbose=verbose)
            proceed = False
            if ln1 is not None:
                for n1 in ln1:
                    for a1 in n1['value']:
                        if not isinstance(a1, int):
                            continue

                        proceed |= bool(a1)

            if proceed:
                return checkNode(node['children'][0], bitarch=bitarch, verbose=verbose)
            else:
                return None
        elif (node["opIDMnemonic"] == "LOAD"):
            if (checkLengthToLog(node, 2, parent=False, verbose=verbose)):
                return None
            return checkNode(node['children'][1], bitarch=bitarch, verbose=verbose)
        # sign extend
        # zero extend
        elif (node["opIDMnemonic"] == "INT_NEGATE") or (node["opIDMnemonic"] == "POPCOUNT") or \
             (node["opIDMnemonic"] == "INT_SEXT") or (node["opIDMnemonic"] == "INT_ZEXT") or \
             (node["opIDMnemonic"] == "INT_2COMP") or (node["opIDMnemonic"] == "BOOL_NEGATE"):
            # 	output = ~input0;
            if (checkLengthToLog(node, 1, parent=False, verbose=verbose)):
                return None
            resarr = []
            ln1 = checkNode(node['children'][0], bitarch=bitarch, verbose=verbose)
            if ln1 is not None:
                for n1 in ln1:
                    for a1 in n1['value']:
                        if not isinstance(a1, int):
                            continue

                        if (node["opIDMnemonic"] == "INT_NEGATE"):
                            resarr.append(
                                {'value': [~a1], "isStr": False,
                                 "isPhi": n1['isPhi']})
                        elif (node["opIDMnemonic"] == "BOOL_NEGATE"):
                            #  	output = !input0;
                            resarr.append(
                                {'value': [int(not bool(a1))], "isStr": False,
                                 "isPhi": n1['isPhi']})
                        elif (node["opIDMnemonic"] == "INT_SEXT"):
                            if bitarch == DEFINES.BIT32:
                                resarr.append(
                                    {'value': [ctypes.c_int32(a1).value], "isStr": False,
                                     "isPhi": n1['isPhi']})
                            elif bitarch == DEFINES.BIT64:
                                resarr.append(
                                    {'value': [ctypes.c_int64(a1).value], "isStr": False,
                                     "isPhi": n1['isPhi']})
                        elif (node["opIDMnemonic"] == "INT_ZEXT"):
                            if bitarch == DEFINES.BIT32:
                                resarr.append(
                                    {'value': [ctypes.c_uint32(a1).value], "isStr": False,
                                     "isPhi": n1['isPhi']})
                            elif bitarch == DEFINES.BIT64:
                                resarr.append(
                                    {'value': [ctypes.c_uint64(a1).value], "isStr": False,
                                     "isPhi": n1['isPhi']})
                        elif (node["opIDMnemonic"] == "POPCOUNT"):
                            if bitarch == DEFINES.BIT32:
                                resarr.append(
                                    {'value': [int(math.log(ctypes.c_uint32(a1).value, 2))], "isStr": False,
                                     "isPhi": n1['isPhi']})
                            elif bitarch == DEFINES.BIT64:
                                resarr.append(
                                    {'value': [int(math.log(ctypes.c_uint64(a1).value, 2))], "isStr": False,
                                     "isPhi": n1['isPhi']})
                        elif (node["opIDMnemonic"] == "INT_2COMP"):
                            if bitarch == DEFINES.BIT32:
                                resarr.append(
                                    {'value': [-ctypes.c_int32(a1).value], "isStr": False,
                                     "isPhi": n1['isPhi']})
                            elif bitarch == DEFINES.BIT64:
                                resarr.append(
                                    {'value': [-ctypes.c_int64(a1).value], "isStr": False,
                                     "isPhi": n1['isPhi']})

            if len(resarr) > 0:
                return resarr

            return None

        elif (node["opIDMnemonic"] == "INT_ADD") or (node["opIDMnemonic"] == "INT_XOR") \
                or (node["opIDMnemonic"] == "INT_MULT") or (node["opIDMnemonic"] == "INT_SUB") \
                or (node["opIDMnemonic"] == "INT_NOTEQUAL") or (node["opIDMnemonic"] == "INT_LESS") \
                or (node["opIDMnemonic"] == "INT_SLESS") or (node["opIDMnemonic"] == "INT_LESSEQUAL") \
                or (node["opIDMnemonic"] == "INT_SLESSEQUAL") or (node["opIDMnemonic"] == "INT_LEFT") \
                or (node["opIDMnemonic"] == "INT_RIGHT") or (node["opIDMnemonic"] == "INT_AND") \
                or (node["opIDMnemonic"] == "INT_OR") or (node["opIDMnemonic"] == "INT_SRIGHT") \
                or (node["opIDMnemonic"] == "INT_DIV") or (node["opIDMnemonic"] == "INT_EQUAL") \
                or (node["opIDMnemonic"] == "INT_SDIV") or (node["opIDMnemonic"] == "FLOAT_ADD") \
                or (node["opIDMnemonic"] == "FLOAT_SUB") or (node["opIDMnemonic"] == "FLOAT_MULT") \
                or (node["opIDMnemonic"] == "FLOAT_DIV") or (node["opIDMnemonic"] == "BOOL_AND") \
                or (node["opIDMnemonic"] == "INT_REM") or (node["opIDMnemonic"] == "INT_SREM") \
                or (node["opIDMnemonic"] == "BOOL_XOR") or (node["opIDMnemonic"] == "BOOL_OR") \
                or (node["opIDMnemonic"] == "FLOAT_EQUAL") or (node["opIDMnemonic"] == "FLOAT_NOTEQUAL") \
                or (node["opIDMnemonic"] == "FLOAT_LESS") or (node["opIDMnemonic"] == "FLOAT_LESSEQUAL"):

            if (checkLengthToLog(node, 2, parent=False, verbose=verbose)):
                return None
            ln1 = checkNode(node['children'][0], bitarch=bitarch, verbose=verbose)
            ln2 = checkNode(node['children'][1], bitarch=bitarch, verbose=verbose)

            resarr = []
            if ln1 is not None and ln2 is not None:
                for n1 in ln1:
                    for a1 in n1['value']:
                        if not isinstance(a1, int):
                            continue
                        for n2 in ln2:
                            for a2 in n2['value']:
                                if not isinstance(a2, int):
                                    continue
                                if node["opIDMnemonic"] == "INT_ADD":
                                    # output = input0 + input1;
                                    # No need to convert to specific types as python works on arbitary bit precission
                                    resarr.append(
                                        {'value': [a1 + a2], "isStr": False, "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "FLOAT_ADD":
                                    # output = input0 + input1;
                                    f1 = tofloat(a1)
                                    f2 = tofloat(a2)
                                    res = f1 + f2
                                    resarr.append(
                                        {'value': [float_to_hex(res)], "isStr": False, "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "INT_XOR":
                                    # output = input0 ^ input1;
                                    resarr.append(
                                        {'value': [a1 ^ a2], "isStr": False, "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "INT_MULT":
                                    # output = input0 * input1;
                                    resarr.append(
                                        {'value': [a1 * a2], "isStr": False, "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "FLOAT_MULT":
                                    # output = input0 * input1;
                                    f1 = tofloat(a1)
                                    f2 = tofloat(a2)
                                    res = f1 * f2
                                    resarr.append(
                                        {'value': [float_to_hex(res)], "isStr": False, "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "INT_SUB":
                                    # output = input0 - input1;
                                    resarr.append(
                                        {'value': [a1 - a2], "isStr": False, "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "FLOAT_SUB":
                                    # output = input0 - input1;
                                    f1 = tofloat(a1)
                                    f2 = tofloat(a2)
                                    res = f1 - f2
                                    resarr.append(
                                        {'value': [float_to_hex(res)], "isStr": False, "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "INT_NOTEQUAL":
                                    # output = input0 != input1;
                                    resarr.append(
                                        {'value': [int(bool(a1 != a2))], "isStr": False,
                                         "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "FLOAT_NOTEQUAL":
                                    # output = input0 != input1;
                                    f1 = tofloat(a1)
                                    f2 = tofloat(a2)
                                    resarr.append(
                                        {'value': [int(bool(f1 != f2))], "isStr": False,
                                         "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "INT_EQUAL":
                                    # output = input0 == input1;
                                    resarr.append(
                                        {'value': [int(bool(a1 == a2))], "isStr": False,
                                         "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "FLOAT_EQUAL":
                                    # output = input0 f== input1;
                                    f1 = tofloat(a1)
                                    f2 = tofloat(a2)
                                    resarr.append(
                                        {'value': [int(bool(f1 == f2))], "isStr": False,
                                         "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "INT_LESS":
                                    # unsigned
                                    # output = input0 < input1;
                                    if bitarch == DEFINES.BIT32:
                                        resarr.append(
                                            {'value': [int(bool(ctypes.c_uint32(a1).value < ctypes.c_uint32(a2).value))], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                    elif bitarch == DEFINES.BIT64:
                                        resarr.append(
                                            {'value': [int(bool(ctypes.c_uint64(a1).value < ctypes.c_uint64(a2).value))], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "FLOAT_LESS":
                                    f1 = tofloat(a1)
                                    f2 = tofloat(a2)
                                    resarr.append(
                                        {'value': [int(bool(f1 < f2))],
                                         "isStr": False,
                                         "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "FLOAT_LESSEQUAL":
                                    f1 = tofloat(a1)
                                    f2 = tofloat(a2)
                                    resarr.append(
                                        {'value': [int(bool(f1 <= f2))],
                                         "isStr": False,
                                         "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "INT_SLESS":
                                    # singed
                                    # output = input0 s< input1;
                                    if bitarch == DEFINES.BIT32:
                                        resarr.append(
                                            {'value': [int(bool(ctypes.c_int32(a1).value < ctypes.c_int32(a2).value))],
                                             "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                    elif bitarch == DEFINES.BIT64:
                                        resarr.append(
                                            {'value': [int(bool(ctypes.c_int64(a1).value < ctypes.c_int64(a2).value))],
                                             "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "INT_LESSEQUAL":
                                    # unsigned
                                    # output = input0 <= input1;
                                    if bitarch == DEFINES.BIT32:
                                        resarr.append(
                                            {'value': [int(bool(ctypes.c_uint32(a1).value <= ctypes.c_uint32(a1).value))], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                    elif bitarch == DEFINES.BIT64:
                                        resarr.append(
                                            {'value': [int(bool(ctypes.c_uint64(a1).value <= ctypes.c_uint64(a1).value))], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "INT_SLESSEQUAL":
                                    # output = input0 s<= input1;
                                    if bitarch == DEFINES.BIT32:
                                        resarr.append(
                                            {'value': [int(bool(ctypes.c_int32(a1).value <= ctypes.c_int32(a2).value))],
                                             "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                    elif bitarch == DEFINES.BIT64:
                                        resarr.append(
                                            {'value': [int(bool(ctypes.c_int64(a1).value <= ctypes.c_int64(a2).value))],
                                             "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "BOOL_XOR":
                                    # output = input0 ^ ^ input1;
                                    resarr.append(
                                        {'value': [int(bool(bool(a1) != bool(a2)))],
                                         "isStr": False,
                                         "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "BOOL_AND":
                                    # output = input0 && input1;
                                    resarr.append(
                                        {'value': [int(bool(bool(a1) and bool(a2)))],
                                         "isStr": False,
                                         "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "BOOL_OR":
                                    #  	output = input0 || input1;
                                    resarr.append(
                                        {'value': [int(bool(bool(a1) or bool(a2)))],
                                         "isStr": False,
                                         "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "INT_AND":
                                    # output = input0 & input1;
                                    resarr.append(
                                        {'value': [a1 & a2], "isStr": False,
                                         "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "INT_OR":
                                    # output = input0 | input1;
                                    resarr.append(
                                        {'value': [a1 | a2], "isStr": False,
                                         "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "INT_LEFT":
                                    # output = input0 << input1;
                                    if bitarch == DEFINES.BIT32:
                                        resarr.append(
                                            {'value': [ctypes.c_uint32(a1).value << abs(a2)], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                    elif bitarch == DEFINES.BIT64:
                                        resarr.append(
                                            {'value': [ctypes.c_uint64(a1).value << abs(a2)], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "INT_RIGHT":
                                    # output = input0 >> input1;
                                    if bitarch == DEFINES.BIT32:
                                        resarr.append(
                                            {'value': [ctypes.c_uint32(a1).value >> abs(a2)], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                    elif bitarch == DEFINES.BIT64:
                                        resarr.append(
                                            {'value': [ctypes.c_uint64(a1).value >> abs(a2)], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "INT_SRIGHT":
                                    # output = input0 s>> input1;
                                    # signed arithmetic right shift
                                    resarr.append(
                                        {'value': [int(a1) >> abs(a2)], "isStr": False,
                                         "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "INT_DIV":
                                    # output = input0 / input1;
                                    if bitarch == DEFINES.BIT32:
                                        resarr.append(
                                            {'value': [ctypes.c_uint32(a1).value / ctypes.c_uint32(a2).value
                                                       if ctypes.c_uint32(
                                                a2).value else 0], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                    elif bitarch == DEFINES.BIT64:
                                        resarr.append(
                                            {'value': [ctypes.c_uint64(a1).value / ctypes.c_uint64(a2).value
                                                       if ctypes.c_uint64(
                                                a2).value else 0], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "FLOAT_DIV":
                                    # output = input0 / input1;
                                    f1 = tofloat(a1)
                                    f2 = tofloat(a2)
                                    res = f1 / f2 if f2 else 0
                                    resarr.append(
                                        {'value': [float_to_hex(res)], "isStr": False, "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "INT_SDIV":
                                    # output = input0 / input1;
                                    if bitarch == DEFINES.BIT32:
                                        resarr.append(
                                            {'value': [ctypes.c_uint32(a1).value / ctypes.c_uint32(a2).value if ctypes.c_uint32(a2).value else 0], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                    elif bitarch == DEFINES.BIT64:
                                        resarr.append(
                                            {'value': [ctypes.c_uint64(a1).value / ctypes.c_uint64(a2).value if ctypes.c_uint64(a2).value else 0], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "INT_REM":
                                    # output = input0 / input1;
                                    # unsigned
                                    if bitarch == DEFINES.BIT32:
                                        resarr.append(
                                            {'value': [ctypes.c_uint32(a1).value % ctypes.c_uint32(a2).value], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                    elif bitarch == DEFINES.BIT64:
                                        resarr.append(
                                            {'value': [ctypes.c_uint64(a1).value % ctypes.c_uint64(a2).value], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif node["opIDMnemonic"] == "INT_SREM":
                                    #  output = input0 % input1;
                                    # unsigned
                                    if bitarch == DEFINES.BIT32:
                                        resarr.append(
                                            {'value': [ctypes.c_int32(a1).value % ctypes.c_int32(a2).value], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                    elif bitarch == DEFINES.BIT64:
                                        resarr.append(
                                            {'value': [ctypes.c_int64(a1).value % ctypes.c_int64(a2).value], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})

            if len(resarr) > 0:
                return resarr

            return None
        elif (node["opIDMnemonic"] == "COPY") or (node["opIDMnemonic"] == "CAST"):
            if (checkLengthToLog(node, 1, parent=False, verbose=verbose)):
                return None
            return checkNode(node['children'][0], bitarch=bitarch, verbose=verbose)
        elif (node["opIDMnemonic"] == "INT_CARRY"):
            if (checkLengthToLog(node, 2, parent=False, verbose=verbose)):
                return None
            MAX_UNINT32 = 2 ** 32
            MAX_UNINT64 = 2 ** 64
            ln1 = checkNode(node['children'][0], bitarch=bitarch, verbose=verbose)
            ln2 = checkNode(node['children'][1], bitarch=bitarch, verbose=verbose)

            resarr = []
            if ln1 is not None and ln2 is not None:
                for n1 in ln1:
                    for a1 in n1['value']:
                        if not isinstance(a1, int):
                            continue
                        for n2 in ln2:
                            for a2 in n2['value']:
                                if not isinstance(a2, int):
                                    continue
                                if bitarch == DEFINES.BIT32:
                                    resarr.append(
                                        {'value': [int(
                                            bool((ctypes.c_uint32(a1).value + ctypes.c_uint32(a2).value) > MAX_UNINT32))],
                                         "isStr": False,
                                         "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif bitarch == DEFINES.BIT64:
                                    resarr.append(
                                        {'value': [int(
                                            bool((ctypes.c_uint64(a1).value + ctypes.c_uint64(a2).value) > MAX_UNINT64))],
                                         "isStr": False,
                                         "isPhi": n1['isPhi'] or n2['isPhi']})

            if len(resarr) > 0:
                return resarr

            return None

        elif (node["opIDMnemonic"] == "INT_SCARRY") or (node["opIDMnemonic"] == "INT_SBORROW"):
            if (checkLengthToLog(node, 2, parent=False, verbose=verbose)):
                return None
            MAX_INT32 = 2 ** 31 - 1
            MAX_INT64 = 2 ** 63 - 1
            MIN_INT32 = -2 ** 31
            MIN_INT64 = -2 ** 63

            ln1 = checkNode(node['children'][0], bitarch=bitarch, verbose=verbose)
            ln2 = checkNode(node['children'][1], bitarch=bitarch, verbose=verbose)

            resarr = []
            if ln1 is not None and ln2 is not None:
                for n1 in ln1:
                    for a1 in n1['value']:
                        if not isinstance(a1, int):
                            continue
                        for n2 in ln2:
                            for a2 in n2['value']:
                                if not isinstance(a2, int):
                                    continue

                                if (node["opIDMnemonic"] == "INT_SCARRY"):
                                    if bitarch == DEFINES.BIT32:
                                        b1 = ((ctypes.c_int32(a1).value + ctypes.c_int32(a2).value) > MAX_INT32)
                                        b2 = ((ctypes.c_int32(a1).value + ctypes.c_int32(a2).value) < MIN_INT32)
                                        resarr.append(
                                            {'value': [int(bool(b1 or b2))], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                    elif bitarch == DEFINES.BIT32:
                                        b1 = ((ctypes.c_int64(a1).value + ctypes.c_int64(a2).value) > MAX_INT64)
                                        b2 = ((ctypes.c_int64(a1).value + ctypes.c_int64(a2).value) < MIN_INT64)
                                        resarr.append(
                                            {'value': [int(bool(b1 or b2))], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})

                                elif (node["opIDMnemonic"] == "INT_SBORROW"):
                                    if bitarch == DEFINES.BIT32:
                                        resarr.append(
                                            {'value': [int(bool(ctypes.c_int32(a1).value < ctypes.c_int32(a2).value))],
                                             "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                    elif bitarch == DEFINES.BIT64:
                                        resarr.append(
                                            {'value': [int(bool(ctypes.c_int64(a1).value < ctypes.c_int64(a2).value))],
                                             "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})

            if len(resarr) > 0:
                return resarr

            return None

        elif (node["opIDMnemonic"] == "PTRSUB"):

            if len(node['children']) == 1:
                if (checkLengthToLog(node, 0, parent=False, verbose=verbose)):
                    return None
                return checkNode(node['children'][0], bitarch=bitarch, verbose=verbose)

            if (checkLengthToLog(node, 2, parent=False, verbose=verbose)):
                return None

            lptr = checkNode(node['children'][0], bitarch=bitarch, verbose=verbose)
            loffset = checkNode(node['children'][1], bitarch=bitarch, verbose=verbose)
            resarr = []
            if lptr is not None and loffset is not None:
                for ptr in lptr:
                    for p in ptr['value']:
                        if not isinstance(p, str):
                            continue
                        for offset in loffset:
                            for o in offset['value']:
                                if not isinstance(o, int):
                                    continue

                                resarr.append({'value': [p[o:]], 'addr': ptr['addr'] + '+' + str(o),
                                               "valuesLength": ptr["valuesLength"],
                                               "isStr": True, "isPhi": ptr['isPhi']})
            if len(resarr) > 0:
                return resarr

            return None

        elif (node["opIDMnemonic"] == "PTRADD"):

            # if it has 1 children means that is already resolve in ghidra script
            if len(node['children']) == 1:
                if (checkLengthToLog(node, 0, parent=False, verbose=verbose)):
                    return None
                return checkNode(node['children'][0], bitarch=bitarch, verbose=verbose)

            if (checkLengthToLog(node, 3, parent=False, verbose=verbose)):
                return None
            lptr = checkNode(node['children'][0], bitarch=bitarch, verbose=verbose)
            loffset = checkNode(node['children'][1], bitarch=bitarch, verbose=verbose)
            lelemsize = checkNode(node['children'][2], bitarch=bitarch, verbose=verbose)

            resarr = []
            if lptr is not None and loffset is not None and lelemsize is not None:
                for ptr in lptr:
                    for p in ptr['value']:
                        if not isinstance(p, str):
                            continue
                        for offset in loffset:
                            for o in offset['value']:
                                if not isinstance(o, int):
                                    continue
                                for elemsize in lelemsize:
                                    for e in elemsize['value']:
                                        if not isinstance(e, int):
                                            continue
                                        resarr.append({'value': [p[o * e:]], 'addr': ptr['addr'] + '+' + str(o * e),
                                                       "valuesLength": ptr["valuesLength"],
                                                       "isStr": True, "isPhi": ptr['isPhi']})
            if len(resarr) > 0:
                return resarr

            return None

        elif (node["opIDMnemonic"] == "MULTIEQUAL"):
            arr = []
            for ch in node['children']:
                l = checkNode(ch, bitarch=bitarch, verbose=verbose)
                if l is not None:
                    for item in l:
                        arr.append(item)

            if len(arr) > 0:
                return arr

            return None

        elif (node["opIDMnemonic"] == "PIECE"):
            if (checkLengthToLog(node, 2, parent=False, verbose=verbose)):
                return None
            ln1 = checkNode(node['children'][0], bitarch=bitarch, verbose=verbose)
            ln2 = checkNode(node['children'][1], bitarch=bitarch, verbose=verbose)

            resarr = []
            if ln1 is not None and ln2 is not None:
                for n1 in ln1:
                    for a1 in n1['value']:
                        for n2 in ln2:
                            for a2 in n2['value']:
                                if isinstance(a2, int) and isinstance(a1, int):
                                    if bitarch == DEFINES.BIT32:
                                        # 32 bit
                                        # input 1 and input 2 must add up to size of output!
                                        # output is 32 bit
                                        resarr.append(
                                            {'value': [((a1 << 16) & 0xFFFF0000) | ((a2) & 0x0000FFFF)], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                    elif bitarch == DEFINES.BIT64:
                                        resarr.append(
                                            {'value': [((a1 << 32) & 0xFFFFFFFF00000000) | ((a2) & 0x0000FFFFFFFF)], "isStr": False,
                                             "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif isinstance(a2, str) and isinstance(a1, str):
                                    resarr.append(
                                        {'value': [a1 + a2], "isStr": False, "isPhi": n1['isPhi'] or n2['isPhi']})
            if len(resarr) > 0:
                return resarr

            return None

        elif (node["opIDMnemonic"] == "SUBPIECE"):
            # output = input0(input1)
            if (checkLengthToLog(node, 2, parent=False, verbose=verbose)):
                return None
            ln1 = checkNode(node['children'][0], bitarch=bitarch, verbose=verbose)
            ln2 = checkNode(node['children'][1], bitarch=bitarch, verbose=verbose)

            resarr = []
            if ln1 is not None and ln2 is not None:
                for n1 in ln1:
                    for a1 in n1['value']:
                        for n2 in ln2:
                            for a2 in n2['value']:
                                if not isinstance(a2, int):
                                    continue

                                # no trunctate continue like copy
                                # change type...
                                if a2 == 0x0:
                                    resarr.append(
                                        {'value': [a1], "isStr": False, "isPhi": n1['isPhi'] or n2['isPhi']})
                                    continue

                                if isinstance(a1, int):
                                    resarr.append(
                                        {'value': [a1 >> a2], "isStr": False, "isPhi": n1['isPhi'] or n2['isPhi']})
                                elif isinstance(a1, str):
                                    if len(a1) > a2:
                                        # truncate a2 bytes
                                        resarr.append(
                                            {'value': [a1[a2:]], "isStr": False, "isPhi": n1['isPhi'] or n2['isPhi']})
            if len(resarr) > 0:
                return resarr

            return None
        # mnemonic of float trunc
        elif (node["opIDMnemonic"] == "TRUNC") or (node["opIDMnemonic"] == "INT2FLOAT")\
                or (node["opIDMnemonic"] == "FLOAT_ABS") or (node["opIDMnemonic"] == "FLOAT_NEG") \
                or (node["opIDMnemonic"] == "FLOAT_CEIL") or (node["opIDMnemonic"] == "FLOAT_SQRT") \
                or (node["opIDMnemonic"] == "FLOAT_FLOOR") or (node["opIDMnemonic"] == "FLOAT_ROUND") \
                or (node["opIDMnemonic"] == "FLOAT_NAN") or (node["opIDMnemonic"] == "FLOAT2FLOAT"):
            if (checkLengthToLog(node, 1, parent=False, verbose=verbose)):
                return None
            ln1 = checkNode(node['children'][0], bitarch=bitarch, verbose=verbose)

            resarr = []
            if ln1 is not None:
                for n1 in ln1:
                    for a1 in n1['value']:
                        if not isinstance(a1, int):
                            continue

                        if (node["opIDMnemonic"] == "TRUNC"):
                            # convert to float
                            f1 = tofloat(a1)
                            resarr.append(
                                    {'value': [int(f1)], "isStr": False, "isPhi": n1['isPhi']})
                        elif (node["opIDMnemonic"] == "INT2FLOAT"):
                            # leave it to hex, operations convert to float
                            resarr.append(
                                    {'value': [a1], "isStr": False, "isPhi": n1['isPhi']})
                        elif (node["opIDMnemonic"] == "FLOAT_ABS"):
                            # convert to float
                            f1 = tofloat(a1)
                            f1 = abs(f1)
                            # leave it to hex, operations convert to float
                            resarr.append(
                                    {'value': [float_to_hex(f1)], "isStr": False, "isPhi": n1['isPhi']})
                        elif (node["opIDMnemonic"] == "FLOAT_SQRT"):
                            # convert to float
                            f1 = tofloat(a1)
                            f1 = math.sqrt(f1)
                            # leave it to hex, operations convert to float
                            resarr.append(
                                    {'value': [float_to_hex(f1)], "isStr": False, "isPhi": n1['isPhi']})
                        elif (node["opIDMnemonic"] == "FLOAT_CEIL"):
                            # convert to float
                            f1 = tofloat(a1)
                            f1 = math.ceil(f1)
                            # leave it to hex, operations convert to float
                            resarr.append(
                                    {'value': [float_to_hex(f1)], "isStr": False, "isPhi": n1['isPhi']})
                        elif (node["opIDMnemonic"] == "FLOAT_FLOOR"):
                            # convert to float
                            f1 = tofloat(a1)
                            f1 = math.floor(f1)
                            # leave it to hex, operations convert to float
                            resarr.append(
                                    {'value': [float_to_hex(f1)], "isStr": False, "isPhi": n1['isPhi']})
                        elif (node["opIDMnemonic"] == "FLOAT_ROUND"):
                            # convert to float
                            f1 = tofloat(a1)
                            f1 = round(f1)
                            # leave it to hex, operations convert to float
                            resarr.append(
                                    {'value': [float_to_hex(f1)], "isStr": False, "isPhi": n1['isPhi']})
                        elif (node["opIDMnemonic"] == "FLOAT_NAN"):
                            # convert to float
                            f1 = tofloat(a1)
                            # leave it to hex, operations convert to float
                            resarr.append(
                                    {'value': [int(bool(math.isnan(f1)))], "isStr": False, "isPhi": n1['isPhi']})
                        elif (node["opIDMnemonic"] == "FLOAT2FLOAT"):
                            # convert to float
                            f1 = tofloat(a1)
                            # leave it to hex, operations convert to float
                            resarr.append(
                                    {'value': [float_to_hex(f1)], "isStr": False, "isPhi": n1['isPhi']})
                        elif (node["opIDMnemonic"] == "FLOAT_NEG"):
                            # convert to float
                            f1 = tofloat(a1)
                            f1 = -f1
                            # leave it to hex, operations convert to float
                            resarr.append(
                                    {'value': [float_to_hex(f1)], "isStr": False, "isPhi": n1['isPhi']})

            if len(resarr) > 0:
                return resarr

            return None

        elif (node["opIDMnemonic"] == "INDIRECT"):
            if (checkLengthToLog(node, 1, parent=False, verbose=verbose)):
                return None
            return checkNode(node['children'][0], bitarch=bitarch, verbose=verbose)
        elif (node["opIDMnemonic"] == "CALLIND"):
            if (checkLengthToLog(node, 1, parent=False, verbose=verbose)):
                return None
            return checkNode(node['children'][0], bitarch=bitarch, verbose=verbose)

    if verbose:
        log.logWF("NOT FOUND NODE: " + str(node))
    return None


def checkConst(node):
    if (node["nodeName"] == "CONST"):
        return getConst(node)
    elif (node["nodeName"] == "PHICONST"):
        return getConst(node, isPhi=True)

    return None


def getConst(node, isPhi=False):
    if (node["isString"] == True):
        return [{'value': node["ArrStringConstValue"], 'addr': node["addr"], "valuesLength": node["valuesLength"],
                 "isStr": True, "isPhi": isPhi}]
    else:
        return [{'value': [node["constValue"]], "isStr": False, "isPhi": isPhi}]


def checkLengthToLog(node, length, parent=False, plen=0, verbose=False, checkchild=True):
    if node['isLoop']:
        return True

    if node['isNull']:
        return True

    if checkchild == False and len(node['children']) > 0:
        if verbose:
            log.logWF("ERROR LENGTH OF NODE" + str(node))
        return True

    if len(node['children']) < length:
        if verbose:
            log.logWF("ERROR LENGTH OF NODE" + str(node))
        return True

    if parent:
        if len(node['parents']) > plen:
            if verbose:
                log.logWF("ERROR PARENT LENGTH OF NODE" + str(node))
            return True

    if not parent:
        if len(node['parents']) > 0:
            if verbose:
                log.logWF("ERROR PARENT" + str(node))
            return True

    return False


def tofloat(a):
    try:
        return struct.unpack('!f', bytes.fromhex(format(a, 'x')))[0]
    except:
        return float(a)

def float_to_hex(f):
    return int(hex(struct.unpack('<I', struct.pack('<f', f))[0]), 0)