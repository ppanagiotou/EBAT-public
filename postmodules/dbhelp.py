import ast
import base64
import hashlib
import itertools
import json
import re
import shelve
from pathlib import Path

from packaging import version

from modules.helpfunctions import createDir
from datetime import datetime
import collections
import copy
from modules.DEFINES import DEFINES, CONFIGURATION

maptypes = {"OpenSSL": "openssl-release", "WolfSSL": "wolfssl-release", "MCRYPT": "mcrypt-release",
            "Nettle": "nettle-release", "Libsodium": "libsodium-release",
            "mbed TLS/ PolarSSL": "mbedtls-release", "GnuTLS": "gnutls-release", "LIBGCRYPT": "libgcrypt-release"}

maptypesother = {  # extra
    "LIBC": "libc-release", "KerberosV5": "KerberosV5-release", "Crypto++": "Crypto++-release",
    "LibTomCrypt": "LibTomCrypt-release"
}

excludeCryptoList = ["OpenSSL", "WolfSSL", "MCRYPT", "Nettle", "mbed TLS/ PolarSSL", "GnuTLS", "LIBGCRYPT", "Libsodium"]


def parse_version(v):
    try:
        return version.Version(v)
    except version.InvalidVersion:
        return version.LegacyVersion(v)


def hashproduct(product, name=None):
    m = hashlib.sha256()
    if name is not None:
        m.update(name.encode('utf-8'))
    else:
        m.update(product.name.encode('utf-8'))
    m.update(product.vendorName.encode('utf-8'))
    m.update(product.typeName.encode('utf-8'))
    return m.hexdigest()


# TODO replace calculated product, fid with orginal pid or even may remove the product from the fid equation will be better
def hashfirmware(product, firmware, name=None):
    m = hashlib.sha256()
    if name is not None:
        m.update(name.encode('utf-8'))
    else:
        m.update(product.name.encode('utf-8'))
    m.update(product.vendorName.encode('utf-8'))
    m.update(product.typeName.encode('utf-8'))
    m.update(firmware.firmwareName.encode('utf-8'))
    m.update(firmware.releaseDate.strftime('%d/%m/%Y').encode('utf-8'))
    return m.hexdigest()
