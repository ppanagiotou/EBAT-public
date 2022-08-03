import re


class Version:
    # tools where
    CVE = 1
    GHIDRA = 2
    SIGNATURES = 3

    # version define only for cryptographic libraries
    UNKNOWN = 0
    OpenSSL = 1
    LIBC = 2
    LIBGCRYPT = 3  # GnuPG
    WolfSSL = 4
    KerberosV5 = 5
    Libmcrypt = 6
    CRYPTOPP = 7
    GnuTLS = 8
    mbedTLS = 9
    LibTomCrypt = 10
    Nettle = 11
    Libsodium = 12

    def __init__(self, type, date, version, version_name="", where=0):
        self.type = type
        self.date = date
        self.version = VersionNumber(version, type)
        self.version_name = version_name
        self.where = where

    def VersionToString(self):
        return self.version.VersionNumtoString()

    def toString(self):
        return self.getMnemonic() + " ," + self.VersionToString()

    def getMnemonic(self):

        if (self.type == self.OpenSSL):
            return "OpenSSL"
        elif (self.type == self.LIBC):
            return "LIBC"
        elif (self.type == self.LIBGCRYPT):
            return "LIBGCRYPT"
        elif (self.type == self.WolfSSL):
            return "WolfSSL"
        elif (self.type == self.KerberosV5):
            return "KerberosV5"
        elif (self.type == self.Libmcrypt):
            return "Libmcrypt"
        elif (self.type == self.CRYPTOPP):
            return "Crypto++"
        elif (self.type == self.GnuTLS):
            return "GnuTLS"
        elif (self.type == self.mbedTLS):
            return "mbed TLS/ PolarSSL"
        elif (self.type == self.LibTomCrypt):
            return "LibTomCrypt"
        elif (self.type == self.Nettle):
            return "Nettle"
        elif (self.type == self.Libsodium):
            return "Libsodium"

        if (self.version_name == ""):
            return "UNKNOWN"

        return self.version_name


def getMnemonicToVersionID(mnem):
    if (mnem == "OpenSSL"):
        return Version.OpenSSL
    elif (mnem == "LIBC"):
        return Version.LIBC
    elif (mnem == "LIBGCRYPT"):
        return Version.LIBGCRYPT
    elif (mnem == "WolfSSL"):
        return Version.WolfSSL
    elif (mnem == "KerberosV5"):
        return Version.KerberosV5
    elif (mnem == "Libmcrypt"):
        return Version.Libmcrypt
    elif (mnem == "Crypto++"):
        return Version.CRYPTOPP
    elif (mnem == "GnuTLS"):
        return Version.GnuTLS
    elif (mnem == "mbed TLS/ PolarSSL"):
        return Version.mbedTLS
    elif (mnem == "LibTomCrypt"):
        return Version.LibTomCrypt
    elif (mnem == "Nettle"):
        return Version.Nettle
    elif (mnem == "Libsodium"):
        return Version.Libsodium

    return Version.UNKNOWN


# libcrypto, libcrypt, libssl, libgcrypt, libwolfssl, libmcrypt, libcrypto++, libk5crypto, libmbedcrypto, libmbedtls, libpolarssl, libmbedx509, libgnutls,
def getVersionID(realname):
    version_id = Version.UNKNOWN
    if (realname == "libcrypto") or (realname == "libssl") or (realname == "openssl"):
        version_id = Version.OpenSSL
    elif realname == "libcrypt":
        version_id = Version.LIBC
    elif realname == "libgcrypt":
        version_id = Version.LIBGCRYPT
    elif realname == "libwolfssl" or realname == "libcyassl":
        version_id = Version.WolfSSL
    elif realname == "libk5crypto" or realname == "kerberos" or realname == "libkrb5":
        version_id = Version.KerberosV5
    elif realname == "libmcrypt":
        version_id = Version.Libmcrypt
    elif realname == "libcrypto++" or realname == "libcryptopp":
        version_id = Version.CRYPTOPP
    elif realname == "libgnutls" or realname == "gnutls-cli":
        version_id = Version.GnuTLS
    elif realname == "libmbedcrypto" or realname == "libmbedtls" or realname == "libpolarssl" or realname == "libmbedx509":
        version_id = Version.mbedTLS
    elif realname == "libtomcrypt":
        version_id = Version.LibTomCrypt
    elif realname == "libnettle":
        version_id = Version.Nettle
    elif realname == "libsodium":
        version_id = Version.Libsodium

    return version_id


class VersionNumber:

    def __init__(self, version, type):
        self.major = ""
        self.minor = ""
        self.patch = ""
        self.name = version
        self.type = type

        self.updateVersion(version)

    def VersionNumtoString(self):
        return str(self.major) + "." + str(self.minor) + "." + str(self.patch)

    # apache version numbering
    # MAJOR.MINOR.PATCH
    # http://apr.apache.org/versioning.html
    def updateVersion(self, version):

        arr = version.strip().split(".")

        try:
            self.major = arr[0]
        except IndexError:
            self.major = ""

        try:
            self.minor = arr[1]
        except IndexError:
            self.minor = ""

        try:
            self.patch = ".".join(arr[2:])
        except IndexError:
            self.patch = ""
