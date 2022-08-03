import gzip
import shutil

import py7zr
from py7zr import SevenZipFile


class archive7:

    def __init__(self, file):
        self.file = file
        self.lnamelist = []

    def extractall(self, dir):
        with SevenZipFile(self.file, 'r') as archive:
            self.lnamelist = archive.getnames()
            archive.extractall(path=dir)

    def namelist(self):
        return self.lnamelist

    def close(self):
        return


class archGzip:

    def __init__(self, file):
        self.file = file
        self.lnamelist = []

    def extractall(self, dir, block_size=65536):
        source_filepath = self.file
        dest_filepath = self.file + "_extracted"

        with gzip.open(source_filepath, 'rb') as s_file, \
                open(dest_filepath, 'wb') as d_file:
            shutil.copyfileobj(s_file, d_file, block_size)

        self.lnamelist.append(dest_filepath)

    def namelist(self):
        return self.lnamelist

    def close(self):
        return
