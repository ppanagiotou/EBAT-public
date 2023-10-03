import logging
import os
import time
from modules.DEFINES import CONFIGURATION


class SLOG:
    def __init__(self, name, level, isStream=True, mLOGDIR=None, moutputDir=None, filename=None):

        self.level = level
        if isStream:
            self.logger = self.createStreamLogger(name, level)
        else:
            logdir = moutputDir / mLOGDIR
            if not os.path.exists(logdir):
                os.mkdir(logdir)

            self.logger = self.createFileLogger(name, level, filename, logdir)

    def createStreamLogger(self, name, level):
        # create formatter
        formatter = logging.Formatter(fmt='%(asctime)s - %(threadName)s - %(name)s - %(levelname)s - %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S')
        # initialise stream logger
        logger = logging.getLogger(name)
        logger.setLevel(level)
        # create console handler and set level to debug
        ch = logging.StreamHandler()
        ch.setLevel(level)
        # add formatter to ch
        ch.setFormatter(formatter)
        # add ch to logger
        logger.addHandler(ch)

        return logger

    def createFileLogger(self, name, level, filename, logdir):
        # create formatter
        formatter = logging.Formatter(fmt='%(asctime)s - %(threadName)s - %(name)s - %(levelname)s - %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S')
        # Initialised file logger
        logger = logging.getLogger(name)
        logger.setLevel(level)

        # create console handler and set level to debug
        fh = logging.FileHandler("{0}/{1}".format(logdir, filename))
        fh.setLevel(level)

        # add formatter to ch
        fh.setFormatter(formatter)

        # add ch to logger
        logger.addHandler(fh)

        return logger

    def logm(self, message):
        if self.level == logging.INFO:
            self.logger.info(message)
        elif self.level == logging.DEBUG:
            self.logger.debug(message)
        elif self.level == logging.WARNING:
            self.logger.warning(message)
        elif self.level == logging.ERROR:
            self.logger.error(message)


class LOG:

    def __init__(self):
        self.loggerI = SLOG("info", logging.INFO)
        self.loggerD = SLOG("debug", logging.DEBUG)
        self.loggerW = SLOG("warning", logging.WARNING)
        self.loggerE = SLOG("error", logging.ERROR)

    def set_file_logs(self, outputDir):
        logdir = outputDir / CONFIGURATION.dict["LOGDIR"]
        if not os.path.exists(logdir):
            os.makedirs(logdir, exist_ok=True)

        self.loggerIF = SLOG(name="finfo", level=logging.INFO, isStream=False, mLOGDIR=CONFIGURATION.dict["LOGDIR"],
                             moutputDir=outputDir, filename=CONFIGURATION.dict["INFOLOGFILE"])
        self.loggerWF = SLOG(name="fwarning", level=logging.WARNING, isStream=False,
                             mLOGDIR=CONFIGURATION.dict["LOGDIR"],
                             moutputDir=outputDir, filename=CONFIGURATION.dict["WARNINGLOGFILE"])
        self.loggerDF = SLOG(name="fdebug", level=logging.DEBUG, isStream=False, mLOGDIR=CONFIGURATION.dict["LOGDIR"],
                             moutputDir=outputDir, filename=CONFIGURATION.dict["DEBUGOLOGFILE"])
        self.loggerEF = SLOG(name="ferror", level=logging.ERROR, isStream=False, mLOGDIR=CONFIGURATION.dict["LOGDIR"],
                             moutputDir=outputDir, filename=CONFIGURATION.dict["ERRORLOGFILE"])
        # log for timing
        self.loggerTF = SLOG(name="time", level=logging.INFO, isStream=False, mLOGDIR=CONFIGURATION.dict["LOGDIR"],
                             moutputDir=outputDir, filename=CONFIGURATION.dict["TIMELOGFILE"])

    def start_time(self):
        return time.time()

    def end_time(self, stime, start="", end="", var=None, accumulated=False):
        endtime = (time.time() - stime)
        self.loggerTF.logm(start + ", " + str(endtime) + ", " + end)
        if var is not None:
            if accumulated:
                var = var + endtime
            else:
                var = endtime

        return var

    def log(self, message):
        self.loggerI.logm(message)

    def logW(self, message):
        self.loggerW.logm(message)

    def logE(self, message):
        self.loggerE.logm(message)

    def logD(self, message):
        self.loggerD.logm(message)

    def logF(self, message):
        self.loggerIF.logm(message)

    def logWF(self, message):
        self.loggerWF.logm(message)

    def logEF(self, message):
        self.loggerEF.logm(message)

    def logDF(self, message):
        self.loggerDF.logm(message)

    def logTime(self, message, endtime):
        self.loggerTF.logm(message + ", " + str(endtime))


# create log object
log = LOG()
