class Results:

    def __init__(self):
        self.uniqueBinaries = 0
        self.dupBinaries = 0

        self.uniqueLib = 0
        self.uniqueExec = 0

        self.dupLib = 0
        self.dupExec = 0

        self.uniqueSinks = set()

    def addUniqueSinksOnly(self, sink):
        self.uniqueSinks.add(sink)

    def addBinary(self, objBinary):
        self.uniqueBinaries = self.uniqueBinaries + 1

        if(objBinary.isLib()):
            self.uniqueLib = self.uniqueLib + 1
        elif (objBinary.isExec()):
            self.uniqueExec = self.uniqueExec + 1

    def alreadyAnalaysed(self, objBinary):
        self.dupBinaries = self.dupBinaries + 1

        if(objBinary.isLib()):
            self.dupLib = self.dupLib + 1
        elif (objBinary.isExec()):
            self.dupExec = self.dupExec + 1
