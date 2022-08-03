import networkx as nx
from networkx.drawing.nx_agraph import graphviz_layout
import matplotlib.pyplot as plt


class CallGraph:

    def __init__(self, binaryName):
        self.g = nx.DiGraph()
        self.binary = binaryName
        self.normalSet = []
        self.indirectSet = []

    def save_graph(self, directory):

        for vfrom, vto in self.indirectSet:
            self.g.add_edge(vfrom, vto, style='dashed')

        for vfrom, vto in self.normalSet:
            self.g.add_edge(vfrom, vto)

        # write dot file to use with graphviz
        # run "dot -Tpng test.dot >test.png
        save_name = '{}-CallGraph'.format(self.binary)
        nx.nx_agraph.write_dot(self.g, str(directory / str(save_name + '.dot')))

    def addEdge(self, vfrom, vto, isIndirect=False):
        if isIndirect == True:
            self.indirectSet.append((vfrom, vto))
        else:
            self.normalSet.append((vfrom, vto))


class GraphAST:

    def __init__(self, binaryName, sinkJson):
        self.g = nx.Graph()
        self.binary = binaryName
        self.callerSink = sinkJson["functionName"]
        self.sink = sinkJson["targetFunctionName"]
        self.address = str(sinkJson["addr"])
        self.paramid = str(sinkJson["argIdx"])
        self.node_counter = 0

        # create
        callerSink_node = self.createNode(self.callerSink)
        sink_node = self.createNode(self.sink + "\n" + self.address)

        self.g.add_edge(callerSink_node, sink_node)

        self.addToGraphRecursive(sink_node, sinkJson)

    def save_graph(self, directory):
        # write dot file to use with graphviz
        # run "dot -Tpng test.dot >test.png
        save_name = '{}-0x{:X}-{}'.format(self.sink, int(self.address, 16), str(self.paramid))
        nx.nx_agraph.write_dot(self.g, str(directory / str(save_name + '.dot')))

    def createNode(self, name):
        ret = str(self.node_counter) + "-" + name
        self.node_counter = self.node_counter + 1
        return ret

    # recursive update all nodes and edges
    def addToGraphRecursive(self, parent, nodes):

        for ch in nodes["parents"]:
            node = self.getNodeName(ch, parent)

            node = self.createNode(node)
            self.g.add_edge(node, parent)

            self.node_counter = self.node_counter + 1

            # recursive
            self.addToGraphRecursive(node, ch)

        for ch in nodes["children"]:
            node = self.getNodeName(ch, parent)

            node = self.createNode(node)
            self.g.add_edge(parent, node)

            # recursive
            self.addToGraphRecursive(node, ch)

    def getNodeName(self, ch, parent):

        node = ch["nodeName"]

        if (ch["nodeName"] == "OPERATION"):
            node = node + "\n" + str(ch["opIDMnemonic"])
            if ch["opIDMnemonic"] == "PTRSUB" or ch["opIDMnemonic"] == "PTRADD":
                node = node + "\nRegister:" + ch["register"] + "\nOffset:" + ch["value"]
        elif (ch["nodeName"] == "THUNK"):
            node = node + "\n" + ch["functionName"]
        elif (ch["nodeName"] == "CONST") or (ch["nodeName"] == "PHICONST"):
            if (ch["isString"] == True):
                node = node + "\n" + "String = " + ",".join(ch["ArrStringConstValue"]) + " @0x" + ch["addr"]
            else:
                node = node + "\n" + "Value = " + hex(ch["constValue"])
        elif (ch["nodeName"] == "FUNCTION"):
            node = node + "\n" + ch["functionName"]
        elif (ch["nodeName"] == "PHIFUNCTION"):
            node = node + "\n" + ch["functionName"]
        elif (ch["nodeName"] == "HIGHPARAM"):
            node = node + "\n" + ch["functionName"] + " ,Param=" + str(ch["argIdx"])
        elif (ch["nodeName"] == "PARENTFUNCTION"):
            node = node + "\n" + ch["targetFunctionName"] + " FROM=" + ch["functionName"]

        if (parent.find("CALL") >= 0):
            node = node + ", Param=" + str(ch["argIdx"])

        if ("addr" in ch):
            node = node + "\n" + "@0x" + ch["addr"]

        if (ch["isLoop"] == True):
            node = node + "\n" + "LOOP"

        return node
