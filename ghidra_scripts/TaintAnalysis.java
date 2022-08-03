//TODO write a description for this script
// Based on https://www.riverloopsecurity.com/blog/2019/05/pcode/
//@author Paris Panagiotou
//@category EBAT
//@keybinding 
//@menupath 
//@toolbar 

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Deque;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.Expose;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.exception.NotYetImplementedException;
import ghidra.util.graph.DepthFirstSearch;
import ghidra.util.graph.DirectedGraph;
import ghidra.util.graph.Edge;
import ghidra.util.graph.Vertex;

public class TaintAnalysis extends HeadlessScript {
//load project configurations
class mProject {

	private boolean debug = false;
	private String input_file = null;
	private String crypto_file = null;
	public HashMap<String, InputSink> mapSinks = new HashMap<>();
	public HashMap<String, GroupSink> mapGroup = new HashMap<>();

	public mProject(String[] args) throws FileNotFoundException, IOException {
		// for every argument
		for (int i = 0; i < args.length; i++) {
			if (args[i].equals("debug")) {
				debug = true;
			} else if (args[i].equals("input")) {
				input_file = args[i + 1];
				i++;
			} else if (args[i].equals("crypto")) {
				crypto_file = args[i + 1];
				i++;
			}
		}

		// load rules
		if (input_file != null) {
			loadConfigurations();
		}
		
		if (crypto_file != null) {
			loadCryptoGroup();
		}
	}
	
	private void loadCryptoGroup() {
		
		Properties prop = new Properties();
		InputStream is = null;
		try {
		    is = new FileInputStream(this.crypto_file);
		} catch (FileNotFoundException ex) {
		    //
			return;
		}
		try {
		    prop.load(is);
		} catch (IOException ex) {
		    return;
		}
		
		
		Enumeration<Object> em = prop.keys();
		while(em.hasMoreElements()){
			  String str = (String)em.nextElement();
			  this.mapGroup.put(str, new GroupSink(prop.getProperty(str)));
		}
		
	}

	public int getNumberofRules() {
		return mapSinks.size();
	}
	
	public int getNumberofPostRules() {
		return mapGroup.size();
	}

	private void loadConfigurations() throws FileNotFoundException, IOException {
		try (BufferedReader br = new BufferedReader(new FileReader(input_file))) {
			String line;
			int count_line = 0;
			while ((line = br.readLine()) != null) {
				count_line++;

				// process the line if does not start with hash
				if ((line.startsWith("#")) || (line.isBlank()) || (line.isEmpty()) || line.startsWith("\n"))
					continue;

				// parse rules
				String[] arr = line.split(";");

				// minimum length = 5
				if (arr.length < 4)
					continue;

				// try to all arguments:type:rule
				HashMap<Integer, TaintedArgs> taintedArgs = new HashMap<>();
				for (int i = 4; i < arr.length; i++) {
					String[] arrtype = arr[i].strip().split(":");

					if (arrtype.length != 3)
						continue;

					try {
						taintedArgs.put(Integer.valueOf(arrtype[0].strip()),
								new TaintedArgs(arrtype[1].strip(), Integer.valueOf(arrtype[2].strip())));
					} catch (NumberFormatException e) {
						Msg.error(this, "Possible wrong format in apply rules @" + Integer.toString(count_line) + " = "
								+ e.getMessage());
						continue;
					}

				}

				// try to parse the constraints ARG1>ARG2
				for (int i = 4; i < arr.length; i++) {
					String[] arrtype = arr[i].strip().split("<");

					if (arrtype.length != 2)
						continue;

					try {
						// if they are both added
						if ((taintedArgs.containsKey(Integer.valueOf(arrtype[0].strip())))
								&& (taintedArgs.containsKey(Integer.valueOf(arrtype[1].strip())))) {
							
								// update predecessor of arg2
								taintedArgs.get(Integer.valueOf(arrtype[0].strip()))
										.SetSuccessors(Integer.valueOf(arrtype[1].strip()));
						}
					}catch (NumberFormatException e) {
						Msg.error(this, "Possible wrong format in apply rules @" + Integer.toString(count_line)
								+ " = " + e.getMessage());
						continue;
					}
				}

				try {
					mapSinks.put(arr[0].strip(), new InputSink(line, Integer.valueOf(arr[3].strip()), arr[0].strip(),
							arr[1], Integer.valueOf(arr[2].strip()), taintedArgs));
				} catch (NumberFormatException e) {
					Msg.error(this, "Possible wrong format in apply rules @" + Integer.toString(count_line) + " = "
							+ e.getMessage());
					continue;
				}

			}
		}

	}

	public boolean isDebug() {
		return debug;
	}

}

//input group sink functions
class GroupSink {
	
	private Integer keysize = null;
	private Integer ivsize = null;
	
	public GroupSink(String values) {
		
			String[] arr = values.split(",");
		   
		   
		   if (arr.length >=3){
				this.keysize = addorNone(arr[2].strip());
		   }
		   
		   if (arr.length >=6){
				this.ivsize = addorNone(arr[5].strip());
		   }
		
	}
	
	Integer getIVSize() {
		return this.ivsize;
	}
	
	Integer getKeySize() {
		return this.keysize;
	}
	
	
    private Integer addorNone(String s) {
    	
    	if (s.equals("") || s.equals("none")){
    		return null;
    	}
    	
		try {
			return Integer.valueOf(s.strip());
		}catch (NumberFormatException e) {
			// Msg.error(this, "Possible wrong format in apply groups @" + " = " + e.getMessage());
		}
		
		return null;
    }

}

//input sink functions
class InputSink {

	private String functionName;

	@SuppressWarnings("unused")
	private String functionSignature;

	private String rule;

	private int numberofParameters;

	@SuppressWarnings("unused")
	private int ruleCryptoType;

	// every arg has a TaintedArgs object
	public HashMap<Integer, TaintedArgs> taintedArgs;

	// List of order when topological sorting is apply
	public ArrayList<Integer> orderedArgs;

	private boolean hasCTX = false;

	public InputSink(String rule, int ruleCryptoType, String functionName, String functionSignature,
			int numberofParameters, HashMap<Integer, TaintedArgs> taintedArgs) {

		this.functionName = functionName;

		this.functionSignature = functionSignature;

		this.numberofParameters = numberofParameters;

		this.taintedArgs = taintedArgs;

		this.rule = rule;

		this.ruleCryptoType = ruleCryptoType;

		this.topoSort();

		for (Map.Entry<Integer, TaintedArgs> entry : taintedArgs.entrySet()) {
			Integer argnum = entry.getKey();
			TaintedArgs t = entry.getValue();
			if (t.getType().equals("CTX")) {
				this.hasCTX = true;
				//find CTX and put it first	
				this.orderedArgs.remove(argnum);
				this.orderedArgs.add(0, argnum);
				break;
			}

		}
	}

	// A recursive function used by topologicalSort
	void topologicalSortUtil(Integer v, HashMap<Integer, Boolean> visited, Deque<Integer> stack) {
		// Mark the current node as visited.
		visited.put(v, true);
		Integer i;

		// Recur for all the vertices adjacent to this
		// vertex
		Iterator<Integer> it = taintedArgs.get(v).GetSuccessors().iterator();
		while (it.hasNext()) {
			i = it.next();
			if (!visited.get(i))
				topologicalSortUtil(i, visited, stack);
		}

		// Push current vertex to stack which stores result
		stack.push(v);
	}

	private void topoSort() {
		int n = taintedArgs.size();
		HashMap<Integer, Boolean> visited = new HashMap<>();

		this.orderedArgs = new ArrayList<>(n);
		Deque<Integer> stack = new ArrayDeque<>();

		for (Integer keys : taintedArgs.keySet())
			visited.put(keys, false);

		for (Integer keys : taintedArgs.keySet())
			if (visited.get(keys) == false)
				topologicalSortUtil(keys, visited, stack);

		while (stack.isEmpty() == false) {
			orderedArgs.add(stack.pop());
		}
	}

	public String getRule() {
		return this.rule;
	}

	public int getNumParameters() {
		return this.numberofParameters;
	}

	public String getName() {
		return functionName;
	}

	public boolean checkSink(Function f) {
		if (f.isExternal() || f.isThunk()) {
			// parameter on thunk functions sometimes it creates wrappers
			// but this wrappers references to correct location with arguments
			if (f.getName().equalsIgnoreCase(this.functionName)) {
				// && (f.getParameterCount() == this.numberofParameters))
				return true;
			}
		}

		return false;

	}

	public boolean hasCTX() {
		return this.hasCTX;
	}

}

class mNode {

	@Expose(serialize = true, deserialize = true)
	String FunctionName;

	Function nodeFunction;
	Address addrentrypoint;

	@Expose(serialize = true, deserialize = true)
	long EntryPoint;

	int key;

	public mNode(Function f) {
		this.addrentrypoint = f.getEntryPoint();
		this.EntryPoint = addrentrypoint.getOffset();
		nodeFunction = f;
		FunctionName = f.getName();
		this.key = f.hashCode();
	}

	public String getFunctionName() {
		return this.FunctionName;
	}

	@Override
	public int hashCode() {
		return this.key;
	}

	/**
	 * @return true iff and only if the given object is a Vertex with the same key.
	 */
	@Override
	public boolean equals(Object o) {
		if (o instanceof mNode) {
			return hashCode() == ((mNode) o).hashCode();
		}
		return false;
	}

}

class mPair {
	@Expose(serialize = true, deserialize = true)
	ArrayList<mNode> edgeList = new ArrayList<>();

	@Expose(serialize = true, deserialize = true)
	boolean isIndirect;

	public mPair(mNode a, mNode b, boolean indirect) {
		edgeList.add(a);
		edgeList.add(b);
		isIndirect = indirect;
	}

	@Override
	public int hashCode() {
		return (edgeList.get(0).hashCode() ^ edgeList.get(1).hashCode());
	}

	/**
	 * @return true iff and only if the given object is a Vertex with the same key.
	 */
	@Override
	public boolean equals(Object o) {
		if (o instanceof mPair) {
			return hashCode() == ((mPair) o).hashCode();
		}
		return false;
	}

}

//which arguments are tainted
class TaintedArgs {

	public static final int SYMMETRIC_CONSTANT_KEY = 11;
	public static final int SYMMETRIC_CONSTANT_IV = 12;

	private String type;
	private int ruleid;
	private HashSet<Integer> defaultValues;
	private HashSet<Integer> successors;

	public TaintedArgs(String type, int ruleid) {
		this.defaultValues = new HashSet<>();
		// parse type of it is a bytes to get possible default values
		if (type.startsWith("bytes")) {
			String[] arrtype = type.strip().split("=");

			this.type = arrtype[0];
			for (int i = 1; i < arrtype.length; i++) {
				this.defaultValues.add(Integer.valueOf(arrtype[i].strip()));
			}
		} else {
			this.type = type;
		}

		this.ruleid = ruleid;
		this.successors = new HashSet<>();
	}

	public void SetSuccessors(Integer obj) {
		this.successors.add(obj);
	}

	public HashSet<Integer> GetSuccessors() {
		return this.successors;
	}
	
	public HashSet<Integer> getDefaultValues() {
		return this.defaultValues;
	}
	
	public void addDefaultValue(Integer d) {
		this.defaultValues.add(d);
	}
	
	public void clearDefaultValues() {
		this.defaultValues.clear();
	}


	public boolean hasSuccessors() {
		return (!(this.successors.isEmpty()));
	}

	public String getType() {
		return this.type;
	}

	public int getRuleID() {
		return this.ruleid;
	}
	
	// copy constructor
	TaintedArgs(TaintedArgs obj){
		this.type = obj.getType();
		this.ruleid = obj.getRuleID();
		this.defaultValues = new HashSet<>();
		this.successors = new HashSet<>();

		this.defaultValues.addAll(obj.getDefaultValues());
		this.successors.addAll(obj.GetSuccessors());
	}

}

// Try to resolve indirect references
// aggressive approach
class FunctionIndirectReferencesE {
	Listing listing;
	Memory memory;
	Program curProg;
	FlatProgramAPI fpapi;
	Address curAddr;

	int ArchBits;

	int offset;

	static final int BIT32 = 32;
	static final int BIT64 = 64;
	static final int BITOFFSET32 = 4;
	static final int BITOFFSET64 = 4;

	static final int MAX_SIZE = 32;
	int MAX_ARRAY_LAST;

	boolean isDebug;

	// the indirect edges that will return
	// a function that uses the pointer -> is used to call to multiple functions
	@SuppressWarnings("hiding")
	HashMap<Function, HashSet<Function>> indirectEdges = new HashMap<>();

	public FunctionIndirectReferencesE(Program cP, Address cA) {
		curProg = cP;
		fpapi = new FlatProgramAPI(curProg);
		curAddr = cA;
		listing = curProg.getListing();
		memory = curProg.getMemory();

		// return 32 for 32bit current program architecture
		// return 64 for 64bit current program architecture
		ArchBits = curProg.getMinAddress().getSize();
		this.setOffset();
	}

	private void setOffset() {
		offset = BITOFFSET32;
		if (ArchBits == BIT64) {
			offset = BITOFFSET64;
		}

		MAX_ARRAY_LAST = offset * MAX_SIZE;
	}

	void setIndirectEdges(Set<Function> setf, Function pointertofunc) {
		for (Function f : setf) {
			if (!indirectEdges.containsKey(pointertofunc)) {
				indirectEdges.put(pointertofunc, new HashSet<>());
			}

			indirectEdges.get(pointertofunc).add(f);

		}
	}

	void tryToAdd(Data nextData, HashSet<Function> setf) {
		// if is address
		if (nextData.getValue() instanceof Address) {
			Address addrs = (Address) nextData.getValue();
			if (addrs != null) {
				// get the found function
				Function pfunc = fpapi.getFunctionAt(addrs);
				if (pfunc != null) {
					setIndirectEdges(setf, pfunc);
				}
			}
		}
	}

	public HashMap<Function, HashSet<Function>> ComputeIndirectReferences() throws AddressFormatException {

		// Iterate through all defined data
		DataIterator dataIterator = listing.getDefinedData(true);
		while (dataIterator.hasNext()) {
			Data nextData = dataIterator.next();

			// if it is a pointer
			if (nextData.isPointer()) {
				// hold last references for pointer that is not array
				HashSet<Function> lastreferences = new HashSet<>();

				// get all references
				ReferenceIterator it = nextData.getReferenceIteratorTo();


				while (it.hasNext()) {
					Reference nextref = it.next();
					Function callingFunction = fpapi.getFunctionContaining(nextref.getFromAddress());
					if (callingFunction != null) {
						lastreferences.add(callingFunction);
					}
				}

				tryToAdd(nextData, lastreferences);

			} else // if it is an array
			if (nextData.isArray()) {
				if ((nextData.getLength() % offset) != 0) {
					continue;
				}

				HashSet<Function> getreferences = new HashSet<>();
				ReferenceIterator it = nextData.getReferenceIteratorTo();
				while (it.hasNext()) {
					Reference nextref = it.next();
					Function callingFunction = fpapi.getFunctionContaining(nextref.getFromAddress());
					if (callingFunction != null) {
						getreferences.add(callingFunction);
					}
				}

				// for every element in the array
				for (int ioff = 0; ioff < nextData.getLength(); ioff += offset) {
					// get the element
					Data element = nextData.getComponentAt(ioff);
					if (element != null) {
						if (element.isPointer()) {
							tryToAdd(element, getreferences);
						} else if (element.getValue() instanceof Scalar) {
							byte[] xbytes = new byte[offset];

							for (int ib = ioff; ib < (offset + ioff); ib++) {
								Data isx = nextData.getComponentAt(ib);

								Scalar x = (Scalar) isx.getValue();

								xbytes[ib - ioff] = (byte) x.getUnsignedValue();
							}

							if (!curProg.getMemory().isBigEndian()) {
								xbytes = reverseByteArray(xbytes, offset, offset);
							}

							Address gotoaddr = curAddr.getAddress(bytesToHex(xbytes));

							if (gotoaddr != null) {
								Function pfunc = fpapi.getFunctionAt(gotoaddr);
								if (pfunc != null) {
									setIndirectEdges(getreferences, pfunc);
								}
							}
						}
					}
				}
			}
		}

		return indirectEdges;
	}

	public byte[] reverseByteArray(byte[] bytes, int arrayLen, int reverseLen) {
		if (reverseLen == 0) {
			return bytes;
		}
		byte[] revbytes;
		if (arrayLen % reverseLen == 0) {
			revbytes = new byte[arrayLen];
			for (int i = 0; i < arrayLen; i += reverseLen) {
				for (int j = 0; j < reverseLen; j++) {
					revbytes[i + j] = bytes[i + (reverseLen - j - 1)];
				}
			}
		} else {
			revbytes = null;
		}
		return revbytes;
	}

	// https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
	private final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

	public String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = HEX_ARRAY[v >>> 4];
			hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
		}
		return new String(hexChars);
	}

}

class mFlowInfo {
	// class for node in a source-sink flow

	@Expose(serialize = true, deserialize = true)
	public String nodeName;

	public boolean isParent;
	private boolean isChild;
	private Function function;
	private Function targetFunction;

	@Expose(serialize = true, deserialize = true)
	private String functionName;
	@Expose(serialize = true, deserialize = true)
	private String functionSignatureName;

	@Expose(serialize = true, deserialize = true)
	private String targetFunctionName;
	@Expose(serialize = true, deserialize = true)
	private String targetSignatureName;

	@Expose(serialize = true, deserialize = true)
	private int argIdx;
	@Expose(serialize = true, deserialize = true)
	private String typeofArg;

	@Expose(serialize = true, deserialize = true)
	public String addr;

	private Address objaddr;

	@Expose(serialize = true, deserialize = true)
	public boolean isLoop = false;

	@Expose(serialize = true, deserialize = true)
	public boolean isNull = false;
	
	private Address callSiteAddress;

	@Expose(serialize = true, deserialize = true)
	private ArrayList<mFlowInfo> children = new ArrayList<mFlowInfo>();
	@Expose(serialize = true, deserialize = true)
	private ArrayList<mFlowInfo> parents = new ArrayList<mFlowInfo>();

	private mFlowInfo lastParent;

	public mFlowInfo(String nodename, int argIdx) {
		this.argIdx = argIdx;
		this.nodeName = nodename;
	}

	public mFlowInfo(String nodename, Address addr, int argIdx) {
		this.argIdx = argIdx;
		this.objaddr = addr;
		this.addr = this.objaddr.toString();
		this.nodeName = nodename;
	}

	public mFlowInfo(Function function, int argIdx) {
		this.function = function;
		this.functionName = function.getName();

		this.isChild = true;

		this.nodeName = "FUNCTION";

		this.functionSignatureName = function.getSignature().getPrototypeString(true);
		this.argIdx = argIdx;
	}

	public mFlowInfo(Function function, Function targetFunction, Address callSiteAddress, int argIdx, String typeofArg) {
		this.function = function;
		this.callSiteAddress = callSiteAddress;
		this.targetFunction = targetFunction;
		this.argIdx = argIdx;

		this.typeofArg = typeofArg;

		this.isParent = true;

		this.nodeName = "PARENTFUNCTION";

		this.targetFunctionName = targetFunction.getName();
		this.functionName = function.getName();

		this.functionSignatureName = function.getSignature().getPrototypeString(true);
		this.targetSignatureName = targetFunction.getSignature().getPrototypeString(true);

		this.objaddr = callSiteAddress;
		this.addr = this.objaddr.toString();
	}

	public void appendNewParent(mFlowInfo parent) {
		this.parents.add(parent);
		// printf("Adding new parent... \n");
	}

	public void appendNewChild(mFlowInfo child) {
		this.children.add(child);
		this.lastParent = this;
		// printf("Adding new child...\n");
	}

	public boolean isConst() {
		return (this.nodeName.equals("CONST") || this.nodeName.equals("PHICONST"));
	}

	public boolean isThunk() {
		return (this.nodeName.equals("THUNK"));
	}

	public mFlowInfo getlastParent() {
		return this.lastParent;
	}

	public boolean isParent() {
		return isParent;
	}

	public boolean isChild() {
		return isChild;
	}

	public ArrayList<mFlowInfo> getChildren() {
		return children;
	}

	public ArrayList<mFlowInfo> getParents() {
		return parents;
	}

	public Function getFunction() {
		return function;
	}

	public Function getTargetFunction() {
		return targetFunction;
	}

	public Address getAddress() {
		return callSiteAddress;
	}

	public int getArgIdx() {
		return argIdx;
	}

}


class ConstNode extends mFlowInfo {

	@Expose(serialize = true, deserialize = true)
	public long constValue = 0;

	@Expose(serialize = true, deserialize = true)
	public boolean isString;

	@Expose(serialize = true, deserialize = true)
	private ArrayList<String> ArrStringConstValue;

	@Expose(serialize = true, deserialize = true)
	private HashSet<Integer> valuesLength;

	public ConstNode(long value, int argIdx) {
		super("CONST", argIdx);
		super.nodeName = "CONST";
		this.constValue = value;
	}

	public ConstNode(ArrayList<String> str, Address addr, int argIdx, HashSet<Integer> valuesLength) {
		super("CONST", addr, argIdx);
		this.ArrStringConstValue = str;
		this.isString = true;
		this.valuesLength = valuesLength;
	}
}

class HighParamNode extends mFlowInfo {

	@Expose(serialize = true, deserialize = true)
	public int totalArg;

	public HighParamNode(Function f, int argIdx, int totalArg) {
		super(f, argIdx);
		super.nodeName = "HIGHPARAM";
		this.totalArg = totalArg;
	}
}

class OperationNode extends mFlowInfo {
	@Expose(serialize = true, deserialize = true)
	public int opID;

	@Expose(serialize = true, deserialize = true)
	public String opIDMnemonic;
	
	@Expose(serialize = true, deserialize = true)
	public String register;
	
	@Expose(serialize = true, deserialize = true)
	public String value;

	public OperationNode(int op, Address addr, int argIdx, PcodeOp pcode) {
		super("OPERATION", addr, argIdx);
		this.opID = op;
		this.opIDMnemonic = PcodeOp.getMnemonic(op);
		
		this.updatePcodeOp(pcode);
	}
	
	public void updatePcodeOp(PcodeOp pcode)
	{
		// just print more details on those 2 pcode ops
		// this does not effect the AST
		switch (this.opID) {
		
			case PcodeOp.PTRSUB:
			case PcodeOp.PTRADD:{
				this.register = pcode.getInput(0).toString();
				this.value = pcode.getInput(1).toString();
				break;
			}
						
			default:
				break;
		}
	}
}

//child class for representing our "sink" function
class Sink extends mFlowInfo {

	@Expose(serialize = true, deserialize = true)
	public int ruleid;

	@Expose(serialize = true, deserialize = true)
	public String rule;

	@Expose(serialize = true, deserialize = true)
	public int totalArg;

	@Expose(serialize = true, deserialize = true)
	public HashMap<String, Boolean> algorithm;
	
	@Expose(serialize = true, deserialize = true)
	public ArrayList<String> dstrings;
	

	public Sink(Function newFunction, Function newTargetFunction, Address newAddr, int ArgId, String typeofArg,
			String rule, int ruleid) {
		super(newFunction, newTargetFunction, newAddr, ArgId, typeofArg);
		super.nodeName = "SINK";
		super.isParent = false; // hacky
		this.totalArg = newFunction.getParameterCount();
		this.rule = rule;
		this.ruleid = ruleid;
		this.algorithm = new HashMap<>();
		this.dstrings = new ArrayList<>();
	}

	public void updateAlgorithm(String a, boolean isPhi) {
		this.algorithm.put(a, isPhi);
	}

	public void updateAlgorithm(HashMap<String, Boolean> sa) {
		for (Map.Entry<String, Boolean> a : sa.entrySet())
		{
			this.algorithm.put(a.getKey(), a.getValue());
		}
	}
	
	public void updateDefinedStrings(ArrayList<String> arr) {
		for(String e : arr) {
			this.dstrings.add(e);
		}
	}
}

class ThunkFunctionNode extends mFlowInfo {
	public ThunkFunctionNode(Function f, int argIdx) {
		super(f, argIdx);
		super.nodeName = "THUNK";
	}
}

class AbstractCallGraph {

	DirectedGraph g;

	HashMap<mNode, Vertex> nodes = new HashMap<>();

	HashSet<mPair> edges = new HashSet<>();

	HashMap<mNode, Boolean> Callingsinks = new HashMap<>();

	Function functionEntry = null;
	mNode nentry = null;
	Vertex ventry = null;

	public AbstractCallGraph() {
		this.g = new DirectedGraph();
	}

	public void setEntry(Function entry) throws Exception {
		this.functionEntry = entry;
		this.nentry = new mNode(entry);
	}

	public void updateVertexEntry() {
		this.ventry = nodes.get(this.nentry);
	}

	public boolean hasEntry() {
		if (this.functionEntry != null)
			return true;
		return false;
	}

	public boolean addEdge(mNode from, mNode to, boolean isSink, boolean isIndirect) {
		if (isSink == true) {
			this.Callingsinks.put(from, false);
		}

		return addEdge(from, to, isIndirect);
	}

	public boolean addEdge(mNode from, mNode to, boolean isIndirect) {
		Vertex fv = null;
		if (!nodes.containsKey((from))) {
			// create from
			fv = new Vertex(from);
			nodes.put(from, fv);
			g.add(fv);
		} else {
			fv = nodes.get(from);
		}

		Vertex tv = null;
		if (!nodes.containsKey(to)) {
			// create to
			tv = new Vertex(to);
			nodes.put(to, tv);
			g.add(tv);
		} else {
			tv = nodes.get(to);
		}

		mPair edge = new mPair(from, to, isIndirect);
		if (edges.contains(edge))
			return false;

		edges.add(edge);

		g.add(new Edge(fv, tv));

		return true;

	}

	public void checkEntry(Set<Function> fset) {
		if (this.functionEntry != null) {
			if (this.ventry != null) {
				Vertex[] initialSeeds = { this.ventry };

				DepthFirstSearch dfs = new DepthFirstSearch(this.g, initialSeeds, false, true, false);

				for (Function f : fset) {
					mNode initialNode = new mNode(f);
					Vertex initialVertex = nodes.get(initialNode);
					if (!dfs.isUnseen(initialVertex)) {
						this.Callingsinks.put(initialNode, true);
					}
				}
			}
		}
	}

	public HashMap<mNode, Vertex> getNodes() {
		return nodes;
	}

	public HashMap<String, Boolean> getCallingSinks() {

		HashMap<String, Boolean> ret = new HashMap<>();

		for (Map.Entry<mNode, Boolean> entry : this.Callingsinks.entrySet()) {
			ret.put(entry.getKey().getFunctionName(), entry.getValue());
		}

		return ret;
	}

	public HashSet<mPair> getEdges() {
		return edges;
	}

}



// child class representing variables / flows that are phi inputs, e.g., any PhiFlow object
// is directly an input to a MULTIEQUAL phi node
class PhiFlow extends mFlowInfo {
	@Expose(serialize = true, deserialize = true)
	public long constValue = 0;

	@Expose(serialize = true, deserialize = true)
	public boolean isString;

	@Expose(serialize = true, deserialize = true)
	private ArrayList<String> ArrStringConstValue;

	@Expose(serialize = true, deserialize = true)
	private HashSet<Integer> valuesLength;

	public PhiFlow(long newConstValue, int argIdx) {
		super("PHICONST", argIdx);
		this.constValue = newConstValue;

	}

	public PhiFlow(ArrayList<String> newStrConstValue, Address addr, int argIdx, HashSet<Integer> valuesLength) {
		super("PHICONST", addr, argIdx);
		this.ArrStringConstValue = newStrConstValue;
		this.isString = true;
		this.valuesLength = valuesLength;
	}

	public PhiFlow(Function newFunction, int argIdx) {
		super(newFunction, argIdx);
		super.nodeName = "PHIFUNCTION";
	}

	public PhiFlow(Function newFunction, Function newTargetFunction, Address newAddr, int newArgIdx) {
		super(newFunction, newTargetFunction, newAddr, newArgIdx, null);
	}
}

class CTX {
	//#define 		   EVP_CTRL_SET_KEY_LENGTH		   0x1
	//# define         EVP_CTRL_AEAD_SET_IVLEN         0x9
	//# define         EVP_CTRL_GCM_SET_IVLEN          EVP_CTRL_AEAD_SET_IVLEN
	//# define         EVP_CTRL_CCM_SET_IVLEN          EVP_CTRL_AEAD_SET_IVLEN
	// OpenSSL defines
	public static final int OPENSSL   = 0;
	public static final int EVP_CTRL_AEAD_SET_IVLEN = 0x9;
	public static final int EVP_CTRL_SET_KEY_LENGTH = 0x1;
	/* AEAD cipher deduces payload length and returns number of bytes
	 * required to store MAC and eventual padding. Subsequent call to
	 * EVP_Cipher even appends/verifies MAC.
	 */
	/* Used by composite AEAD ciphers, no-op in GCM, CCM... */
	// #define		EVP_CTRL_AEAD_SET_MAC_KEY	0x17
	public static final int EVP_CTRL_AEAD_SET_MAC_KEY = 0x17;
	// # define         EVP_CTRL_CCM_SET_L              0x14
	public static final int EVP_CTRL_CCM_SET_L = 0x14;
	
	// Very old but still found it
	public static final int LIBGCRYPT   = 1;
	public static final int GCRYCTL_SET_KEY  = 1;
	public static final int GCRYCTL_SET_IV   = 2;
	
	HashSet<Long> addresses;

	private HashMap<String, Boolean> ciphertype;

	int keylength;
	int ivlength;
	int type;

	int arg;
	
	int LIBRARY;

	HashMap<Integer, Integer> typearg;

	CTX(String fname) {
		addresses = new HashSet<Long>();
		typearg = new HashMap<Integer, Integer>();
		ciphertype = new HashMap<String, Boolean>();
		type = -1;
		arg = -1;
		keylength = 0;
		ivlength = 0;
		
		LIBRARY = OPENSSL;
		if (fname.equals("gcry_cipher_ctl")) {
			LIBRARY = LIBGCRYPT;
		}
		
	}

	public void addKey(long k) {
		addresses.add(k);
	}

	public void addCipherType(String s, boolean isPhi) {
		this.ciphertype.put(s, isPhi);
	}

	public void addCipherType(HashMap<String, Boolean> sa) {
		for (Map.Entry<String, Boolean> a : sa.entrySet())
		{
			this.ciphertype.put(a.getKey(), a.getValue());
		}

	}
	
	public HashMap<String, Boolean> getCipherType(){
		return this.ciphertype;
	}
	
	public boolean isCipherTypeEmpty(){
		return this.ciphertype.isEmpty();
	}

	/**
	 * @return
	 */
	@Override
	public boolean equals(Object o) {

		if (o instanceof CTX) {
			return !(Collections.disjoint(this.addresses, ((CTX) o).addresses));
		}

		return false;
	}
	
	// TODO (FUTURE) more CTRL Features
	public void tryUpdate(int ltype, int larg) {
		
		if ((larg == 0) || (larg == -1)){
			return;
		}
		
		if ((ltype == EVP_CTRL_AEAD_SET_IVLEN) || (ltype == EVP_CTRL_CCM_SET_L)) {
			ivlength = larg;
		}
		else
		if ((ltype == EVP_CTRL_SET_KEY_LENGTH) || (ltype == EVP_CTRL_AEAD_SET_MAC_KEY)) {
			keylength = larg;
		}
		
		if (LIBRARY == LIBGCRYPT) {
			if (ltype == GCRYCTL_SET_IV) {
				ivlength = larg;
			}
			else
			if (ltype == GCRYCTL_SET_KEY) {
				keylength = larg;
			}
		}

		// update
		this.typearg.put(ltype, larg);
	}


	public void updateCTX(String fname, boolean isPhi, HashMap<String, GroupSink> mapGroup) {
		
		boolean isAdd = true;
		
		if (mapGroup.containsKey(fname)) {
			
			Integer getkeysize = mapGroup.get(fname).getKeySize();
			if(getkeysize != null) {
				// to bytes
				this.keylength = (getkeysize/8);
			}

			Integer getivsize = mapGroup.get(fname).getIVSize();
			if(getivsize != null) {
				// to bytes
				this.ivlength = (getivsize/8);
			}
			
		}
		else {
			this.addCipherType("NOT-FOUND:" + fname, isPhi);
			isAdd = false;
		}
		
		
		if (isAdd == true) {
			this.addCipherType(fname, isPhi);
		}
	}

}

	public static final int NO_ARGUMENTS = 0;

	private DecompInterface decomplib;

	private HashMap<Address, Integer> traverse = new HashMap<>();
	private HashSet<mFlowInfo> finalnodes = new HashSet<>();
	public TaintedArgs currentTaintedObj;

	mProject proj = null;
	// Print the AST
	GsonBuilder builder = null;

	AbstractCallGraph graph;

	HashMap<Function, HashSet<Function>> indirectEdges;

	// context defuse
	HashSet<CTX> defuse = new HashSet<>();
	
	HashMap<PcodeOpAST, Function> defuseIndirect;

	CTX currentCTX = null;
	
	private int LIMIT_FLATTEN_LOOP = 3*2 + 1;
	
	private int LIMIT_EXTRACTION_BYTE = 1048578; //1 Mbyte
	
	/*
	 * set up the decompiler
	 */
	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decompInterface = new DecompInterface();

		DecompileOptions options;
		options = new DecompileOptions();
		PluginTool tool = state.getTool();
		if (tool != null) {
			OptionsService service = tool.getService(OptionsService.class);
			if (service != null) {
				ToolOptions opt = service.getOptions("Decompiler");
				options.grabFromToolAndProgram(null, opt, program);
			}
		}
		decompInterface.setOptions(options);

		/*
		 * Toggle whether or not calls to the decompiler process (via the
		 * decompileFunction method) produce C code. The default is to always compute C
		 * code, but some applications may only need the syntax tree or other function
		 * information Parameters: val - = true, to produce C code, false otherwise
		 * Returns: true if the decompiler process accepted the new state
		 */
		decompInterface.toggleCCode(true);
		
		/*
		 * his method toggles whether or not the decompiler produces a syntax tree (via
		 * calls to decompileFunction). The default is to always produce a syntax tree,
		 * but some applications may only need C code. Parameters: val - = true, to
		 * produce a syntax tree, false otherwise Returns: true if the decompiler
		 * process, accepted the change of state
		 */
		decompInterface.toggleSyntaxTree(true);
		
		/*
		 * "decompile" - this is the default, and performs all analysis steps suitable
		 * for producing C code. "normalize" - omits type recovery from the analysis and
		 * some of the final clean-up steps involved in making valid C code. It is
		 * suitable for creating normalized pcode syntax trees of the dataflow.
		 * "firstpass" - does no analysis, but produces an unmodified syntax tree of the
		 * dataflow from the "register" - does ???. "paramid" - does required amount of
		 * decompilation followed by analysis steps that send parameter measure
		 * information for parameter id analysis. raw pcode.
		 */
		decompInterface.setSimplificationStyle("decompile");
		

		/* boolean toggleJumpLoads​(boolean val) Toggle whether or not
		 * the decompiler process should return information about tables used to recover
		 * switch statements.
		 */
		decompInterface.toggleJumpLoads(true);
		
		/*
		 * TODO: (FUTURE) add MAYBE MORE DECOMPILER FEATURE
		 *
		 * boolean toggleParamMeasures​(boolean val) Toggle whether or not calls to the
		 * decompiler process (via the decompileFunction method) produce Parameter
		 * Measures.
		 * 
		 */
		
		return decompInterface;
	}

	public HighFunction decompileFunction(Function f) {
		HighFunction hfunction = null;

		try {
			DecompileResults dRes = decomplib.decompileFunction(f, decomplib.getOptions().getDefaultTimeout(),
					getMonitor());

			hfunction = dRes.getHighFunction();
		} catch (Exception exc) {
			exc.printStackTrace();
		}

		return hfunction;
	}

	

	/*
	 * Given a function, analyze all sites where it is called, looking at how the
	 * parameter at the call site specified by paramSlot is derived. This is for
	 * situations where we determine that a varnode we are looking at is a parameter
	 * to the current function - we then have to analyze all sites where that
	 * function is called to determine possible values for that parameter.
	 */
	//TODO (FUTURE): analyzeCallSites handle more reference types
	private mFlowInfo analyzeCallSites(mFlowInfo path, Function function, int paramSlot, boolean isPhi, Varnode callingV)
			throws InvalidInputException, NotYetImplementedException, NotFoundException {

		// get the p-codeOp of the calling varnode
		PcodeOp def = callingV.getDef();

		// get the calling address: Context Sensitive Taint Analysis
		Address callingAddr = null;

		if ((def != null) && (def.getSeqnum().getTarget() != null)) {
			if(proj.isDebug()) {
				printf("Calling v = 0x%x\n", def.getSeqnum().getTarget().getOffset());
			}
			callingAddr = def.getSeqnum().getTarget();
		}

		ReferenceIterator referencesTo = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint());

		mFlowInfo currentPath = null;

		for (Reference currentReference : referencesTo) {

			Address fromAddr = currentReference.getFromAddress();

			// get the callsite that we are called! Context sensitive
			if (callingAddr != null) {
				if (!callingAddr.equals(fromAddr))
					continue;
			}

			Function callingFunction = getFunctionContaining(fromAddr);

			if (callingFunction == null) {
				if(proj.isDebug()) {
					printf("Could not get calling function @ 0x%x\n", fromAddr.getOffset());
				}
				continue;
			}
			
			if (proj.isDebug()) {
				printf("analyzeCallSites(..., %s, ...) - found calling function @ 0x%x [%s] - %s\n", function.getName(),
						fromAddr.getOffset(), callingFunction.getName(), currentReference.getReferenceType());
			}
		
			if (currentReference.getReferenceType() == RefType.COMPUTED_CALL) {
				//if (proj.isDebug()) {
					printf("\nTODO HANDLE COMPUTED CALL %d == %d\n\n", callingFunction.getParameterCount(),
							function.getParameterCount());
				//}
				// possibly wrapper added automatically by compiler call this recursive
				if ((function.getName() == callingFunction.getName())
						&& (function.getParameterCount() == callingFunction.getParameterCount())
						&& (function != callingFunction)) {
					analyzeCallSites(path, callingFunction, paramSlot, isPhi, callingV);
				}
			}
			// if the reference is a UNCONDITIONAL_CALL
			else if (currentReference.getReferenceType() == RefType.UNCONDITIONAL_CALL) {
				if (proj.isDebug()) {
					printf("found unconditional call %s -> %s\n",
							getFunctionContaining(currentReference.getFromAddress()).getName(), function.getName());
				}

				Function thatcalling = getFunctionContaining(currentReference.getFromAddress());

				// Heavily based off of code at ShowConstantUse.java:729.
				HighFunction hfunction = decompileFunction(callingFunction);
				
				if (hfunction == null) {
					printf("Failed to decompile function %s\n", callingFunction.getName());
					continue;
				}

				// get the p-code ops at the address of the reference
				Iterator<PcodeOpAST> ops = hfunction.getPcodeOps(fromAddr.getPhysicalAddress());

				// now loop over p-code ops ops looking for the CALL operation
				while (ops.hasNext() && !monitor.isCancelled()) {

					PcodeOpAST currentOp = ops.next();

					if ((currentOp.getOpcode() == PcodeOp.CALL)|| (currentOp.getOpcode() == PcodeOp.BRANCH) 
							||(currentOp.getOpcode() == PcodeOp.CBRANCH)) {
						Address parentAddress = currentOp.getSeqnum().getTarget();

						mFlowInfo parentNode = null;

						// get the function which is called by the CALL operation
						Function targetFunction = getFunctionAt(currentOp.getInput(0).getAddress());
						if (targetFunction == null) {
							//something went wrong on getting the function
							continue;
						}

						// construct and add the appropriate node to our path

						if (!isPhi) {
							parentNode = new mFlowInfo(thatcalling, targetFunction, parentAddress, paramSlot, null);
						} else {
							parentNode = new PhiFlow(thatcalling, targetFunction, parentAddress, paramSlot);
						}

						// dispatch to analysis of the particular function callsite we are examining to
						// determine how the parameter is defined
						currentPath = analyzeFunctionCallSite(parentNode,
								getFunctionContaining(currentReference.getFromAddress()), currentOp, paramSlot);

						path.appendNewParent(currentPath);
					}
					// try to resolve indirect calls
					// save them to a def-use list
					else if ((currentOp.getOpcode() == PcodeOp.CALLIND) || (currentOp.getOpcode() == PcodeOp.BRANCHIND)) {
						
						Address parentAddress = currentOp.getSeqnum().getTarget();
						
						Function targetFunction = processIndirectVarnode(currentOp.getInput(0));

						if (targetFunction == null) {
							continue;
						}
						
						// construct and add the appropriate node to our path
						mFlowInfo parentNode = null;
						if (!isPhi) {
							parentNode = new mFlowInfo(thatcalling, targetFunction, parentAddress, paramSlot, null);
						} else {
							parentNode = new PhiFlow(thatcalling, targetFunction, parentAddress, paramSlot);
						}

						// dispatch to analysis of the particular function callsite we are examining to
						// determine how the parameter is defined
						currentPath = analyzeFunctionCallSite(parentNode,
								getFunctionContaining(currentReference.getFromAddress()), currentOp, paramSlot);

						path.appendNewParent(currentPath);
						
						}
					}
			}
			else {
				if(proj.isDebug()) {
					// TODO (FUTURE): analyzeCallSites handle more reference types
					printf("TODO handle Reference Type %s\n", currentReference.getReferenceType().getName());
				}
			}

		}

		return path;
	}

	/*
	 * This function analyzes a function called on the way to determining an input
	 * to our sink e.g.:
	 * 
	 * int x = calledFunction(); sink(x);
	 * 
	 * We find the function, then find all of it's RETURN pcode ops, and analyze
	 * backwards from the varnode associated with the RETURN value.
	 * 
	 * weird edge case, we can't handle funcs that are just wrappers around other
	 * functions, e.g.: func(){ return rand() };
	 */
	private void analyzeCalledFunction(mFlowInfo path, Function f, boolean isPhi, Varnode callingV, int argID, boolean isPointer)
			throws NotYetImplementedException, InvalidInputException, NotFoundException {

		// get the p-code op defining the varnode
		PcodeOp def = callingV.getDef();

		if ((def != null) && (def.getSeqnum().getTarget() != null)) {
			if (proj.isDebug())
				printf("Calling v = 0x%x\n", def.getSeqnum().getTarget().getOffset());
		}

		// if it is Thunk end do not analyse
		if ((f.isThunk()) || (f.isExternal())) {
			mFlowInfo thunkNode = new ThunkFunctionNode(f, argID);
			path.appendNewChild(thunkNode);

			// try to update current context
			if ((currentTaintedObj.getType().equals("CTX")) || (currentTaintedObj.getType().equals("CTYPE"))) {
				currentCTX.updateCTX(f.getName(), isPhi, this.proj.mapGroup);
			}

			if (proj.isDebug()) {
				printf("EXTERNAL END\n");
				printf("--> Could not resolve return value from %s\n", f.getName());
			}

			return;
		}

		mFlowInfo newFlow = null;
		if (!isPhi) {
			newFlow = new mFlowInfo(f, argID);
			path.appendNewChild(newFlow);
		} else {
			newFlow = new PhiFlow(f, argID);
			path.appendNewChild(newFlow);
		}

		HighFunction hfunction = decompileFunction(f);
		if (hfunction == null) {
			printf("Failed to decompile function!");
			return;
		}
		if (proj.isDebug()) {
			printf("Function %s entry @ 0x%x\n", f.getName(), f.getEntryPoint().getOffset());
		}

		Iterator<PcodeOpAST> ops = hfunction.getPcodeOps();

		// Loop through the functions p-code ops, looking for RETURN
		boolean isFound = false; //is found at least ones
		while (ops.hasNext() && !monitor.isCancelled()) {
			PcodeOpAST pcodeOpAST = ops.next();
			
			if (pcodeOpAST.getOpcode() != PcodeOp.RETURN) {
				continue;
			}

			// from here on, we are dealing with a PcodeOp.RETURN
			// 0 is the OFFSET on return instruction
			for (int i = 1; i < pcodeOpAST.getNumInputs(); i++) {
				// get the varnode for the function's return value
				Varnode returnedValue = pcodeOpAST.getInput(i);

				if (returnedValue == null) {
					printf("--> Could not resolve return value from %s\n", f.getName());
					continue;
				}
				
				if (proj.isDebug()) {
					printf("Found returned AST %s\n", pcodeOpAST.toString());
				}

				// if we had a phi earlier, it's been logged, so going forward we set isPhi back
				// to false
				processOneVarnode(newFlow, f, returnedValue, false, callingV, argID, isPointer, 0);
				isFound = true;
			}
		}
		
		if (isFound == false){
			path.isNull = true;
		}
	}

	private ArrayList<String> getPossibleTypeValue(Address addr) {
		// we want only integer for bit or byte force it
		// if it is type int maybe through trace we find something else! check for
		// string and if not found return the int
		if (currentTaintedObj.getType().equals("bit") || currentTaintedObj.getType().equals("byte") 
				|| currentTaintedObj.getType().equals("int"))
			return null;

		ArrayList<String> str = null;
		try {
			str = getDataAtAddr(addr, currentTaintedObj.getType());
		} catch (AddressFormatException e) {
			return null;
		}
		return str;
	}

	private void AddConstNode(mFlowInfo path, boolean isPhi, ArrayList<String> arrstr, long value, Address addr,
			int argID) {
		// either it's just a constant, or an input to a phi...
		if (!isPhi) {
			mFlowInfo terminal;
			if (arrstr == null) {
				terminal = new ConstNode(value, argID);
			} else {
				terminal = new ConstNode(arrstr, addr, argID, currentTaintedObj.getDefaultValues());
			}
			path.appendNewChild(terminal);
			if (currentTaintedObj.hasSuccessors())
				finalnodes.add(terminal);
		} else {
			PhiFlow terminalPhi;
			if (arrstr == null) {
				terminalPhi = new PhiFlow(value, argID);
			} else {
				terminalPhi = new PhiFlow(arrstr, addr, argID, currentTaintedObj.getDefaultValues());
			}
			path.appendNewChild(terminalPhi);
			if (currentTaintedObj.hasSuccessors())
				finalnodes.add(terminalPhi);
		}

		if (currentTaintedObj.getType().equals("type")) {
			if (arrstr == null) {
				currentCTX.type = (int) value;
			}
		} 
		else 
		if (currentTaintedObj.getType().equals("arg")) {
			if (arrstr == null) {
				currentCTX.arg = (int) value;
			}
		}
		else 
		if (currentTaintedObj.getType().equals("keysize")) {
			if (arrstr == null) {
				currentCTX.keylength = (int) value;
			}
		} 

	}

	// get data at addresss
	private ArrayList<String> getDataAtAddr(Address addr, String type) throws AddressFormatException {
		/* Very strange way to get a real address,
		* varnode address return a type const that leads us to not get the data type correclty
		* Force new address for the current address
		*/
		Address daddr = currentAddress.getAddress(Long.toHexString(addr.getOffset()));


		// Get string at an address, if present
		Data data = getDataAt(daddr);
		// return array of data
		// if it is bytes -> string is base64 converted
		ArrayList<String> retarr = new ArrayList<>();
		// parse bytes type
		if (type.equals("bytes")) {
			// automatically
			try {
				HashSet<Integer> defaultValues = currentTaintedObj.getDefaultValues();
				if (defaultValues.size() > 0) {
					// get default values
					// for every size of values try to get the bytes
					for (Integer dv : defaultValues) {
						if (dv <= 0) {
							continue;
						}
						
						if(dv > LIMIT_EXTRACTION_BYTE) {
							printf("LIMIT_EXTRACTION_BYTE = %d", dv);
							dv = LIMIT_EXTRACTION_BYTE;
						}
						

						byte barr[] = new byte[dv];
						// get bytes of size byte array length 
						currentProgram.getMemory().getBytes(daddr, barr);
						
						// barr now has the bytes from memory
						// endianness is not a problem -> depends on the library how to treat the output
						/*
						if(!currentProgram.getMemory().isBigEndian())
						{
							barr = reverseByteArray(barr, barr.length, barr.length);
							if (barr == null){
								throw new Exception("Error in reverseByteArray");
							}
						}
						*/
						 
						if (proj.isDebug()) {
							printf("byte string value base64: %s , size = %d\n", Base64.getEncoder().encodeToString(barr),dv);
						}

						retarr.add(Base64.getEncoder().encodeToString(barr));
					}

					return retarr;
				}

			} catch (Exception e) {
				//pass try other types
			}
		}

		// try to get the string if already is defined
		if (data != null) {
			StringDataInstance str = StringDataInstance.getStringDataInstance(data);
			String s = str.getStringValue();

			if (s != null) {
				if (proj.isDebug()) {
					printf("possible string value: %s\n", s);
					printf("length = %d\n", str.getStringLength());
				}

				retarr.add(s);
				return retarr;
			}
		}

		// if data is null check if it is a string
		if (type.equals("string") || type.equals("bytes")) {
			// automatically force the type
			try {
				// remove the data type
				removeDataAt(daddr);
				// add manually the type
				data = createAsciiString(daddr);

				StringDataInstance str = StringDataInstance.getStringDataInstance(data);
				String s = str.getStringValue();

				if (s != null) {
					if (proj.isDebug())
						printf("after type possible string value: %s\n", s);
					retarr.add(s);
					return retarr;
				}

			} catch (Exception e) {
				//pass
			}
		}

		// if all failed return null
		return null;
	}
	
	
	private Address resolvePointer(Varnode parm, long offset, boolean force)
	{
		if ((parm.isAddress() || parm.isAddrTied()) && (!parm.isRegister())) {
		
			// resolve the pointer
			Data data = getDataAt(parm.getAddress());
			if (data != null) {
				if (data.isPointer())
				{
					Address toaddr = (Address) data.getValue();
					if (toaddr == null){
						 // * Keep in mind this varnode may also correspond to a defined register 
						 // * if true is returned and {@link #isRegister()} return false.  
						return null;
					}
					//Pointer addition (offset is negative)
					Long toaddress = toaddr.getOffset() + offset;

					try {
						// return the memory address
						return currentAddress.getAddress(Long.toHexString(toaddress));
					} catch (AddressFormatException e) {
						return null;
					}
				}
			}
			
			if(force)
			{
				//create pointer
				if(createPointer(parm.getAddress())) {
					//resolve it and return
					return resolvePointer(parm, offset, false);
				}
			}
		}
		
		return null;
	}
	
	
	private mFlowInfo processStackVariable(mFlowInfo newNodeOp, Function f, Varnode baseVal, int offsetVal, boolean isPhi, 
			Varnode v, Varnode callingV,int argID) throws NotYetImplementedException, InvalidInputException, NotFoundException {
		if (baseVal.isRegister()){

			// get the variable from the stack frame
			StackFrame s = f.getStackFrame();
			//printf("reg??? %s, %d", s.toString(), offsetVal);
			Variable x = s.getVariableContaining(offsetVal);
			if (x == null) {
				return newNodeOp;
			}
			
			if(proj.isDebug()) {
				printf("var = %s , addr = %s, offset = %d, datatype = %s", x.toString(), x.getMinAddress().toString(), x.getFirstUseOffset(), x.getDataType().toString());
			}
	
			// if it is a stack variable
			if (x.isStackVariable()){
	
				Varnode vf = x.getFirstStorageVarnode();
				Varnode vl = x.getLastStorageVarnode();

				if(proj.isDebug()) {
					printf("vf = %s , %s", vl.toString(), vf.getAddress().toString());
					printf("vl = %s", vl.toString());
				}
				
				HighFunction high = decompileFunction(f);
				if (high == null) {
					printf("ERROR: Failed to decompile function!\n");
					return newNodeOp;
				}
				
				// return all PcodeOps (alive or dead) ordered by SequenceNumber
				Iterator<PcodeOpAST> ops = high.getPcodeOps();

				// iterate over all p-code ops in the function
				while (ops.hasNext() && !monitor.isCancelled()) {
					PcodeOpAST pcodeOpAST = ops.next();

					// we want to find the usage of the stack variable
					if (pcodeOpAST.getOutput() == null){
						continue;
					}

					// both and taint all if stack output is input to other varnode
					// backward tracing not work as expected, stuck on dereferencing local stack pointer
					if (pcodeOpAST.getOutput().getAddress().equals(vl.getAddress()) || pcodeOpAST.getOutput().getAddress().equals(vf.getAddress())) {
						if(proj.isDebug()) {
						    printf("TODO proceed with offset %s: %s", v.getDef().getMnemonic(), baseVal.toString());
							printf("pcodeOpAST = %s", pcodeOpAST.toString());
						}
						newNodeOp = processOnePcode(newNodeOp, f, pcodeOpAST, isPhi, v, callingV, argID, true, offsetVal);
					}
				}
			}
		}
		
		return newNodeOp;
	}
	
	
	/*
	 * 
	 * This function handles one varnode
	 * 
	 * If the varnode is a constant, we are done, create a constant node and return
	 * 
	 * If the varnode is associated with a parameter to the function, we then find
	 * each site where the function is called, and analyze how the parameter varnode
	 * at the corresponding index is derived for each call of the function
	 * 
	 * If the varnode is not constant or a parameter, we get the p-code op which
	 * defines it, and then recursively trace the one or more varnodes associated
	 * with that varnode (tracing backwards), and see how they are defined
	 * 
	 */
	private mFlowInfo processOneVarnode(mFlowInfo path, Function f, Varnode v, boolean isPhi, Varnode callingV, int argID, boolean isPointer, int offset)
			throws NotYetImplementedException, InvalidInputException, NotFoundException {

		// check if varnode is null
		if (v == null) {
			printf("processOneVarnode(): Null varnode?\n");
			path.isNull = true;
			return path;
		}
		
		
		if (proj.isDebug())
		{
			if(v != null) {
				printf("processOneVarnode() %s\n", v.toString());
			}
		}
		
		// get the p-code op defining the varnode
		// may this address not exists
		Address pcaddr = null;
		try {
			pcaddr = v.getPCAddress();
			if (pcaddr == null){
				pcaddr = v.getAddress();
			}
			if (currentTaintedObj.getType().equals("CTX")) {
				if (pcaddr.getOffset() != 0x0){
					currentCTX.addKey(pcaddr.getOffset());
				}
			}
		}
		catch (Exception e){
			//pass
		}

		
		if (pcaddr != null){
			boolean init = true;
			// check path
			if (traverse.containsKey(pcaddr)) {
				init = false;
				if (proj.isDebug()) {
					printf("TODO CHECK POSSIBLE LOOP\n");
				}
	
				int counter = traverse.get(pcaddr);
				traverse.put(pcaddr, counter + 1);
	
				if (counter >= LIMIT_FLATTEN_LOOP) {
					path.isLoop = true;
					path.addr = pcaddr.toString();
					return path;
				}
			}
			
			if (init)
			{
				// save the path after exploration
				traverse.put(pcaddr, 0);
			}
		}

		// If the varnode is constant, we are done, save it off
		if (v.isConstant()) {
			if (proj.isDebug())
				printf("\t\t\tprocessOneVarnode: Addr or Constant! - %s\n", v.toString());

			long value = v.getOffset() + offset;

			// get argument if it is a string
			ArrayList<String> str = null;
			try {
				str = getPossibleTypeValue(currentAddress.getAddress(Long.toHexString(value)));
			} catch (AddressFormatException e) {
				//pass
			}

			AddConstNode(path, isPhi, str, value, v.getAddress(), argID);

			// done! return
			return path;
		}
		
		
		// possible to high parameter
		// pointer needs to explicitly resolve the pointers
		if ((v.isAddress()||v.isAddrTied()) && !v.isRegister())
		{
			boolean force = false;
			if(isPointer) {
				force = true;
			}
				
			Address addrpointer = resolvePointer(v, offset, force);
			if (addrpointer!=null)
			{
				// get argument if it is a string
				ArrayList<String> str = null;
				long value = v.getOffset();
				str = getPossibleTypeValue(addrpointer);
				if (str != null) {
					AddConstNode(path, isPhi, str, value, addrpointer, argID);
					return path;
				}
			}
			else
			{
				long value = v.getOffset() + offset;
	
				// get argument if it is a string
				ArrayList<String> str = null;
				try {
					str = getPossibleTypeValue(currentAddress.getAddress(Long.toHexString(value)));
					if(str != null)
					{
						AddConstNode(path, isPhi, str, value, v.getAddress(), argID);
						// done! return
						return path;
					}
				} catch (AddressFormatException e) {
					//pass
				}
			}
		}

		/*
		 * check if this varnode is in fact a parameter to the current function
		 * 
		 * we retrieve the high level decompiler variable associated with the varnode
		 * and check if it is an instance of HighParam, a child class of HighVariable
		 * representing a function parameter. This seems like an unncessarily complex
		 * way of figuring out if a given varnode is a parameter, but I found examples
		 * of doing it this way in officially-published plugins bundled with Ghidra, and
		 * I couldn't figure out a better way to do it
		 */

		HighVariable hvar = v.getHigh();

		if (hvar instanceof HighParam) {
			if (proj.isDebug()) {
				printf("Varnode is function parameter -> parameter #%d... %s\n", ((HighParam) hvar).getSlot(), // the																						// index
						v.toString());
			}

			mFlowInfo hip = new HighParamNode(f, ((HighParam) hvar).getSlot(), f.getParameterCount());
			path.appendNewChild(hip);

			// ok, so we do have a function parameter. Now we want to analyze all
			// sites in the binary where this function is called, seeing how varnode
			// at the parameter index that we are is derived
			analyzeCallSites(hip, f, ((HighParam) hvar).getSlot(), isPhi, callingV);

			return path;
		}

		// get the p-code op defining the varnode
		PcodeOp def = v.getDef();

		if (def == null) {
			if (proj.isDebug()) {
				printf("NULL DEF!\n");
			}
			path.isNull = true;
			return path;
		}
		
		return processOnePcode(path, f, def, isPhi, v, callingV, argID, isPointer, offset);
	}
		
		
	private mFlowInfo processOnePcode(mFlowInfo path, Function f, PcodeOp def, boolean isPhi, Varnode v, Varnode callingV, int argID, boolean isPointer, int offset) throws NotYetImplementedException, InvalidInputException, NotFoundException {
		
		// get the enum value of the p-code operation that defines our varnode
		int opcode = def.getOpcode();
		
		// create a new operation node
		mFlowInfo newNodeOp = new OperationNode(opcode, v.getPCAddress(), argID, def);
		
		Address pcaddr = null;
		try {
			pcaddr = v.getPCAddress();
			if (pcaddr == null){
				pcaddr = v.getAddress();
			}
			if (currentTaintedObj.getType().equals("CTX")) {
				if (pcaddr.getOffset() != 0x0){
					currentCTX.addKey(pcaddr.getOffset());
				}
			}
		}
		catch (Exception e){
			//pass
		}
		
		if (pcaddr != null){
			boolean init = true;
			// check path
			if (traverse.containsKey(pcaddr)) {
				init = false;
				if (proj.isDebug()) {
					printf("TODO CHECK POSSIBLE LOOP\n");
				}
	
				int counter = traverse.get(pcaddr);
				traverse.put(pcaddr, counter + 1);
	
				if (counter >= LIMIT_FLATTEN_LOOP) {
					path.isLoop = true;
					path.addr = pcaddr.toString();
					return path;
				}
			}
			
			if (init)
			{
				// save the path after exploration
				traverse.put(pcaddr, 0);
			}
		}


		path.appendNewChild(newNodeOp);
		
		if(proj.isDebug()) {
			printf("processOnePcode() %s\n", def.toString());
		}

		/*
		 * Switch on the opcode enum value. Note that this script doens't support all
		 * possible p-code operations, just common ones that I encountered while writing
		 * code to test this script
		 * 
		 * see Ghidra's included docs/languages/html/pcodedescription.htm for a listing
		 * of p-code operations, and check the "next" link at the bottom for even more
		 */
		switch (opcode) {

		/*
		 * Handle p-code ops that take one input. We just pass through here, analyzing
		 * single varnode that the p-code operation takes.
		 * 
		 * For example, see "NOT EAX" here. Our output varnode is just the negation of
		 * the input varnode. So upon seeing a INT_NEGATE p-code operation, we just
		 * examine the single varnode that is its input
		 * 
		 * malloc(~return3());
		 * 
		 * 004008a9 NOT EAX EAX = INT_NEGATE EAX 004008ab CDQE RAX = INT_SEXT EAX
		 * 004008ad MOV RDI,RAX RDI = COPY RAX 004008b0 CALL malloc RSP = INT_SUB RSP,
		 * 8:8 STORE ram(RSP), 0x4008b5:8 CALL *[ram]0x400550:8
		 * 
		 * 
		 */
		case PcodeOp.INT_NEGATE:
		case PcodeOp.INT_ZEXT:
		case PcodeOp.INT_SEXT:
		case PcodeOp.INT_2COMP:
		case PcodeOp.BOOL_NEGATE:{
			processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, isPointer, offset);
			break;
		}
		
		
		case PcodeOp.CAST:
		case PcodeOp.COPY: {
			processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, isPointer, offset);
			break;
		}
		
		/*
		 * Handle p-code ops that take two inputs.
		 * 
		 * The output (our current varnode) = "(pcodeop input1 input2)" or
		 * "input1 [pcodeop] input2":
		 * 
		 * Because we are not tracing out all the values that effect values going into
		 * our sink function, just terminating constants and function calls, we don't
		 * log constants associated with these operations
		 * 
		 * So if we had a current varnode x:
		 * 
		 * "x = y + 5" would result in us calling processOneVarnode(y) but ignoring that
		 * "5"
		 * 
		 * "x = y + z" would result in us calling processOneVarnode(y) and
		 * processOneVarnode(z)
		 * 
		 */
		case PcodeOp.INT_ADD:
		case PcodeOp.INT_SUB:
		case PcodeOp.INT_MULT:
		case PcodeOp.INT_DIV:
		case PcodeOp.INT_REM:
		case PcodeOp.INT_SDIV:
		case PcodeOp.INT_SREM:
		case PcodeOp.INT_AND:
		case PcodeOp.INT_OR:
		case PcodeOp.INT_XOR:
		case PcodeOp.INT_LEFT:
		case PcodeOp.INT_RIGHT:
		case PcodeOp.INT_SRIGHT:
		case PcodeOp.INT_CARRY:
		case PcodeOp.INT_SCARRY:
		case PcodeOp.INT_SBORROW:{

			// if (!def.getInput(0).isConstant()) {
			// only process if not constant
			processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, isPointer, offset);
			// }
			// if(!def.getInput(1).isConstant()) {
			// only process if not constant
			processOneVarnode(newNodeOp, f, def.getInput(1), isPhi, callingV, argID, isPointer, offset);
			// }
			break;
		}
		
		case PcodeOp.FLOAT_ADD:
		case PcodeOp.FLOAT_SUB:
		case PcodeOp.FLOAT_MULT:
		case PcodeOp.FLOAT_DIV:{

			// if (!def.getInput(0).isConstant()) {
			// only process if not constant
			processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, isPointer, offset);
			// }
			// if(!def.getInput(1).isConstant()) {
			// only process if not constant
			processOneVarnode(newNodeOp, f, def.getInput(1), isPhi, callingV, argID, isPointer, offset);
			// }
			break;
		}
		
		case PcodeOp.FLOAT_INT2FLOAT:
		case PcodeOp.FLOAT_NEG: 
		case PcodeOp.FLOAT_FLOAT2FLOAT:
		case PcodeOp.FLOAT_NAN:{
			processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, isPointer, offset);
			break;
		}
		case PcodeOp.CALLIND: 
		case PcodeOp.BRANCHIND:{
			
			// get function of the given call
			Function pf = processIndirectVarnode(def.getInput(0));
			if (pf != null) {

				callingV = v;
	
				analyzeCalledFunction(newNodeOp, pf, isPhi, callingV, argID, isPointer);
				
				break;
			}
			
			// need to resolve the indirect node!!!
			if (proj.isDebug()) {
				printf("TODO NOT IMPLEMENTED: %s\n", PcodeOp.getMnemonic(opcode));
				// get parameters
				for (int i = 0; i < def.getNumInputs(); i++) {
					printf("Arguments of %s %d:%s\n", PcodeOp.getMnemonic(opcode), i, def.getInput(i).toString());
				}
			}

			break;
		}

		/*
		 * Handle CALL p-code ops by analyzing the functions that they call
		 */
		case PcodeOp.CALL:
		case PcodeOp.BRANCH:{
			
			// if is not address or address tied
			if (def.getInput(0).isAddress() || def.getInput(0).isAddrTied()) {
			
				if (proj.isDebug())
					printf("Located source - call to %x [%s]\n", def.getInput(0).getAddress().getOffset(),
							getFunctionAt(def.getInput(0).getAddress()).getName());
	
				// get function of the given call
				Function pf = getFunctionAt(def.getInput(0).getAddress());
				if (pf != null) {
					callingV = v;
		
					analyzeCalledFunction(newNodeOp, pf, isPhi, callingV, argID, isPointer);
					
					break;
				}
			}
			
			if(proj.isDebug()) {
				printf("Argument CALL or branch but not a valid address %s\n", def.getInput(0).toString());
			}
			break;
		}
		case PcodeOp.CBRANCH:{
			
			processOneVarnode(newNodeOp, f, def.getInput(1), isPhi, callingV, argID, isPointer, offset);
			// if is not address or address tied
			if (def.getInput(0).isAddress() || def.getInput(0).isAddrTied()) {
			
				if (proj.isDebug()) {
					printf("Located source - call to %x [%s]\n", def.getInput(0).getAddress().getOffset(),
							getFunctionAt(def.getInput(0).getAddress()).getName());
				}
	
				// get function of the given call
				Function pf = getFunctionAt(def.getInput(0).getAddress());
				if (pf != null) {
					callingV = v;
		
					analyzeCalledFunction(newNodeOp, pf, isPhi, callingV, argID, isPointer);
					
					break;
				}
			}
			break;
		}
		
		case PcodeOp.CALLOTHER: {
			
			// Other unusual subroutine calling conventions
			if (proj.isDebug()) {
				printf("TODO NOT IMPLEMENTED: %s\n", PcodeOp.getMnemonic(opcode));
				// get parameters
				for (int i = 0; i < def.getNumInputs(); i++) {
					printf("Arguments LOAD %d:%s\n", i, def.getInput(i).toString());
				}
			}
			
			break;
		}

		/*
		 * p-code representation of a PHI operation.
		 * 
		 * So here we choose one varnode from a number of incoming varnodes.
		 * 
		 * In this case, we want to explore each varnode that the phi handles We need to
		 * propogate phi status to each of them as well
		 * 
		 * See documentation at /docs/languages/html/additionalpcode.html
		 */
		case PcodeOp.MULTIEQUAL: {
			if (proj.isDebug()) {
				printf("Processing a MULTIEQUAL with %d inputs", def.getInputs().length);
			}

			// visit each input to the MULTIEQUAL
			for (int i = 0; i < def.getInputs().length; i++) {
				// we set isPhi = true, as we trace each of the phi inputs
				processOneVarnode(newNodeOp, f, def.getInput(i), true, callingV, argID, isPointer, offset);
			}
			break;
		}

		/*
		 * This is a p-code op that may be inserted during the decompiler's construction
		 * of SSA form. To be honest, I don't completely understand this p-code op's
		 * purpose
		 * 
		 * See documentation at /docs/languages/html/additionalpcode.html
		 */
		case PcodeOp.INDIRECT: {
			
			if (proj.isDebug()) {
				printf("TODO NOT IMPLEMENTED: %s\n", PcodeOp.getMnemonic(opcode));
				// get parameters
				for (int i = 0; i < def.getNumInputs(); i++) {
					printf("Arguments of %s %d:%s\n", PcodeOp.getMnemonic(opcode), i, def.getInput(i).toString());
				}
			}
			
			if(def.getInput(0).isConstant()) {
				// A constant varnode (zero) for input0 is used by analysis to indicate that the output of the INDIRECT is produced solely by the 
				// p-code operation producing the indirect effect, and there is no possibility that the value existing prior to the operation 
				// was used or preserved.
				if(def.getInput(0).getOffset() == 0x0)
				{
					processOneVarnode(newNodeOp,f, def.getInput(1), isPhi, callingV, argID, isPointer, offset);
					break;
				}
			}
	
			//indirect stack load with same input as output
			Varnode output = def.getOutput();
			if (output.getAddress().equals(def.getInput(0).getAddress())) {
				// show constant use
				processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, isPointer, offset);
				break;
			}

			if (def.getInput(0).isUnique()) {
				processOneVarnode(newNodeOp,f, def.getInput(0), isPhi, callingV, argID, isPointer, offset);
				break;
			}
			
			if ((def.getInput(0).isAddrTied()) || (def.getInput(0).isAddress()) && (def.getInput(0).isRegister() == false)) {
				Address addrpointer = resolvePointer(def.getInput(0), 0x0, false);
				if (addrpointer != null){
					// get argument if it is a string
					ArrayList<String> str = null;
					long value = v.getOffset();
					str = getPossibleTypeValue(addrpointer);
					if (str != null) {
						AddConstNode(newNodeOp, isPhi, str, value, addrpointer, argID);
					}
					break;
				}
			}
			
			// Indirect (TODO): else input1 	(special) 	Code iop of instruction causing effect.
			processOneVarnode(newNodeOp,f, def.getInput(0), isPhi, callingV, argID, isPointer, offset);
			//processOneVarnode(newNodeOp,f, def.getInput(1), isPhi, callingV, argID, isPointer, offset);
			break;
		}

		/*
		 * Two more p-code operations which take two inputs
		 */
		case PcodeOp.PIECE: {
			processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, isPointer, offset);
			processOneVarnode(newNodeOp, f, def.getInput(1), isPhi, callingV, argID, isPointer, offset);
			break;
		}

		case PcodeOp.PTRSUB: {
			/*
			 * input0 Varnode containing pointer to structure. input1 Varnode containing
			 * integer offset to a subcomponent. pointer calculation input0 + input1
			 */
			
			Varnode offsetVal = def.getInput(1);
			if (!offsetVal.isConstant()) {
				processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, isPointer, offset);		
				processOneVarnode(newNodeOp, f, def.getInput(1), isPhi, callingV, argID, isPointer, offset);
				break;
			}

			Varnode baseVal = def.getInput(0);
			if (baseVal.isConstant()) {
				// both constant, just use it and return the address
				long value = baseVal.getOffset() + (int)offsetVal.getOffset() + offset;

				if (proj.isDebug())
					printf("\tConstant @ %x\n", value);
				
				// get argument if it is a string
				ArrayList<String> str = null;
				try {
					
					str = getPossibleTypeValue(currentAddress.getAddress(Long.toHexString(value)));
					if (str != null) {
						AddConstNode(newNodeOp, isPhi, str, value, currentAddress.getAddress(Long.toHexString(value)),
								argID);
					}
					// done! return
					break;
				} catch (AddressFormatException e) {
					//pass
				}
			}

			// if is address and not register
			if ((baseVal.isAddrTied()) || (baseVal.isAddress()) && (baseVal.isRegister() == false))
			{
				// force = true
				Address addrpointer = resolvePointer(baseVal, offsetVal.getOffset() + offset, true);
				if (addrpointer != null)
				{
					// get argument if it is a string
					ArrayList<String> str = null;
					long value = v.getOffset();
					str = getPossibleTypeValue(addrpointer);
					if (str != null) {
						AddConstNode(newNodeOp, isPhi, str, value, addrpointer, argID);
					}
					break;
				}
			}
			
			// if it is a register need to resolve the register then add them to the index
			if (offsetVal.getOffset() == 0) {
				processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, true, offset);
				break;
			}
			
			//processStackVariable
			//newNodeOp = processStackVariable(newNodeOp, f, baseVal, (int)offsetVal.getOffset() + offset, isPhi, v, callingV, argID);
			//if(baseVal.isUnique()) {
			processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, isPointer, (int)offsetVal.getOffset() + offset);		
			processOneVarnode(newNodeOp, f, def.getInput(1), isPhi, callingV, argID, isPointer, (int)offsetVal.getOffset() + offset);		
			//break;
			//}
			


			// TODO: (Future) resolve stack
			break;

		}
		case PcodeOp.PTRADD: {
			/*
			 * input0 Varnode containing pointer to an array. input1 Varnode containing
			 * integer index. input2 (constant) Constant varnode indicating element size.
			 * pointer calcualtion input0 + input1 * input2
			 */
			//input2 	(constant) 	Constant varnode indicating element size.
			Varnode elemsize = def.getInput(2);
			if (!elemsize.isConstant()) {
				processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, isPointer, offset);		
				processOneVarnode(newNodeOp, f, def.getInput(1), isPhi, callingV, argID, isPointer, offset);
				processOneVarnode(newNodeOp, f, def.getInput(2), isPhi, callingV, argID, isPointer, offset);
				break;
			}

			//input1 		Varnode containing integer index.
			Varnode index = def.getInput(1);
			if (!index.isConstant()) {
				processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, isPointer, offset);		
				processOneVarnode(newNodeOp, f, def.getInput(1), isPhi, callingV, argID, isPointer, offset);
				processOneVarnode(newNodeOp, f, def.getInput(2), isPhi, callingV, argID, isPointer, offset);
				break;
			}

			//input0 		Varnode containing pointer to an array.
			Varnode arrptr = def.getInput(0);
			if (arrptr.isConstant()) {
				// both constant, just use it and return the address
				long value = arrptr.getOffset() + (index.getOffset() * elemsize.getOffset()) + offset;

				if (proj.isDebug()) {
					printf("\tConstant! - %s\n", v.toString());
				}

				try {
					Address constaddr = currentAddress.getAddress(Long.toHexString(value));
					// get argument if it is a string
					ArrayList<String> str = getPossibleTypeValue(constaddr);
					if (str != null) {
						AddConstNode(newNodeOp, isPhi, str, value, constaddr, argID);
					}

					// done! return
					break;
				} catch (AddressFormatException e) {
					// pass
				}
			}
			
			if ((arrptr.isAddrTied()) || (arrptr.isAddress()) && (arrptr.isRegister() == false)) 
			{
				Address addrpointer = resolvePointer(arrptr, (index.getOffset() * elemsize.getOffset()) + offset, true);
				if (addrpointer!=null)
				{
					// get argument if it is a string
					ArrayList<String> str = null;
					long value = v.getOffset();
					str = getPossibleTypeValue(addrpointer);
					if (str != null) {
						AddConstNode(newNodeOp, isPhi, str, value, addrpointer, argID);
					}
					break;
				}
			}
			
			// if there is no offset proceed and is a register
			if ((index.getOffset() * elemsize.getOffset()) == 0) {
				processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, true, offset);
				break;
			}
			
			if(arrptr.isUnique()) {
				processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, isPointer, (int)(index.getOffset() * elemsize.getOffset()) + offset);		
				break;
			}

			//processStackVariable
			//newNodeOp = processStackVariable(newNodeOp, f, arrptr, (int)(index.getOffset() * elemsize.getOffset()) + offset, isPhi, v, callingV, argID);
			processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, isPointer, offset);		
			processOneVarnode(newNodeOp, f, def.getInput(1), isPhi, callingV, argID, isPointer, offset);
			processOneVarnode(newNodeOp, f, def.getInput(2), isPhi, callingV, argID, isPointer, offset);
			break;
			// TODO (FUTURE): PTRADD resolve stack
			//break;
		}

		case PcodeOp.SUBPIECE: {
			// output = input0(input1); //  input1 	(constant)	Constant indicating how many bytes to truncate.
			processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, isPointer, offset);
			processOneVarnode(newNodeOp, f, def.getInput(1), isPhi, callingV, argID, isPointer, offset);
			break;
		}

		case PcodeOp.INT_EQUAL:
		case PcodeOp.INT_NOTEQUAL:
		case PcodeOp.INT_LESS:
		case PcodeOp.INT_SLESS:
		case PcodeOp.INT_LESSEQUAL:
		case PcodeOp.INT_SLESSEQUAL:
		case PcodeOp.BOOL_XOR:
		case PcodeOp.BOOL_AND:
		case PcodeOp.BOOL_OR:
		case PcodeOp.FLOAT_EQUAL:
		case PcodeOp.FLOAT_LESS: 
		case PcodeOp.FLOAT_LESSEQUAL:{
			processOneVarnode(newNodeOp, f, def.getInput(0), true, callingV, argID, isPointer, offset);
			processOneVarnode(newNodeOp, f, def.getInput(1), true, callingV, argID, isPointer, offset);

			break;
		}

		case PcodeOp.LOAD: {
			
			if (proj.isDebug()) {
				printf("TODO NOT IMPLEMENTED: %s\n", PcodeOp.getMnemonic(opcode));
				// get parameters
				for (int i = 0; i < def.getNumInputs(); i++) {
					printf("Arguments LOAD %d:%s\n", i, def.getInput(i).toString());
				}
			}
			
			// input0 	(special) 	Constant ID of space to load from.
			// I think no need to taint.
			
			// input1  Varnode containing pointer offset to data.
			processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, isPointer, offset);
			processOneVarnode(newNodeOp, f, def.getInput(1), isPhi, callingV, argID, isPointer, offset);
			break;
		}
		case PcodeOp.FLOAT_TRUNC: 
		case PcodeOp.FLOAT_ROUND:
		case PcodeOp.FLOAT_FLOOR: 
		case PcodeOp.FLOAT_CEIL: 
		case PcodeOp.FLOAT_SQRT:
		case PcodeOp.FLOAT_ABS: {
		
			// try to resolve it
			processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, isPointer, offset);
			break;
		}
		// added to version > 9.2
		/*
		case PcodeOp.POPCOUNT:{
			processOneVarnode(newNodeOp, f, def.getInput(0), isPhi, callingV, argID, isPointer, offset);
			break;
		}
		*/

		// throw an exception when encountering a p-code op we don't support
		default: {
			throw new NotYetImplementedException("TODO Support for PcodeOp " + def.toString() + "not implemented");
		}
		
		}
	
		return path;

	}


	private boolean createPointer(Address addr)
	{
		try {
			removeDataAt(addr);
		} catch (Exception e) {
			return false;
		}

		CreateDataCmd cmd = new CreateDataCmd(addr, new ByteDataType());
		cmd.applyTo(currentProgram);

		// Byte becomes Byte*
		cmd = new CreateDataCmd(addr, false, true, new PointerDataType());
		cmd.applyTo(currentProgram);
		
		return true;
	}
	

	// resolve indirect varnode for CALLIND or BRANCHID
	private Function processIndirectVarnode(Varnode v) {
	
		if ((v.isAddress() || v.isAddrTied()) && (!v.isRegister())) {
			// force true
			Address toaddr = resolvePointer(v, 0x0, true);
			
			if (toaddr == null) {
				return null;
			}
			
			if(proj.isDebug()) {
				printf("fix pointer get addr @%s", toaddr.toString());
			}
	
			// entry point of function
			Function possibleCallIND = getFunctionAt(toaddr);
			if (possibleCallIND != null) {
				if(proj.isDebug()) {
					printf("resolve function %s", possibleCallIND.getName());
				}
				return possibleCallIND;
			}

		}
		
		if(proj.isDebug()) {
			// TODO (FUTURE) need to resolve PTR-SUB, PTR-ADD, INDIRECT, COPY, CAST, LOAD
			printf("TODO need to resolve INDIRECT CALL = %s", v.toString());
		}
		
		return null;
	}
	
	

	/*
	 * This function handles analysis of a particular callsite for a function we are
	 * looking at - we start at knowing we want to analyze a particular input to the
	 * function, e.g., the second parameter, then find all call sites in the binary
	 * where that function is called (see getFunctionCallSitePCodeOps), and then
	 * call this function, passing it the pcode op for the CALL that dispatches to
	 * the function, as well as the parameter index that we want to examine.
	 * 
	 * This function then finds the varnode associated with that particular index,
	 * and either saves it (if it is a constant value), or passes it off to
	 * processOneVarnode to be analyzed
	 * 
	 */
	
	public mFlowInfo analyzeFunctionCallSite(mFlowInfo path, Function f, PcodeOpAST callPCOp, int paramIndex)
			throws InvalidInputException, NotYetImplementedException, NotFoundException {

		if ((callPCOp.getOpcode() != PcodeOp.CALL) && (callPCOp.getOpcode() != PcodeOp.BRANCH)
				&& (callPCOp.getOpcode() != PcodeOp.CALLIND) && (callPCOp.getOpcode() != PcodeOp.BRANCHIND)) {
			throw new InvalidInputException("PCodeOp that is not CALL passed in to function expecting CALL only");
		}

		// get the called values
		Varnode calledFunc = callPCOp.getInput(0);

		Address pa = callPCOp.getSeqnum().getTarget();

		int numParams = callPCOp.getNumInputs();

		/*
		 * the number of p-code operation varnode inputs here is the number of
		 * parameters being passed to the function when called
		 * 
		 * Note that these parameters only become associated with the CALL p-code op
		 * during decompiler analysis. They are not present in the raw p-code.
		 */
		if (proj.isDebug()) {
			printf("\nCall @ 0x%x [%s] to 0x%x [%s] (%d pcodeops)\n", pa.getOffset(), f.getName(),
					calledFunc.getAddress().getOffset(), resolveSinkFunction(callPCOp).getName(), numParams);
		}

		// param index #0 is the call target address, skip it, start at 1, the 0th
		// parameter
		for (int i = 1; i < numParams; i++) {

			// this function is called with param index starting at 0, we subtract 1 from
			// the input #
			if (i - 1 == paramIndex) {
				// ok, we have the parameter of interest
				Varnode parm = callPCOp.getInput(i);

				if (parm == null) {
					if (proj.isDebug())
						printf("\tNULL param #%d??\n", i);
					continue;
				}
				
				if (proj.isDebug())
				{
					printf("\tParameter #%d - %s @ 0x%x\n", i, parm.toString(), parm.getAddress().getOffset());
				}

				// if we have a constant parameter, save that. We are done here
				if (parm.isConstant()) {

					long value = parm.getOffset();
					if (proj.isDebug())
						printf("\t\tisConstant: %d\n", value);

					// get argument if it is a string
					ArrayList<String> str = getPossibleTypeValue(parm.getAddress());
					// not phi
					AddConstNode(path, false, str, value, parm.getAddress(), paramIndex);

				} else {
					// called varnode = callPCOp.getInput(0)
					path = processOneVarnode(path, f, parm, false, callPCOp.getInput(0), paramIndex, false, 0); // isPhi = false

				}
			}
		}
		return path;
	}

	/*
	 * Within a function "f", look for all p-code operations associated with a call
	 * to a specified function, calledFunctionName
	 * 
	 * Return an array of these p-code CALL sites
	 */
	public ArrayList<PcodeOpAST> getFunctionCallSitePCodeOps(Function f, HashSet<Function> sinkFunctions) {

		/*
		 * Pcode Op describes a generic machine operation. You can think of it as the
		 * microcode for a specific processor's instruction set. There are a finite
		 * number of PcodeOp's that theoretically can define the operations for any
		 * given processor. Pcode have An operation code Some number of input parameter
		 * varnodes possible output varnode
		 */
		ArrayList<PcodeOpAST> pcodeOpCallSites = new ArrayList<PcodeOpAST>();
		/*
		 * High-level abstraction associated with a low level function made up of
		 * assembly instructions. Based on information the decompiler has produced after
		 * working on a function.
		 */
		HighFunction hfunction = decompileFunction(f);
		if (hfunction == null) {
			printf("ERROR: Failed to decompile function!\n");
			return null;
		}
		
		if(proj.isDebug()) {
			printf("getFunctionCallSitePCodeOps() : %s, %s\n", f.getName(), f.getEntryPoint().toString());
		}

		// return all PcodeOps (alive or dead) ordered by SequenceNumber
		Iterator<PcodeOpAST> ops = hfunction.getPcodeOps();

		// iterate over all p-code ops in the function
		while (ops.hasNext() && !monitor.isCancelled()) {
			PcodeOpAST pcodeOpAST = ops.next();

			// check CALL, BRANCH, CBRANCH only if is a valid address, check if this lead us to a sink!
			if ((pcodeOpAST.getOpcode() == PcodeOp.CALL) || (pcodeOpAST.getOpcode() == PcodeOp.BRANCH)
				||  (pcodeOpAST.getOpcode() == PcodeOp.CBRANCH)) {

				// current p-code op is a CALL
				// get the address CALL-ed
				Varnode calledVarnode = pcodeOpAST.getInput(0);

				if (calledVarnode == null || (!(calledVarnode.isAddress() || calledVarnode.isAddrTied()))) {
					if(proj.isDebug()) {
						printf("ERROR: %s, but not to address.", pcodeOpAST.getMnemonic());
					}
					continue;
				}

				// if the CALL is to our function, save this callsite
				Function possibleSink = getFunctionAt(calledVarnode.getAddress());

				if (sinkFunctions.contains(possibleSink)) {
					// add to array
					pcodeOpCallSites.add(pcodeOpAST);
				}
			
			// try to resolve indirect calls
			// save them to a def-use list
			} else if ((pcodeOpAST.getOpcode() == PcodeOp.CALLIND) || (pcodeOpAST.getOpcode() == PcodeOp.BRANCHIND)) {
				

				Varnode calledVarnode = pcodeOpAST.getInput(0);
				
				Function possibleSink = processIndirectVarnode(calledVarnode);

				if (possibleSink == null) {
				    printf("ERROR HANDLE %s.\n", pcodeOpAST.getMnemonic());
					continue;
				}
				
				if (sinkFunctions.contains(possibleSink)) {
					// add to array
					pcodeOpCallSites.add(pcodeOpAST);
					defuseIndirect.put(pcodeOpAST, possibleSink);
				}
			}
			else if (pcodeOpAST.getOpcode() == PcodeOp.CALLOTHER) {
				if(proj.isDebug()) {
					printf("TODO HANDLE %s.\n", pcodeOpAST.getMnemonic());
				}
				continue;
			}
		}
		
		return pcodeOpCallSites;
	}

	// recursive to build the call graph
	public void getAllReferences(mNode forward, Function function) {
		// Get an iterator over all references that have the given address as their "To"
		// address.
		Reference[] FunctionReferences = getReferencesTo(function.getEntryPoint());

		// Now find all references to this function
		for (Reference ref : FunctionReferences) {

			// get the function where the current reference occurs (hopefully it is a
			// function)
			Function callingFunction = getFunctionContaining(ref.getFromAddress());

			// check if calling function exists and is not Thunk
			if (callingFunction != null && !callingFunction.isThunk()) {
				// create new reference node
				mNode refv = new mNode(callingFunction);
				// add the edge this also add sinkv and refv if it is not in the graph
				if (graph.addEdge(refv, forward, false) == true) {
					getAllReferences(refv, callingFunction);
				}
			}
		}

		HashSet<Function> sf = indirectEdges.get(function);
		if (sf != null) {
			for (Function fptr : sf) {
				if (!fptr.isThunk()) {
					// create new reference node
					mNode refv = new mNode(fptr);
					// add the edge this also add sinkv and refv if it is not in the graph
					if (graph.addEdge(refv, forward, true) == true) {
						getAllReferences(refv, fptr);
					}
				}
			}
		}

	}

	private CTX updateCTXdefUse() {
		boolean unique = true;
		for (CTX x : defuse) {
			if (currentCTX.equals(x)) {
				unique = false;
				// update x
				for (long k : currentCTX.addresses) {
					x.addKey(k);
				}

				if (currentCTX.isCipherTypeEmpty() == false) {
					x.addCipherType(currentCTX.getCipherType());
				}

				if ((currentCTX.type != -1) && (currentCTX.arg != -1)) {
					// update
					x.tryUpdate(currentCTX.type, currentCTX.arg);
				}
				return x;
				// break;
			}
		}

		if (unique) {
			if ((currentCTX.type != -1) && (currentCTX.arg != -1)) {
				currentCTX.typearg.put(currentCTX.type, currentCTX.arg);
			}
			defuse.add(currentCTX);
		}

		return currentCTX;
	}

	private void addEntryPoint(Function function, Long mainid) throws Exception {
		
		// main not found
		if (mainid == null)
			return;
		
		if (graph.hasEntry()) {
			return;
		}
		
		// check if is the marked main
		if (function.getID() == mainid) {
			printf("Created Main found at @%x\n", function.getEntryPoint().getOffset());
			graph.setEntry(function);
		}
		
	}

	private void updateDefaultValues(mFlowInfo node, InputSink targetSink, Sink sink, HashSet<Integer> initb) {

		if (node.isConst()) {
			Integer getsize;
			if (node.nodeName.equals("CONST")) {
				ConstNode t = (ConstNode) node;
				getsize = (int) t.constValue;
			} else {
				PhiFlow t = (PhiFlow) node;
				getsize = (int) t.constValue;
			}

			if (getsize == 0)
				return;

			// possible in bits convert to bytes
			if (currentTaintedObj.getType().equals("bit"))
				getsize = getsize >> 3;

			for (Integer aftersuc : currentTaintedObj.GetSuccessors()) {
				// update my child default values
				TaintedArgs afterSink = targetSink.taintedArgs.get(aftersuc);

				if (initb.contains(aftersuc) == false) {
					afterSink.clearDefaultValues();
					initb.add(aftersuc);
				}

				afterSink.addDefaultValue(getsize);
			}
			if (proj.isDebug()) {
				printf("hola const value = %d bytes\n", getsize);
			}

		}
	}

	void updateDefaultValuesFromCTX(Sink sink, HashSet<Integer> initb, Integer argtoAnalyse) {

		if ((currentTaintedObj.getRuleID() == TaintedArgs.SYMMETRIC_CONSTANT_KEY) && (currentCTX.keylength != 0)) {
			if (initb.contains(argtoAnalyse) == false) {
				currentTaintedObj.clearDefaultValues();
				initb.add(argtoAnalyse);
			}

			currentTaintedObj.addDefaultValue(currentCTX.keylength);

		} else if ((currentTaintedObj.getRuleID() == TaintedArgs.SYMMETRIC_CONSTANT_IV) && (currentCTX.ivlength != 0)) {
			if (initb.contains(argtoAnalyse) == false) {
				currentTaintedObj.clearDefaultValues();
				initb.add(argtoAnalyse);
			}

			currentTaintedObj.addDefaultValue(currentCTX.ivlength);
		}

	}
	
	// use def-use list for the indirect calls
	Function resolveSinkFunction(PcodeOpAST callSite)
	{
		if ((callSite.getOpcode() == PcodeOp.CALLIND) || (callSite.getOpcode() == PcodeOp.BRANCHIND))
		{
			return defuseIndirect.get(callSite);
		}
		// else
		// resolve CALL or BRANCH with address
		return getFunctionContaining(callSite.getInput(0).getAddress());

	}
	
	//Only String data
	ArrayList<String> findDefinedUsedData(Function ftaint){
		
		ArrayList<String> retres = new ArrayList<>();
		// aggressive data search inside function
		DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);
		while (dataIterator.hasNext()) {
			Data nextData = dataIterator.next();

			// if it is a string
			if (nextData.hasStringValue()) {

				// get all references
				ReferenceIterator it = nextData.getReferenceIteratorTo();

				while (it.hasNext()) {
					Reference nextref = it.next();
					Function callingFunction = getFunctionContaining(nextref.getFromAddress());
					if (callingFunction != null) {
						if (callingFunction == ftaint) {
							StringDataInstance str = StringDataInstance.getStringDataInstance(nextData);
							String s = str.getStringValue();
							retres.add(s);
						}
					}
				}
			}
			else if (nextData.isPointer())
			{
				
				// get all references
				ReferenceIterator it = nextData.getReferenceIteratorTo();
				while (it.hasNext()) {
					Reference nextref = it.next();
					Function callingFunction = getFunctionContaining(nextref.getFromAddress());
					if (callingFunction != null) {
						if (callingFunction == ftaint) {
							
							if (nextData.getValue() instanceof Address) {
								Address addrs = (Address) nextData.getValue();
								
								if (addrs != null){
									// try to resolve the pointers too
									Data ptrstr = currentProgram.getListing().getDefinedDataAt(addrs);
									if (ptrstr != null) {
										if (ptrstr.hasStringValue())
										{
											StringDataInstance str = StringDataInstance.getStringDataInstance(ptrstr);
											String s = str.getStringValue();
											retres.add(s);
										}
									}
								}
							}
						}
					}
				}
			}			
		}
		
		return retres;
	}

	public void run() throws Exception {
		
		if(isHeadlessAnalysisEnabled()) {
			if (analysisTimeoutOccurred()) {
				printf("Analysis timeout occurred\n");
				return;
			}
		}

		// create the project
		// get options and
		// parse the input rules to objects
		proj = new mProject(getScriptArgs());
		// Initialize the partial call graph
		graph = new AbstractCallGraph();
		
		// get main function id from previous script FindMain.java -> script communication
		Long mainid = null;
	    boolean containsKey = headlessStorageContainsKey("MAINID");
	    if(containsKey)
	    {
	    	mainid = (Long) getStoredHeadlessValue("MAINID");
	    	printf("Found main id = %d, %s\n", mainid,  currentProgram.getFunctionManager().getFunction(mainid).getName());
	    }

		if (proj.getNumberofRules() == 0) {
			Msg.error(this, "No rule founds");
			throw new Exception("No rule founds");
		}

		printf("Number of rules found: %d\n", proj.getNumberofRules());
		printf("Number of post rules found: %d\n", proj.getNumberofPostRules());

		// set up the decompiler
		decomplib = setUpDecompiler(currentProgram);

		/*
		 * This call initializes a new decompiler process to do decompilations for a new
		 * program
		 */
		if (!decomplib.openProgram(currentProgram)) {
			printf("Decompiler error: %s\n", decomplib.getLastMessage());
			return;
		}

		// try to resolve indirect references of function calls
		FunctionIndirectReferencesE indobj = new FunctionIndirectReferencesE(currentProgram, currentAddress);
		// for all known discover types try to compute the possible indirect references of function calls
		indirectEdges = indobj.ComputeIndirectReferences();

		if (proj.isDebug()) {
			printf("Indirect Function Calls:\n");
			for (Map.Entry<Function, HashSet<Function>> entry : indirectEdges.entrySet()) {
				Function from = entry.getKey();
				for (Function to : entry.getValue()) {
					printf("\tfrom %s -> to %s\n", from.getName(), to.getName());
				}
			}
		}
		// hold for static taint analysis
		Reference[] sinkFunctionReferences;

		HashMap<Function, HashSet<Function>> foundCallingSinks = new HashMap<>();
		HashMap<String, InputSink> possiblyMisuse = new HashMap<>();

		Function sinkfunction = null;
		
		// Add possible indirect sink to foundCallingSinks!
		// add them to the graph too
		for (Map.Entry<Function, HashSet<Function>> entry : indirectEdges.entrySet()) {
			Function function = entry.getKey();
			Boolean check = false;
			// for every sink
			// check if we found any
			if (proj.mapSinks.containsKey(function.getName())) {
				InputSink sink = proj.mapSinks.get(function.getName());
				if (sink.checkSink(function)) {
					check = true;
					possiblyMisuse.putIfAbsent(function.getName(), sink);
					sinkfunction = function;
				}
			}
			
			// a sink is found
			if (check == true) {
				// create new node
				mNode sinkv = new mNode(function);
				for (Function callingFunction : entry.getValue()) {
					// check if calling function exists and is not external and is not thunk
					if (callingFunction != null && !callingFunction.isExternal() && !callingFunction.isThunk()) {

						// create new reference node
						mNode refv = new mNode(callingFunction);
						// add the edge (this also adds refv and sinkv)
						if (graph.addEdge(refv, sinkv, true, true) == true) {
							// get other references to build the call graph
							getAllReferences(refv, callingFunction);
						}
						// check if we already add this
						if (foundCallingSinks.containsKey(callingFunction)) {
							// set is unique
							foundCallingSinks.get(callingFunction).add(sinkfunction);
						} else {
							foundCallingSinks.put(callingFunction, new HashSet<Function>());
							foundCallingSinks.get(callingFunction).add(sinkfunction);
						}
					}
				}
			}
		}
		

		// PIE not correct on getFunctionsNoStubs
		FunctionIterator functionManager = currentProgram.getFunctionManager().getFunctions(true);
		// Iterate over all functions in ascending address order
		for (Function function : functionManager) {
				
			// check for entry point and add main function if found
			// Created earlier with script @FindMain.java
			addEntryPoint(function, mainid);

			Boolean check = false;
			// for every sink
			// check if we found any
			if (proj.mapSinks.containsKey(function.getName())) {
				InputSink sink = proj.mapSinks.get(function.getName());
				if (sink.checkSink(function)) {
					check = true;
					possiblyMisuse.putIfAbsent(function.getName(), sink);
					sinkfunction = function;
				}
			}

			// a sink is found
			if (check == true) {

				// create new node
				mNode sinkv = new mNode(function);

				// Get an iterator over all references that have the given address as their "To"
				// address.
				sinkFunctionReferences = getReferencesTo(function.getEntryPoint());

				// Now find all references to this function
				for (Reference ref : sinkFunctionReferences) {
					if (proj.isDebug()) {
						printf("\tFound %s reference @ 0x%x (%s)\n", sinkfunction.getName(),
								ref.getFromAddress().getOffset(), ref.getReferenceType().getName());
					}

					// get the function where the current reference occurs (hopefully it is a
					// function)
					Function callingFunction = getFunctionContaining(ref.getFromAddress());

					// check if calling function exists and is not external and is not thunk
					if (callingFunction != null && !callingFunction.isExternal() && !callingFunction.isThunk()) {

						// create new reference node
						mNode refv = new mNode(callingFunction);
						// add the edge (this also adds refv and sinkv)
						if (graph.addEdge(refv, sinkv, true, false) == true) {
							// get other references to build the call graph
							getAllReferences(refv, callingFunction);
						}
						// check if we already add this
						if (foundCallingSinks.containsKey(callingFunction)) {
							// set is unique
							foundCallingSinks.get(callingFunction).add(sinkfunction);
						} else {
							foundCallingSinks.put(callingFunction, new HashSet<Function>());
							foundCallingSinks.get(callingFunction).add(sinkfunction);
						}
					}
				}
			}
		}

		// print the function set
		if (proj.isDebug()) {
			for (Map.Entry<Function, HashSet<Function>> entry : foundCallingSinks.entrySet()) {
				Function callf = entry.getKey();
				HashSet<Function> setSinks = entry.getValue();

				printf("GIVEN calling function: %s\n", callf.getName());
				printf("\tFound %d sink functions inside calling function\n", setSinks.size());
				for (Function currentFunction : setSinks) {
					printf("\t\t-> %s\n", currentFunction.toString());
				}
			}
		}

		// if we found an entry point
		if (graph.hasEntry()) {
			// update vertex entry
			graph.updateVertexEntry();

			// Call graph completed now DFS to check for entry
			// DFS algorithm to check for every sinks, if we can find them from entry
			graph.checkEntry(foundCallingSinks.keySet());
		}
		else
		{
			// possibly is a library
			printf("Entry Not Found\n");
		}

		// create an array of FlowInfo class
		ArrayList<mFlowInfo> paths = new ArrayList<mFlowInfo>();

		// iterate through each unique function which references our sinks functions
		for (Map.Entry<Function, HashSet<Function>> entry : foundCallingSinks.entrySet()) {

			// get the current function
			Function currentFunction = entry.getKey();
			// get all the found sinks
			HashSet<Function> setSinks = entry.getValue();

			// re init def use indirect list
			defuseIndirect = new HashMap<>();
			// get all sites in the function where we CALL the sink
			ArrayList<PcodeOpAST> callSites = getFunctionCallSitePCodeOps(currentFunction, setSinks);

			if (callSites == null) {
				// something went wrong during the decompiling
				continue;
			}

			if (proj.isDebug()) {
				printf("\nFound %d sink functions call sites in %s\n", callSites.size(), currentFunction.getName());
			}

			// for each CALL, figure out the inputs into the sink function
			for (PcodeOpAST callSite : callSites) {

				/**
				 * getSeqnum()
				 * 
				 * @return the sequence number this pcode is within some number of pcode
				 */
				/**
				 * getTarget();
				 * 
				 * @return get address of instruction this sequence belongs to
				 */
				Address pa = callSite.getSeqnum().getTarget();

				Function sinkFunction = resolveSinkFunction(callSite);
				
				if (proj.isDebug()) {
					printf("\n\n\nAnalyse: targetFunction %s at address 0x%X\n", sinkFunction.getName(),
							pa.getOffset());
				}

				// get the arguments to analyze that comes with the rule
				InputSink targetSink = null;
				if (possiblyMisuse.containsKey(sinkFunction.getName())) {
					InputSink input = possiblyMisuse.get(sinkFunction.getName());
					if (input.checkSink(sinkFunction)) {
						targetSink = input;
					}
				}

				if (proj.isDebug()){
					printf("target sink: %s", targetSink.getRule());
				}

				HashSet<Integer> initb = new HashSet<Integer>();
				// create new context
				this.currentCTX = new CTX(sinkFunction.getName());
				
				ArrayList<Sink> listofsinks = new ArrayList<>();
				ArrayList<mFlowInfo> listofcurrentPaths = new ArrayList<>();

				for (Integer argtoAnalyse : targetSink.orderedArgs) {		
					
					// get tainted object
					this.currentTaintedObj = new TaintedArgs(targetSink.taintedArgs.get(argtoAnalyse));

					if (proj.isDebug()) {
						printf("\n\nAnalyse Argument %d with type %s\n", argtoAnalyse, currentTaintedObj.getType());
						printf(" Default values:");
						for (Integer d : currentTaintedObj.getDefaultValues()) {
							printf("\t\t%d\n", d);
						}
					}
					
					// create sink
					Sink sink = new Sink(currentFunction, sinkFunction, pa, argtoAnalyse, currentTaintedObj.getType(),
							targetSink.getRule(), currentTaintedObj.getRuleID());
					
					listofsinks.add(sink);

					// update if found
					updateDefaultValuesFromCTX(sink, initb, argtoAnalyse);

					if (argtoAnalyse <= NO_ARGUMENTS) {
						if (proj.isDebug())
							printf("NO ARGUMENT TO ANALYSE\n");
						paths.add(sink);
						continue;
					}

					traverse.clear();
					finalnodes.clear();

					if (proj.isDebug()) {
						printf(" Default values:");
						for (Integer d : currentTaintedObj.getDefaultValues()) {
							printf("\t\t%d\n", d);
						}
					}

					mFlowInfo currentPath = analyzeFunctionCallSite(sink, currentFunction, callSite, argtoAnalyse - 1);
					
					if (currentTaintedObj.hasSuccessors()) {
						if (!currentTaintedObj.getType().equals("CTX") && !currentTaintedObj.getType().equals("CTYPE")) {
							// from sink!!!
							for (mFlowInfo node : finalnodes) {
								updateDefaultValues(node, targetSink, sink, initb);
							}
						}
					}
					
					listofcurrentPaths.add(currentPath);

					// update and get CTX
					currentCTX = updateCTXdefUse();	
					// update defined strings of functions only on CTX
					if (currentTaintedObj.getType().equals("CTX")){
						sink.updateDefinedStrings(findDefinedUsedData(currentFunction));
					}
					
				}
				
				for(Sink sink: listofsinks)
				{
					// update Ciphertype
					sink.updateAlgorithm(currentCTX.getCipherType());
				}
				
				for(mFlowInfo currentPath : listofcurrentPaths)
				{
					paths.add(currentPath);
				}
				
				if(proj.isDebug()) {
					for(long x : currentCTX.addresses)
					{
						printf("Current ctx address: %x", x);
					}
					/*
					for(String x : currentCTX.getCipherType())
					{
						printf("Current ctx algorithm: %s", x);
					}
					*/
				}

			}
		}

		if (proj.isDebug())
			builder = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting();
		else
			builder = new GsonBuilder().disableHtmlEscaping();

		builder.excludeFieldsWithoutExposeAnnotation();
		Gson gson = builder.create();

		String json = gson.toJson(paths);
		System.out.println("JSONAST;" + json);

		String json1 = gson.toJson(graph.getCallingSinks());
		System.out.println("JSONCALLINGSINKS;" + json1);

		String json2 = gson.toJson(graph.getEdges());
		System.out.println("JSONCALLGRAPH;" + json2);
		
		//get all export symbols
		//includeDynamicSymbols = false
		ArrayList<String> exports = new ArrayList<String>();
		SymbolIterator iter = currentProgram.getSymbolTable().getAllSymbols(false);
		while (iter.hasNext()) {
			Symbol s = iter.next();
			
			if (s.isExternalEntryPoint()){
				// printf("%s\n", s.getName());
				exports.add(s.getName());
			}
		}
		
		String json3 = gson.toJson(exports);
		System.out.println("JSONEXPORTS;" + json3);

	}

}

