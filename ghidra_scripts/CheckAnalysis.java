//TODO write a description for this script
//@author Paris Panagiotou
//@category EBAT
//@keybinding 
//@menupath 
//@toolbar 


import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;


public class CheckAnalysis extends HeadlessScript {
	private boolean debug = false;
//load project configurations
class mProject {

	private boolean debug = false;
	private String input_file = null;
	public HashMap<String, InputSink> mapSinks = new HashMap<>();

	public mProject(String[] args) throws FileNotFoundException, IOException {
		// for every argument
		for (int i = 0; i < args.length; i++) {
			if (args[i].equals("debug")) {
				debug = true;
			} else if (args[i].equals("input")) {
				input_file = args[i + 1];
				i++;
			}
		}

		// load rules
		if (input_file != null) {
			loadConfigurations();
		}
		
	}
	
	public int getNumberofRules() {
		return mapSinks.size();
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

	// TODO FIX IT MAKE IT YOURS
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

	// TODO FIX IT MAKE IT YOURS
	private void topoSort() {
		int n = taintedArgs.size();
		HashMap<Integer, Boolean> visited = new HashMap<>();
		// List<Integer> ordered = new ArrayList<>(n);
		this.orderedArgs = new ArrayList<>(n);
		// working horse
		Deque<Integer> stack = new ArrayDeque<>();

		for (Integer keys : taintedArgs.keySet())
			visited.put(keys, false);

		// Call the recursive helper function to store
		// Topological Sort starting from all vertices
		// one by one
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
			if ((f.getName().equals(this.functionName))) {
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

	mProject proj = null;
	
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
		if(debug) {
			printf("Number of rules found: %d\n", proj.getNumberofRules());
		}

		Reference[] sinkFunctionReferences;
		boolean isFound = false;
		
		// PIE not correct on getFunctionsNoStubs
		FunctionIterator functionManager = currentProgram.getFunctionManager().getFunctions(true);
		for (Function function : functionManager) {
			
			Boolean check = false;
			// for every sink
			// check if we found any
			if (proj.mapSinks.containsKey(function.getName())) {
				InputSink sink = proj.mapSinks.get(function.getName());
				if (sink.checkSink(function)) {
					check = true;
				}
			}

			// a sink is found
			if (check == true) {
				if(debug) {
					printf("found function: %s", function.toString());
				}
				// Get an iterator over all references that have the given address as their "To"
				// address.
				sinkFunctionReferences = getReferencesTo(function.getEntryPoint());

				// Now find all references to this function
				for (Reference ref : sinkFunctionReferences) {
					// get the function where the current reference occurs (hopefully it is a
					// function)
					Function callingFunction = getFunctionContaining(ref.getFromAddress());

					// check if calling function exists and is not external
					if (callingFunction != null && !callingFunction.isExternal() && !callingFunction.isThunk()) {
						isFound = true;
						break;
					}
				}
			}
			
			if(isFound)
			{
				break;
			}
			
		}
		
		System.out.println("CHECKANALYSIS=" + isFound); 
	}
}
