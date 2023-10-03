//TODO write a description for this script
//
//@author Paris Panagiotou
//@category EBAT
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
//import ghidra.util.exception.NotYetImplementedException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.concurrent.ThreadLocalRandom;



public class FindMain extends HeadlessScript {
	
	private boolean isFound = false;
	private DecompInterface decomplib;
	private boolean isDebug = false;
	private Function main = null;
	private Long argid = null;
	
	HashMap<PcodeOpAST, Function> defuseIndirect;
	
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
		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.toggleJumpLoads(true);
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}

	public HighFunction decompileFunction(Function f) {
		HighFunction hfunction = null;

		try {
			DecompileResults dRes = decomplib.decompileFunction(f, decomplib.getOptions().getDefaultTimeout(),
					getMonitor());

			hfunction = dRes.getHighFunction();
		} catch (Exception exc) {
			printf("EXCEPTION IN DECOMPILATION!\n");
			exc.printStackTrace();
		}

		return hfunction;
	}
	
	
	private boolean resolvePointer(Varnode parm, long offset)
	{
		if ((parm.isAddress()) && (!parm.isRegister())) {
			if (parm.isAddrTied()){
				
				if(isDebug) {
					printf("address tied?\n");
				}

				// resolve the pointer
				Data data = getDataAt(parm.getAddress());
				if (data != null) {
					if (data.isPointer())
					{
						Address toaddr = (Address) data.getValue();
						//Pointer addition (offset is negative)
						Long toaddress = toaddr.getOffset() + offset;
						// add main
						addEntry(toaddress);
						return true;
					}
				}
			}
		}
		
		return false;
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
	
	
	
	// resolve indirect varnode for CALLIND or BRANCHID
	private Function processIndirectVarnode(Varnode v) {
	
		if ((v.isAddress() || v.isAddrTied()) && (!v.isRegister())) {
			// force true
			Address toaddr = resolvePointer(v, 0x0, true);
			
			if (toaddr == null) {
				return null;
			}
	
			// entry point of function
			Function possibleCallIND = getFunctionAt(toaddr);
			if (possibleCallIND != null) {
				return possibleCallIND;
			}

		}
		
		// TODO need to resolve PTR-SUB, PTR-ADD, INDIRECT, COPY, CAST, LOAD
		printf("TODO need to resolve INDIRECT CALL = %s", v.toString());
		
		return null;
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
		
		// re init def use indirect list
		defuseIndirect = new HashMap<>();

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

				if (calledVarnode == null || !calledVarnode.isAddress()) {
					printf("ERROR: call, but not to address!");
					continue;
				}

				// if the CALL is to our function, save this callsite

				/**
				 * Returns the function with the specified entry point, or null if no function
				 * exists.
				 * 
				 * @param entryPoint the function entry point address
				 * @return the function with the specified entry point, or null if no function
				 *         exists
				 */
				Function possibleSink = getFunctionAt(calledVarnode.getAddress());

				if (sinkFunctions.contains(possibleSink)) {
					// add to array
					pcodeOpCallSites.add(pcodeOpAST);
				}

			// try to resolve indirect calls
			// save them to a def-use list
			} 
			else if ((pcodeOpAST.getOpcode() == PcodeOp.CALLIND) || (pcodeOpAST.getOpcode() == PcodeOp.BRANCHIND)) {
				

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
				printf("TODO HANDLE %s.\n", pcodeOpAST.getMnemonic());
				continue;
			}

		}
		return pcodeOpCallSites;
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
	
	
	private boolean processVarnode(Varnode parm)
	{
		if(parm.isConstant())
		{
			//get address
			addEntry(parm.getOffset());
			return true;
		}
		
		// possibly pointer defined
		if(resolvePointer(parm, 0l)) {
			return true;
		}
		
		// Resolve more complex pointer
		// get the p-code op defining the varnode
		PcodeOp def = parm.getDef();
		return processPcode(def);
	}
	
	private boolean processPcode(PcodeOp def)
	{
		boolean ret = false;
		if (def == null) {
			printf("Problem on ENTRY POINT def null\n");
			return ret;
		}
		
		if(isDebug) {
			printf("processOneVarnode: %s\n", def.toString());
		}

		// get the enum value of the p-code operation that defines our varnode
		int opcode = def.getOpcode();
		switch (opcode) {
			case PcodeOp.PTRSUB: {
				/*
				 * input0 Varnode containing pointer to structure. input1 Varnode containing
				 * integer offset to a subcomponent. pointer calculation input0 + input1
				 */
				Varnode offsetVal = def.getInput(1);
				if (!offsetVal.isConstant()) {
					ret = false;
					break;
				}

				Varnode baseVal = def.getInput(0);
				if (baseVal.isConstant()) {
					// both constant, just use it and return the address
					long value = baseVal.getOffset() + offsetVal.getOffset();
					addEntry(value);
					ret = true;
					break;
				}
				
				// possibly pointer defined
				if(resolvePointer(baseVal, offsetVal.getOffset())) {
					ret = true;
					break;
				}
				
				break;

			}
			case PcodeOp.CALL:
			case PcodeOp.BRANCH: {
				// get function of the given call
				Function pf = getFunctionAt(def.getInput(0).getAddress());
				if (pf == null) {
					break;
				}
				addEntry(def.getInput(0).getAddress().getOffset());
				ret = true;
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
					break;
				}
	
				//input1 		Varnode containing integer index.
				Varnode index = def.getInput(1);
				if (!index.isConstant()) {
					break;
				}
	
				//input0 		Varnode containing pointer to an array.
				Varnode arrptr = def.getInput(0);
				if (arrptr.isConstant()) {
					// both constant, just use it and return the address
					long value = arrptr.getOffset() + (index.getOffset() * elemsize.getOffset());
	
					addEntry(value);
					ret = true;
					break;
				}
				
				// possibly pointer defined
				if(resolvePointer(arrptr, (index.getOffset() * elemsize.getOffset()))) {
					ret = true;
					break;
				}
				break;
			}
			default: {
				//throw new NotYetImplementedException("TODO Support for PcodeOp " + def.toString() + "not implemented");
				printf("TODO Support for PcodeOp " + def.toString() + "not implemented");
			}
		}
		return ret;
	}

	
	boolean addPossibleEntryPoint(Function function)
	{
		boolean ret = false;
		Reference[] refs = getReferencesTo(function.getEntryPoint());
		if(isDebug) {
			printf("found at @%x\n", function.getEntryPoint().getOffset());
		}
		// see if we created more than one main then raise an error
		int count = 0;
		// Now find all references to this function
		for (Reference ref : refs) {
			Function callingFunction = getFunctionContaining(ref.getFromAddress());
			if (callingFunction != null && !callingFunction.isThunk() && !callingFunction.isExternal()) {	
				if(isDebug) {
					printf("entry??? %s\n", callingFunction.getName());
				}
				
				count++;
				// get libc call
				// get all sites in the function where we CALL the sink
				HashSet<Function> sinkentry = new HashSet<>();
				sinkentry.add(function);
				ArrayList<PcodeOpAST> callSites = getFunctionCallSitePCodeOps(callingFunction, sinkentry);
				
				if (callSites == null) {
					// something went wrong during the decompiling
					continue;
				}
				
				// for each CALL, figure out the inputs into the sink function
				for (PcodeOpAST callSite : callSites) {

					if(isDebug) {
						Address pa = callSite.getSeqnum().getTarget();
						printf("that address %x\n", pa.getOffset());
					}

					int numParams = callSite.getNumInputs();
					if(isDebug) {
						printf("num parameters : %d\n", numParams);
					}

					// param index #0 is the call target address, skip it, start at 1, the 0th
					// parameter
					// taint the 1st one
					if(numParams < 2)
					{
						printf("Problem on ENTRY POINT param function\n");
						ret = false;
						continue;
					}
					
					int taintParam = 1;
					Varnode parm = callSite.getInput(taintParam);
					if(isDebug) {
						printf(" varnode parm %s\n", parm.toString());
					}
					
					if(processVarnode(parm))
					{
						ret = ret | true;
						continue;
					}

				}
			}
		}
		
		if(count > 1)
		{	
			printf("Problem on ENTRY POINT multiple\n");
			ret = false;
		}
		
		return ret;
	}
	
	void getEntryPoint(Function function)
	{	
		
		// most of the time for good decompilation
		boolean foundEntry = false;
		if(function.isThunk() || function.isExternal()){
			if(function.getName().equals("__libc_start_main") || function.getName().equals("__uClibc_main"))
			{
				foundEntry = addPossibleEntryPoint(function);
			}
		}
		
		if (foundEntry==false)
		{
			// check more aggressive entry, start, _entry, _start
			if(function.getName().equals("__libc_start_main") || function.getName().equals("__uClibc_main"))
			{
				Reference[] refs = getReferencesTo(function.getEntryPoint());
				for (Reference ref : refs) {
					Function callingFunction = getFunctionContaining(ref.getFromAddress());
					if (callingFunction != null && !callingFunction.isThunk() && !callingFunction.isExternal()) {	
						if (callingFunction.getName().equals("entry") || callingFunction.getName().equals("start") || 
								callingFunction.getName().equals("_entry") || callingFunction.getName().equals("_start"))
						{		
							foundEntry = addPossibleEntryPoint(function);
							break;
						}
					}
				}		
			}
		}
		
		// possible wrapper :(
		if (foundEntry==false)
		{
			if(function.isThunk() || function.isExternal()){
				if(function.getName().equals("__libc_start_main") || function.getName().equals("__uClibc_main"))
				{
					Reference[] refs = getReferencesTo(function.getEntryPoint());
					for (Reference ref : refs) {
						Function callingFunction = getFunctionContaining(ref.getFromAddress());
						if (callingFunction != null && !callingFunction.isThunk() && !callingFunction.isExternal()) {	
							printf("call = %s", callingFunction.getName());
							foundEntry = addPossibleEntryPoint(callingFunction);
							if(foundEntry)
								break;
						}
					}
				}
			}
		}

	}
	
	private void addEntry(long value)
	{
		// get the even address
		value = value - (value % 2);
		
		if(isDebug) {
			printf("\tConstant @ %x\n", value);
		}
		
		Address mainaddr = currentAddress.getNewAddress(value);
		
		// check if the function is already there
		Function lmain = getFunctionContaining(mainaddr);
		if(lmain != null)
		{
			if(isDebug) {
				printf("name??? %s\n", lmain.getName());
			}
			Address entry = lmain.getEntryPoint();
			if(entry.equals(mainaddr))
			{
				renameMainFunction(lmain, "EBATCreatedMain");
				
				if(isDebug) {
					printf("\tAlready added\n");
				}
				return;
			}	
		}
		
		if(isDebug) {
			printf("\tmain address @ %x\n", mainaddr.getOffset());
		}
		
		// create the function
		if (lmain != null) {
			removeFunctionAt(mainaddr);
		}
			
		boolean didDisassemble = disassemble(mainaddr);
		if (didDisassemble) {
			Function func = createFunction(mainaddr, null);
			if (func != null) {
				println("Made function at address: " + mainaddr.toString());
				renameMainFunction(func, "EBATCreatedMain");
			}
			else {
				println("***Function could not be made at address: " +
						mainaddr.toString());
				
				
				// get the reason of wrong decompiled
				Instruction instr = getInstructionContaining(mainaddr);
				if (instr != null){
					PcodeOp[] arrop =  instr.getPcode();
					
					for(PcodeOp op: arrop)
					{
						try {
							processPcode(op);
						} catch (Exception e) {
							println("Not supported Pcode yet");
							continue;
						}
					}
				}
				else
				{
					// try to resolve if it is pointer
					Data data = getDataAt(mainaddr);
					if (data != null) {
						if (data.isPointer())
						{
							Address toaddr = (Address) data.getValue();
							Long toaddress = toaddr.getOffset() + 0;
							// add main
							addEntry(toaddress);
						}
					}
				}
			}
		}
		else
		{
			println("dissasemble failed");
		}

	}

	
	private void renameMainFunction(Function func, String name)
	{
		if(func.isThunk())
		{	//revert it
			func.setThunkedFunction(null);
		}
		
		try {
			func.setName(name, SourceType.ANALYSIS);
			this.isFound = true;
			this.main = func;
		} catch (DuplicateNameException | InvalidInputException e) {
			// cannot rename change name -> random?
			if(isDebug) {
				println("Not renamed???");
			}
			
			renameMainFunction(func, "EBATCreatedMain" + Integer.toString(ThreadLocalRandom.current().nextInt()));
		}
	}
	
	private void checkMainSymbol()
	{
		FunctionIterator functionManager = currentProgram.getFunctionManager().getFunctions(true);
		for (Function function : functionManager) {
			if (function.getName(false).equals("main")) {
				renameMainFunction(function, "EBATCreatedMain");
				return;
			}		
		}
	}
	
	@Override
	protected void run(){
		
		if(isHeadlessAnalysisEnabled()) {
			if (analysisTimeoutOccurred()) {
				printf("Analysis timeout occurred\n");
				return;
			}
		}
		
		// set up the decompiler to get the PCODE
		decomplib = setUpDecompiler(currentProgram);

		/*
		 * This call initializes a new decompiler process to do decompilations for a new
		 * program
		 */
		if (!decomplib.openProgram(currentProgram)) {
			printf("Decompiler error: %s\n", decomplib.getLastMessage());
			return;
		}
		
		String args[] = getScriptArgs();
		
		// main id is only at arguments
		for( String s: args) {
			try {
				this.argid = Long.parseLong(s);
			} catch (Exception e) {
				continue;
			}
		}
		
		// check if we already declare main
		if (this.argid!=null)
		{
			Function posmain = currentProgram.getFunctionManager().getFunction(argid);
			// main already found
			if(posmain!=null)
			{
				//send it to taint analysis
			    storeHeadlessValue("MAINID", posmain.getID());
				return;
			}
		}
		
		FunctionIterator functionManager = currentProgram.getFunctionManager().getFunctions(true);
		for (Function function : functionManager) {
			//check for entry point and create main function if not found
			getEntryPoint(function);
			if(isFound) {
				break;
			}
		}
		
		//last option
		if (isFound == false)
		{
			// check for main symbol
			checkMainSymbol();
		}
		
		// give also output the id of the function that we declare main
		if(main != null)
		{
			System.out.println("CHECKMAIN=" + isFound + "," + main.getID());
		    storeHeadlessValue("MAINID", main.getID());
		}
		else
		{
			System.out.println("CHECKMAIN=" + isFound + ",null"); 
		}

		
		if(isFound) {
			analyzeChanges(currentProgram);
		}
		

	}

}
