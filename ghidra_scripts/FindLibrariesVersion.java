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
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.exception.NotYetImplementedException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.Expose;


public class FindLibrariesVersion extends HeadlessScript {
	

	private DecompInterface decomplib;
	

	private String currentType = "";
	
	boolean debug = false;
	
	
	@Expose(serialize = true, deserialize = true)
	private String versionType = "";
	@Expose(serialize = true, deserialize = true)
	ArrayList<Results> fres = new ArrayList<>();
	

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
		 * TODO: add MAYBE MORE DECOMPILER FEATURE
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
			printf("EXCEPTION IN DECOMPILATION!\n");
			exc.printStackTrace();
		}

		return hfunction;
	}

	
	
	private ArrayList<String> getAtAddr(Address addr, String type) throws AddressFormatException {

		ArrayList<String> retarr = new ArrayList<>();
		
		if (addr == null) {
			return null;
		}

		Address daddr = currentAddress.getAddress(Long.toHexString(addr.getOffset()));

		// Get string at an address, if present
		Data data = getDataAt(daddr);

		// try to get the string if already is defined
		if (data != null) {
			StringDataInstance str = StringDataInstance.getStringDataInstance(data);
			String s = str.getStringValue();
			retarr.add(s);
			return retarr;
		}
		
		
		// if data is null check if it is a string
		if (type.equals("string")) {
			// automatically
			try {
				// remove the data type
				removeDataAt(daddr);
				// add manually the type
				data = createAsciiString(daddr);

				StringDataInstance str = StringDataInstance.getStringDataInstance(data);
				String s = str.getStringValue();

				if (s != null) {
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
	
	
	private ArrayList<String> getPossibleTypeValue(Address addr) {

		ArrayList<String> str = null;
		try {
			str = getAtAddr(addr, currentType);
		} catch (AddressFormatException e) {
			//pass
		}
		return str;
	}
	
	class Results
	{
		@Expose(serialize = true, deserialize = true)
		long value;
		@Expose(serialize = true, deserialize = true)
		ArrayList<String> str = null;
		@Expose(serialize = true, deserialize = true)
		boolean isStr;
		@Expose(serialize = true, deserialize = true)
		boolean isMajor = false;
		@Expose(serialize = true, deserialize = true)
		boolean isMinor = false;
		
		Results(long value)
		{
			this.value = value;
			this.isStr = false;
		}
		
		Results(ArrayList<String> str)
		{
			this.str = str;
			this.isStr = true;
		}
	}
	
	Results retResults(long value, ArrayList<String> str)
	{
		if (str == null)
		{
			return new Results(value);
		}

		return new Results(str);
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

	private HashMap<Address, Integer> traverse = new HashMap<>();
	private int LIMIT_FLATTEN_LOOP = 3*2 + 1;
	// TODO same as TaintAnalysis.java
	ArrayList<Results> processVarNode(ArrayList<Results> res, Varnode v, Function f, boolean isPointer, int offset) throws AddressFormatException, NotYetImplementedException, InvalidInputException, NotFoundException
	{
		

		if (v == null) {
			return res;
		}
		
		// get the p-code op defining the varnode
		// may this address not exists
		Address pcaddr = null;
		try {
			pcaddr = v.getPCAddress();
			if (pcaddr == null){
				pcaddr = v.getAddress();
			}
		}
		catch (Exception e){
			//pass
		}
		
		if (pcaddr != null){			// check path
			if (traverse.containsKey(pcaddr)) {
				int counter = traverse.get(pcaddr);
				traverse.put(pcaddr, counter + 1);
	
				if (counter >= LIMIT_FLATTEN_LOOP) {
					return res;
				}

			}
			else {
				// save the path after exploration
				traverse.put(pcaddr, 0);
			}
		}
		else {
			return res;
		}
		
		if (v.isConstant()) {
			long value = v.getOffset() + offset;
			// get argument if it is a string
			ArrayList<String> str = getPossibleTypeValue(currentAddress.getAddress(Long.toHexString(value)));
			res.add(retResults(value, str));
			return res;
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
				ArrayList<String> str = getPossibleTypeValue(addrpointer);
				long value = v.getOffset();
				res.add(retResults(value, str));
				return res;
			}
			
			// get argument if it is a string
			ArrayList<String> str = getPossibleTypeValue(addrpointer);
			long value = v.getOffset();
			res.add(retResults(value, str));
			return res;
		}
		
		// get the p-code op defining the varnode
		PcodeOp def = v.getDef();
		
		if (def == null) {
			return res;
		}
		
		return processPcodeOp(res, def, v, f, isPointer, offset);
	}
		
	ArrayList<Results> processPcodeOp(ArrayList<Results> res, PcodeOp def, Varnode v, Function f, boolean isPointer, int offset) throws NotYetImplementedException, InvalidInputException, NotFoundException, AddressFormatException {
		
		// get the enum value of the p-code operation that defines our varnode
		int opcode = def.getOpcode();
		
		if(this.debug) {
			printf("processPcodeOp: %s\n", def.toString());
		}


		switch (opcode) {
			case PcodeOp.INT_NEGATE:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
			case PcodeOp.INT_2COMP:{
				processVarNode(res, def.getInput(0), f, isPointer, offset);
				break;
			}
			
			
			case PcodeOp.CAST:
			case PcodeOp.COPY: {
				processVarNode(res, def.getInput(0), f, isPointer, offset);
				break;
			}

			case PcodeOp.INT_ADD:
			{
				
				ArrayList<Results> lres = new ArrayList<>();
				
				// naive approach discards phi and add only in offset
				// ptr + x
				lres = processVarNode(lres, def.getInput(0), f, isPointer, offset);
				lres = processVarNode(lres, def.getInput(1), f, isPointer, offset);

				boolean found = false;
				for(Results e : lres)
				{
					if (e.isStr){
						continue;
					}
					
					if(this.debug) {
						printf("v = %x\n", e.value);
					}
					
					found = true;
					processVarNode(res, def.getInput(0), f, isPointer, offset + (int)e.value);
					processVarNode(res, def.getInput(1), f, isPointer, offset + (int)e.value);
				}
				
				if (found == false){
					processVarNode(res, def.getInput(0), f, isPointer, offset);
					processVarNode(res, def.getInput(1), f, isPointer, offset);
				}
				
				
				
				break;
			}
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
				

				
				processVarNode(res, def.getInput(0), f, isPointer, offset);
				processVarNode(res, def.getInput(1), f, isPointer, offset);
				break;
			}
			
			case PcodeOp.FLOAT_ADD:
			case PcodeOp.FLOAT_SUB:
			case PcodeOp.FLOAT_MULT:
			case PcodeOp.FLOAT_DIV:{
	
				processVarNode(res, def.getInput(0), f, isPointer, offset);
				processVarNode(res, def.getInput(1), f, isPointer, offset);
				break;
			}
			
			case PcodeOp.FLOAT_INT2FLOAT: {
				processVarNode(res, def.getInput(0), f, isPointer, offset);
				break;
			}

	
			case PcodeOp.MULTIEQUAL: {

				// visit each input to the MULTIEQUAL
				for (int i = 0; i < def.getInputs().length; i++) {
					// we set isPhi = true, as we trace each of the phi inputs
					processVarNode(res, def.getInput(i), f, isPointer, offset);
				}
				break;
			}
	
	
			case PcodeOp.INDIRECT: {
				
				if(def.getInput(0).isConstant()) {
					// A constant varnode (zero) for input0 is used by analysis to indicate that the output of the INDIRECT is produced solely by the 
					// p-code operation producing the indirect effect, and there is no possibility that the value existing prior to the operation 
					// was used or preserved.
					if(def.getInput(0).getOffset() == 0x0)
					{
						processVarNode(res, def.getInput(1), f, isPointer, offset);
						break;
					}
				}
		
				//indirect stack load with same input as output
				Varnode output = def.getOutput();
				if (output.getAddress().equals(def.getInput(0).getAddress())) {
					// show constant use
					processVarNode(res, def.getInput(0), f, isPointer, offset);
					break;
				}
	
				if (def.getInput(0).isUnique()) {
					processVarNode(res, def.getInput(0), f, isPointer, offset);
					break;
				}
				
				if ((def.getInput(0).isAddrTied()) || (def.getInput(0).isAddress()) && (def.getInput(0).isRegister() == false)) {
					Address addrpointer = resolvePointer(def.getInput(0), 0x0, false);
					if (addrpointer != null){
						// get argument if it is a string
						ArrayList<String> str = getPossibleTypeValue(addrpointer);
						long value = v.getOffset();
						res.add(retResults(value, str));
						break;
					}
				}

				processVarNode(res, def.getInput(0), f, isPointer, offset);
				break;
			}
	
			/*
			 * Two more p-code operations which take two inputs
			 */
			case PcodeOp.PIECE: {
				processVarNode(res, def.getInput(0), f, isPointer, offset);
				processVarNode(res, def.getInput(1), f, isPointer, offset);
				break;
			}
	
			case PcodeOp.PTRSUB: {
				/*
				 * input0 Varnode containing pointer to structure. input1 Varnode containing
				 * integer offset to a subcomponent. pointer calculation input0 + input1
				 */
	
				Varnode offsetVal = def.getInput(1);
				if (!offsetVal.isConstant()) {
					break;
				}
	
				Varnode baseVal = def.getInput(0);
				if (baseVal.isConstant()) {
					
					// both constant, just use it and return the address
					long value = baseVal.getOffset() + offsetVal.getOffset() + offset;
					
					// get argument if it is a string
					ArrayList<String> str = getPossibleTypeValue(currentAddress.getAddress(Long.toHexString(value)));
					res.add(retResults(value, str));
					break;
				}
	
				// if is address and not register
				if ((baseVal.isAddrTied()) || (baseVal.isAddress()) && (baseVal.isRegister() == false))
				{
					// force = true
					Address addrpointer = resolvePointer(baseVal, offsetVal.getOffset(), true);
					if (addrpointer != null)
					{
						// get argument if it is a string
						ArrayList<String> str = getPossibleTypeValue(addrpointer);
						long value = v.getOffset();
						res.add(retResults(value, str));
						break;
					}
				}
				
				// if it is a register need to resolve the register then add them to the index
				if (offsetVal.getOffset() == 0) {
					processVarNode(res, def.getInput(0), f, true, offset);
					break;
				}
				
				if(baseVal.isUnique()) {
					processVarNode(res, def.getInput(0), f, isPointer, (int)offsetVal.getOffset() + offset);	
					break;
				}
				
				//processStackVariable
				res = processStackVariable(res, f, baseVal, (int)offsetVal.getOffset() + offset);
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
					long value = arrptr.getOffset() + (index.getOffset() * elemsize.getOffset()) + offset;
					
					// get argument if it is a string
					ArrayList<String> str = getPossibleTypeValue(currentAddress.getAddress(Long.toHexString(value)));
					res.add(retResults(value, str));
					break;
				}
				
				if ((arrptr.isAddrTied()) || (arrptr.isAddress()) && (arrptr.isRegister() == false)) 
				{
					Address addrpointer = resolvePointer(arrptr, (index.getOffset() * elemsize.getOffset()), true);
					if (addrpointer!=null)
					{
						// get argument if it is a string
						ArrayList<String> str = getPossibleTypeValue(addrpointer);
						long value = v.getOffset();
						res.add(retResults(value, str));
						break;
					}
				}
				
				// if there is no offset proceed and is a register
				if ((index.getOffset() * elemsize.getOffset()) == 0) {
					processVarNode(res, def.getInput(0), f, true, offset);
					break;
				}
				
				if(arrptr.isUnique()) {
					processVarNode(res, def.getInput(0), f, isPointer, (int)(index.getOffset() * elemsize.getOffset()) + offset);
					break;
				}
	
				//processStackVariable
				res = processStackVariable(res, f, arrptr, (int)(index.getOffset() * elemsize.getOffset() + offset));
				
				break;
			}
	
			case PcodeOp.SUBPIECE: {
				long value = def.getInput(1).getOffset();
				if (value != 0) {
					processVarNode(res, def.getInput(1), f, isPointer, offset);
				}
	
				processVarNode(res, def.getInput(0), f, isPointer, offset);
	
				break;
			}
	
			case PcodeOp.INT_EQUAL:
			case PcodeOp.INT_NOTEQUAL:
			case PcodeOp.INT_LESS:
			case PcodeOp.INT_SLESS:
			case PcodeOp.INT_LESSEQUAL:
			case PcodeOp.INT_SLESSEQUAL:
			case PcodeOp.BOOL_NEGATE:
			case PcodeOp.BOOL_XOR:
			case PcodeOp.BOOL_AND:
			case PcodeOp.BOOL_OR: {
				processVarNode(res, def.getInput(0), f, isPointer, offset);
				processVarNode(res, def.getInput(1), f, isPointer, offset);
				break;
			}
	
			case PcodeOp.LOAD: {
				
				// input0 	(special) 	Constant ID of space to load from.
				// I think no need to taint.
				
				// input1  Varnode containing pointer offset to data.
				processVarNode(res, def.getInput(1), f, isPointer, offset);
				break;
			}
			case PcodeOp.FLOAT_TRUNC: {
				// try to resolve it
				processVarNode(res, def.getInput(0), f, isPointer, offset);
				break;
			}
	
			// throw an exception when encountering a p-code op we don't support
			default: {
				//throw new NotYetImplementedException("TODO Support for PcodeOp " + def.toString() + "not implemented");
				printf("TODO Support for PcodeOp " + def.toString() + "not implemented");
			}
		
		}
		
		return res;
	}
	
	
	
	private ArrayList<Results> processStackVariable(ArrayList<Results> res, Function f, Varnode baseVal, int offsetVal) throws NotYetImplementedException, InvalidInputException, NotFoundException, AddressFormatException {
		if (baseVal.isRegister()){
			// get the variable from the stack frame
			StackFrame s = f.getStackFrame();
			Variable x = s.getVariableContaining(offsetVal);
			if (x == null) {
				return res;
			}
			
			// if it is a stack variable
			if (x.isStackVariable()){
	
				Varnode vf = x.getFirstStorageVarnode();
				Varnode vl = x.getLastStorageVarnode();
				
				HighFunction high = decompileFunction(f);
				if (high == null) {
					printf("ERROR: Failed to decompile function!\n");
					return res;
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

						res = processPcodeOp(res, pcodeOpAST, baseVal, f, true, offsetVal);
					}
				}
			}
		}
		
		return res;
	}
	
	
	
	ArrayList<Results> findVersion(Function f, boolean taintCalls) throws AddressFormatException, NotYetImplementedException, InvalidInputException, NotFoundException
	{
		HighFunction hfunction = decompileFunction(f);
		if (hfunction == null) {
			printf("Failed to decompile function!");
			return null;
		}
		
		printf("Function %s entry @ 0x%x\n", f.getName(), f.getEntryPoint().getOffset());

		Iterator<PcodeOpAST> ops = hfunction.getPcodeOps();
		
		ArrayList<Results> retres = new ArrayList<>();

		// Loop through the functions p-code ops, looking for RETURN
		while (ops.hasNext() && !monitor.isCancelled()) {
			PcodeOpAST pcodeOpAST = ops.next();
			
			//try to taint the function calls also
			if (taintCalls == true)
			{
				if ((pcodeOpAST.getOpcode() == PcodeOp.CALL) || (pcodeOpAST.getOpcode() == PcodeOp.BRANCH)
						||  (pcodeOpAST.getOpcode() == PcodeOp.CBRANCH)) {
					// current p-code op is a CALL
					// get the address CALL-ed
					Varnode calledVarnode = pcodeOpAST.getInput(0);

					if (calledVarnode == null || !calledVarnode.isAddress()) {
						printf("ERROR: call, but not to address!");
						continue;
					}

					Function possiblef = getFunctionAt(calledVarnode.getAddress());
					if (possiblef == null){
						continue;
					}
					
					ArrayList<Results> res = findVersion(possiblef, false);
					if (res != null)
					{
						for( Results e : res)
							retres.add(e);
					}
					
					ArrayList<String> arrstr = findDefinedUsedData(possiblef);
					if (arrstr.size() > 0) {
						retres.add(new Results(arrstr));
					}

					continue;
				}
				// do not resolve indirect function call is to complicate no need
			}

			// if it not return
			if (pcodeOpAST.getOpcode() != PcodeOp.RETURN) {
				continue;
			}

			
			// 0 is the OFFSET on return instruction
			for (int i = 1; i < pcodeOpAST.getNumInputs(); i++) {
				traverse.clear();
				// get the varnode for the function's return value
				Varnode returnedValue = pcodeOpAST.getInput(i);
				ArrayList<Results> res = processVarNode(new ArrayList<Results>(), returnedValue, f, false, 0x0);
				
				if (res != null)
				{
					for( Results e : res)
						retres.add(e);
				}
			}
		}

		return retres;
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

	
	
	boolean getTaintPoint(Function function) throws Exception
	{	
		
		if (function.isExternal())
			return false;

		//OpenSSL
		if(function.getName().equals("SSLeay_version") || function.getName().equals("OpenSSL_version"))
		{
			this.versionType = "openssl";
			this.currentType = "string";
			this.fres = findVersion(function, false);
			
			ArrayList<String> arrstr = findDefinedUsedData(function);
			if (arrstr.size() > 0) {
				this.fres.add(new Results(arrstr));
			}

			if (this.fres.size() > 0)
				return true;
			
		}
		// WolfSSL 
		else if((function.getName().equals("wolfSSL_lib_version")) || (function.getName().equals("CyaSSL_lib_version")))
		{
			this.versionType = "libwolfssl";
			this.currentType = "string";
			this.fres = findVersion(function, false);
			
			ArrayList<String> arrstr = findDefinedUsedData(function);
			if (arrstr.size() > 0) {
				this.fres.add(new Results(arrstr));
			}
			
			if (this.fres.size() > 0)
				return true;
		
		}
		// libgcrypt
		else if(function.getName().equals("gcry_check_version"))
		{
			this.versionType = "libgcrypt";
			this.currentType = "string";
			this.fres = findVersion(function, true);
			
			ArrayList<String> arrstr = findDefinedUsedData(function);
			if (arrstr.size() > 0) {
				this.fres.add(new Results(arrstr));
			}
			
			if (this.fres.size() > 0)
				return true;
		}
		// GNUTLS
		else if(function.getName().equals("gnutls_check_version"))
		{

			this.versionType = "libgnutls";
			this.currentType = "string";
			this.fres = findVersion(function, true);
			
			ArrayList<String> arrstr = findDefinedUsedData(function);
			if (arrstr.size() > 0) {
				this.fres.add(new Results(arrstr));
			}
			
			if (this.fres.size() > 0)
				return true;
		}
		// mbedTLS or polarssl
		else if((function.getName().equals("mbedtls_version_get_number")) || (function.getName().equals("version_get_number")))
		{
			this.versionType = "libmbedcrypto";
			this.currentType = "int";
			this.fres = findVersion(function, false);
			if (this.fres.size() > 0)
				return true;
		}
		// libmcrypt
		else if(function.getName().equals("mcrypt_check_version"))
		{
			this.versionType = "libmcrypt";
			this.currentType = "string";
			this.fres = findVersion(function, false);
			
			ArrayList<String> arrstr = findDefinedUsedData(function);
			if (arrstr.size() > 0) {
				this.fres.add(new Results(arrstr));
			}
			
			if (this.fres.size() > 0)
				return true;
		}
		// libsodium
		else if(function.getName().equals("sodium_version_string"))
		{
			this.versionType = "libsodium";
			this.currentType = "string";
			this.fres = findVersion(function, false);
			
			ArrayList<String> arrstr = findDefinedUsedData(function);
			if (arrstr.size() > 0) {
				this.fres.add(new Results(arrstr));
			}
			
			if (this.fres.size() > 0)
				return true;
		}
		// nettle major
		else if(function.getName().equals("nettle_version_major"))
		{
			this.versionType = "libnettle";
			this.currentType = "string";
			ArrayList<Results> tempres = findVersion(function, false);
			
			ArrayList<String> arrstr = findDefinedUsedData(function);
			if (arrstr.size() > 0) {
				Results obj = new Results(arrstr);
				obj.isMajor = true;
				this.fres.add(obj);
			}
			
			for( Results e : tempres)
			{
				e.isMajor = true;
				this.fres.add(e);
			}

		}
		// nettle minor
		else if(function.getName().equals("nettle_version_minor"))
		{
			this.versionType = "libnettle";
			this.currentType = "string";
			ArrayList<Results> tempres = findVersion(function, false);
			
			ArrayList<String> arrstr = findDefinedUsedData(function);
			if (arrstr.size() > 0) {
				Results obj = new Results(arrstr);
				obj.isMinor = true;
				this.fres.add(obj);
			}
			
			for( Results e : tempres)
			{
				e.isMinor = true;
				this.fres.add(e);
			}

		}

		return false;
	}

	
	@Override
	protected void run() throws Exception {
		
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
		
		
		FunctionIterator functionManager = currentProgram.getFunctionManager().getFunctions(true);
		for (Function function : functionManager) {
			//check for entry point and create main function if not found
			boolean ret = getTaintPoint(function);
			if(ret == true)
			{
				break;
			}
		}
		
		GsonBuilder builder = new GsonBuilder().disableHtmlEscaping();
		
		builder.excludeFieldsWithoutExposeAnnotation();
		Gson gson = builder.create();
		
		String json = gson.toJson(this);
		System.out.println("JSONLIBS;" + json);
		if(debug) {
			printf("%s,", json);
		}
	}

}
