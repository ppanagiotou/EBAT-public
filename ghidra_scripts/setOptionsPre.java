//TODO write a description for this script
//@author Paris Panagiotou
//@category EBAT
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;

import java.util.Map;


public class setOptionsPre extends GhidraScript{
	
	private static final int LEVEL1 = 1;
	private static final int LEVEL2 = 2;
	private static final int LEVEL3 = 3;

	
	private static final String DECOMPILER_PARAMETER_ID = "Decompiler Parameter ID";
	
	private static final String DATA_REFERENCE_SWITCH_TABLE_REFERENCES = "Data Reference.Switch Table References";
	private static final String DATA_REFERENCE_Create_Address_Tables = "Data Reference.Create Address Tables";
	
	
	private static final String REFERENCE_ADDRESS_TABLE_REFERENCES = "Reference.Create Address Tables";
	private static final String REFERENCE_ADDRESS_SWITCH_REFERENCES = "Reference.Switch Table References";
	
	private static final String ARM_AGGRESSIVE_INSTRUCTION_FINDER = "ARM Aggressive Instruction Finder";
	
	private static final String AGGRESIVE_INSTRUCTION_FINDER = "Aggressive Instruction Finder";
	
	private static final String ELF_SCALAR_OPERAND_REFERENCES = "ELF Scalar Operand References";
	
	private static final String MIPS_Constant_Reference_Analyzer = "MIPS Constant Reference Analyzer";
	private static final String MIPS_Constant_Reference_Analyzer_Switch_Tables = "MIPS Constant Reference Analyzer.Attempt to recover switch tables";
	
	private static final String ARM_Constant_Reference_Analyzer_Switch = "ARM Constant Reference Analyzer.Switch Table Recovery";
	
	private static final String DEMANGLER_ONLY_MANGLED_SYMBOLS = "Demangler GNU.Demangle Only Known Mangled Symbols";
	
	private boolean isLib = false;
	// default level
	private int level = LEVEL1;
	// only for debug
	private boolean debug = false;
	
	@Override
	protected void run() throws Exception {
		
		String[] args = getScriptArgs();
		//for every argument
		for(int i=0; i < args.length; i++)
		{
			if(args[i].equals("isLib"))
			{
				isLib = true;
			}
			else if(args[i].equals("level"))
			{
				level = Integer.valueOf(args[i+1]);
				i++;
				continue;
			}
		}

		
		Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
		
		if(debug) {
	    	for (Map.Entry<String, String> entry : options.entrySet()) {
	    		
	    		String opt1 = entry.getKey();
	    		String opt2 = entry.getValue();
	    		printf("%s , %s\n", opt1,opt2);
	    	}
		}
    	
		//default level 1
		if(isLib == true)
		{
			if (options.containsKey(ELF_SCALAR_OPERAND_REFERENCES)) {
				setAnalysisOption(currentProgram, ELF_SCALAR_OPERAND_REFERENCES, "true");
			}
		}
		
		//level 1
		if(level >= LEVEL1) {
			if (options.containsKey(MIPS_Constant_Reference_Analyzer)) {
				setAnalysisOption(currentProgram, MIPS_Constant_Reference_Analyzer, "true");
			}
			if (options.containsKey(DEMANGLER_ONLY_MANGLED_SYMBOLS)) {
				setAnalysisOption(currentProgram, DEMANGLER_ONLY_MANGLED_SYMBOLS, "true");
			}
			if (options.containsKey(MIPS_Constant_Reference_Analyzer_Switch_Tables)) {
				setAnalysisOption(currentProgram, MIPS_Constant_Reference_Analyzer_Switch_Tables, "true");
			}
			if (options.containsKey(DATA_REFERENCE_SWITCH_TABLE_REFERENCES)) {
				setAnalysisOption(currentProgram, DATA_REFERENCE_SWITCH_TABLE_REFERENCES, "true");
			}
			if (options.containsKey(DATA_REFERENCE_Create_Address_Tables)) {
				setAnalysisOption(currentProgram, DATA_REFERENCE_Create_Address_Tables, "true");
			}
			if (options.containsKey(REFERENCE_ADDRESS_TABLE_REFERENCES)) {
				setAnalysisOption(currentProgram, REFERENCE_ADDRESS_TABLE_REFERENCES, "true");
			}
			if (options.containsKey(REFERENCE_ADDRESS_SWITCH_REFERENCES)) {
				setAnalysisOption(currentProgram, REFERENCE_ADDRESS_SWITCH_REFERENCES, "true");
			}
			if (options.containsKey(ARM_Constant_Reference_Analyzer_Switch)) {
				setAnalysisOption(currentProgram, ARM_Constant_Reference_Analyzer_Switch, "true");
			}
		}
		
		//level 2
		if(level >= LEVEL2)
		{
	    	//WARNING THIS CAN TAKE SIGNIFICANT AMOUNT OF TIME!!!
			if (options.containsKey(DECOMPILER_PARAMETER_ID)) {
				setAnalysisOption(currentProgram, DECOMPILER_PARAMETER_ID, "true");
			}
		}
		
		//level 3
		if(level >= LEVEL3)
		{
	    	//WARNING aggressive disassemble
			if (options.containsKey(ARM_AGGRESSIVE_INSTRUCTION_FINDER)) {
				setAnalysisOption(currentProgram, ARM_AGGRESSIVE_INSTRUCTION_FINDER, "true");
			}
			
			if (options.containsKey(AGGRESIVE_INSTRUCTION_FINDER)) {
				setAnalysisOption(currentProgram, ARM_AGGRESSIVE_INSTRUCTION_FINDER, "true");
			}
		}

		

	}

}
