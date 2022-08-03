//TODO write a description for this script
// DEBUG SCRIPT
//@author 
//@category EBAT
//@keybinding 
//@menupath 
//@toolbar 


import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;

public class PRINTALL extends HeadlessScript {

	
	private static String DELIMETER = "PRINTALL";
	
	class TOPRINT{
		
		Function f;
		int numref;
		String libname;
		
		TOPRINT(Function f, int numref, String libname)
		{
			this.f = f;
			this.numref = numref;
			this.libname = libname;
		}
	}
	
public void run() throws Exception {
	
	if(isHeadlessAnalysisEnabled()) {
		if (analysisTimeoutOccurred()) {
			printf("Analysis timeout occurred\n");
			return;
		}
	}
	
	/*
    	printf("------------EXTERNAL FUNCTIONS-------------\n");
		FunctionIterator functionManagerE = currentProgram.getFunctionManager().getExternalFunctions();
		for (Function function : functionManagerE) {
			
			if(function==null)
				continue;

    			printf("0x%X\t%s\n",
    					function.getEntryPoint().getOffset(),
    					function.getName());

    			    			if(function.isExternal() == true)
    			if(function.isExternal() == true)
    			{
    				String libname = function.getExternalLocation().getLibraryName();
					printf("%s, %s\n", libname, function.getExternalLocation().getOriginalImportedName());
	    			//if(libname != null)
					//{
					//	printf("Libname:%s\n",libname);
					//}
    			}
		}
    	printf("---------END EXTERNAL FUNCTIONS---------\n");
*/

		HashMap<String, TOPRINT> setf = new HashMap<>();
		HashSet<Function> alreadysetf = new HashSet<>();
		
    	/*Internal Functions!!!! */
    	//iterator over all functions in the program
    	FunctionIterator functionManager = currentProgram.getFunctionManager().getFunctions(true);

    	for (Function function : functionManager) {
    		
			if(function==null)
				continue;
			
    			//printf("0x%X\t%s\n",
    			//		function.getEntryPoint().getOffset(),
    			//		function.getName());

    			//fp.format("0x%X\t%s\n",
    			//		function.getEntryPoint().getOffset(),
    			//		function.getName());
    			Reference[] FunctionReferences = getReferencesTo(function.getEntryPoint());
    			if((function.isThunk() == true) || (function.isExternal() == true))
    			{
        			//Get an iterator over all references that have the given address as their "To" address.
    				
    				Function ftemp = function.getThunkedFunction(true);
    				ExternalLocation eloc = ftemp.getExternalLocation();
    				
    				String libname = "none";
    				if(eloc != null)
    					libname = eloc.getLibraryName(); 
    				//if(libname!=null)
    					//printf("Libname:%s , %d\n",libname, FunctionReferences.length);
	    			//if(libname != null)
					//{
					//	printf("Libname:%s\n",libname);
					//}
					if(FunctionReferences.length >= 1)
					{
						//if(!function.getName().startsWith("FUN_"))
						//{
						if(!alreadysetf.contains(function))
						{
							alreadysetf.add(function);
							setf.put(function.getName(), new TOPRINT(function, FunctionReferences.length ,libname));
							//printf("\n%s; %s; %s; %d; %s;%s;\n", DELIMETER, function.getName(), 
							//		function.getPrototypeString(true, true), FunctionReferences.length ,libname, currentProgram.getName());
						}

						//}

					}

					
    			}
    			else
    			{
					if(FunctionReferences.length >= 1)
					{
						if(!function.getName().startsWith("FUN_"))
						{
							if(!alreadysetf.contains(function))
							{
								alreadysetf.add(function);
								setf.put(function.getName(), new TOPRINT(function, FunctionReferences.length ,"none"));
							}

						}

					}
    			}
    			
    			

    		
    			//printf("Parameters Count: %d\n",function.getParameterCount());
    			//printf("Calling conversion name: %s\n",function.getCallingConventionName());
    			//getPrototypeString​(boolean formalSignature, boolean includeCallingConvention)
    			//printf("Function signature: %s\n",function.getPrototypeString(true, true));

    			//Parameter param = function.getReturn();

    			//printf("test:0x%X\n",param.getFirstUseOffset());
    
    	}
    	
    	
    	for(Map.Entry<String, TOPRINT> entry : setf.entrySet())
    	{
    		Function function = entry.getValue().f;
    		
    		printf("\n%s; %s; %s; %d; %s;%s;\n",DELIMETER, function.getName(), function.getPrototypeString(true, true), 
    				entry.getValue().numref, entry.getValue().libname, currentProgram.getName());
    	}

  
	}
}
