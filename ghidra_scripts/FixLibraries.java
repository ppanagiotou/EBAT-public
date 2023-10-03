//TODO write a description for this script
// Deprecated not used DEBUG ONLY
//@author 
//@category EBAT
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;

import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.util.ELFExternalSymbolResolver;
import ghidra.util.Msg;

import java.util.HashMap;


public class FixLibraries extends GhidraScript {

	HashMap<String, String> libs = new HashMap<String, String>();
	
	public String givePath(String lib)
	{
		return libs.get(lib);
	}


	@Override
    public void run() throws Exception {

    	// to add the path and get the libraries
		ExternalManager ext = currentProgram.getExternalManager();
		
		//get arguments
		String[] args = getScriptArgs();
		
		//check if any
		if(args.length == 0)
		{
			return;
		}
	
		//for every argument
		for(int i=0; i < args.length; i++)
		{
			String[] arr = args[i].split(",");
			libs.put(arr[0],arr[1]);
		}

		printf("SET PATHS");
		String[] libnames = ext.getExternalLibraryNames();
		//libnames = ext.getExternalLibraryNames();
		for (String s : libnames) {
			
			printf("%s\n",s);

			try {
				
				String pathname = givePath(s);
				if(pathname != null)
				{
					//void setExternalPath​(java.lang.String libraryName, java.lang.String pathname, boolean userDefined) throws InvalidInputException
					ext.setExternalPath(s, "/" + pathname,true);
				}

			}
			catch (Exception exc) {
				printf("EXCEPTION in adding external path!\n");
				exc.printStackTrace();
			}

		}

		printf("FIX SYMBOLS");
		if (!ElfLoader.ELF_NAME.equals(currentProgram.getExecutableFormat())) {
			Msg.showError(this, null, "FixupELFExternalSymbols",
				"Current program is not an ELF program!  (" + currentProgram.getExecutableFormat() +
					")");
			return;
		}
		MessageLog msgLog = new MessageLog();
		ELFExternalSymbolResolver.fixUnresolvedExternalSymbols(currentProgram, false, msgLog,
			monitor);
		Msg.info(this, msgLog.toString());


		String[] arrs2 = ext.getExternalLibraryNames();

		String notfound = "";

		printf("GET PATHS");

		for (String libraryName : arrs2) {

			if(ext.getExternalLibraryPath(libraryName) == null)
			{
				notfound += "NOTFOUND " + libraryName + "\n";
			}

		 	printf("Lib:%s, %s\n",libraryName, ext.getExternalLibraryPath(libraryName));
		 }

		System.out.println(notfound);
   
    }
}
