//TODO write a description for this script
//@author 
//@category EBAT
//@keybinding 
//@menupath 
//@toolbar 

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.Expose;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.symbol.ExternalManager;

public class FindLibraries extends HeadlessScript {
	
	@Expose(serialize = true, deserialize = true)
	private String[] libnames;
	
	GsonBuilder builder = null;

	@Override
    public void run() throws Exception {

    	// to add the path and get the libraries
		ExternalManager ext = currentProgram.getExternalManager();

		libnames = ext.getExternalLibraryNames();
		
		builder = new GsonBuilder().disableHtmlEscaping();
		
		builder.excludeFieldsWithoutExposeAnnotation();
		Gson gson = builder.create();
		
		String json = gson.toJson(this);

		System.out.println("JSON;" + json);
   
    }
}

