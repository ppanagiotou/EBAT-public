/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Finds undefined functions by searching for common 
//byte patterns used by compilers for function entry points.
//
//Only Intel GCC, Windows, and PowerPC are currently
//handled.
//
//Please feel free to change this script and add
//different byte patterns.
//
//When the byte pattern is found, the instructions 
//will be disassembled and a function will be created.
//
//Please note: this will NOT find all undefined functions!
//@category EBAT


import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class FindUndefinedFunctions extends HeadlessScript {

	Memory memory;
	boolean isDebug = false;
	@Override
	protected void run() throws Exception {
		
		if(isHeadlessAnalysisEnabled()) {
			if (analysisTimeoutOccurred()) {
				printf("Analysis timeout occurred\n");
				return;
			}
		}
		
		
		String[] args = getScriptArgs();
		//for every argument
		for(int i=0; i < args.length; i++)
		{
			if(args[i].equals("debug"))
			{
				isDebug = true;
			}
		}
		
		boolean isFound = false;
		
		//get current program memory
		memory = currentProgram.getMemory();
		
		PatternMatcher[] expectedPatterns = getPatterns();
		
		if(expectedPatterns != null)
		{
			MemoryBlock[] memoryBlock = currentProgram.getMemory().getBlocks();
			//for every block
			for (int i = 0; i < memoryBlock.length; i++) {
				if (memoryBlock[i].isExecute()) {
					for (PatternMatcher expectedPattern : expectedPatterns) {
						boolean keepSearching = true;
						Address start = memoryBlock[i].getStart();
						Address end = memoryBlock[i].getEnd();
						while ((keepSearching) && (!monitor.isCancelled())) {
							Address found = expectedPattern.CheckIfMatch(start, end, memoryBlock[i]);
							if(found != null)
							{
								Function testFunc = getFunctionContaining(found);
								if (testFunc == null) {
									boolean didDisassemble = disassemble(found);
									if (didDisassemble) {
										Function func = createFunction(found, null);
										isFound = true;
										if(isDebug)
										if (func != null) {
											println("Made function at address: " + found.toString());
										}
										else {
											println("***Function could not be made at address: " +
												found.toString());
										}
									}
								}
								else {
									if(isDebug) {
									println("Function already exists at address: " + found.toString() + " name = " + testFunc.getName() + 
											" @0x" + Long.toString(testFunc.getEntryPoint().getOffset()));
									}
								}
								start = found.add(4);
							}
							else {
								//no pattern found
								keepSearching = false;
							}
						}
					}
				}	
			}
		}
		else
		{
			printf("unsupported language\n");
		}
		
		System.out.println("CHECKUNDEFINED=" + isFound); 

	}

	private PatternMatcher[] getPatterns() {
		if (currentProgram == null) {
			return null;
		}

		Processor processor = currentProgram.getLanguage().getProcessor();

		if (processor.equals(Processor.findOrPossiblyCreateProcessor("x86"))) {
			CompilerSpecID compilerSpecID = currentProgram.getCompilerSpec().getCompilerSpecID();
			if (compilerSpecID.equals(new CompilerSpecID("windows"))) {
				return new PatternMatcher[] { new PatternMatcher(new byte[] { (byte) 0x55,
					(byte) 0x8b, (byte) 0xec }, false), };
			}
			if (compilerSpecID.equals(new CompilerSpecID("gcc"))) {
				return new PatternMatcher[] { new PatternMatcher(new byte[] { (byte) 0x55,
					(byte) 0x89, (byte) 0xe5 }, false), };
			}
		}

		// Endianness OK here?
		if (processor.equals(Processor.findOrPossiblyCreateProcessor("PowerPC"))) {
			return new PatternMatcher[] { new PatternMatcher(new byte[] { (byte) 0x7c, (byte) 0x08,
				(byte) 0x02, (byte) 0xa6 }, false),//
			};
		}
		if (processor.equals(Processor.findOrPossiblyCreateProcessor("ARM"))) {
			return new PatternMatcher[] {
				//new PatternMatcher(new byte[]{(byte)0x00,(byte)0x00,(byte)0x50,(byte)0xe3}, true),//only check 'cmp' at function entry
				//new PatternMatcher(new byte[]{(byte)0x00,(byte)0x00,(byte)0x51,(byte)0xe3}, true),//only check 'cmp' at function entry
				//new PatternMatcher(new byte[]{(byte)0x00,(byte)0x00,(byte)0x53,(byte)0xe3}, true),//only check 'cmp' at function entry
				new PatternMatcher(
					new byte[] { (byte) 0xf0, (byte) 0x40, (byte) 0x2d, (byte) 0xe9 }, false),//stmdb sp!{r4 r5 r6 r7 lr}
				new PatternMatcher(
					new byte[] { (byte) 0xb0, (byte) 0x40, (byte) 0x2d, (byte) 0xe9 }, false),//stmdb sp!{r4 r5 r7 lr}
				new PatternMatcher(
					new byte[] { (byte) 0x90, (byte) 0x40, (byte) 0x2d, (byte) 0xe9 }, false),//stmdb sp!{r4 r7 lr}
				new PatternMatcher(
					new byte[] { (byte) 0x80, (byte) 0x40, (byte) 0x2d, (byte) 0xe9 }, false),//stmdb sp!{r7 lr}
				new PatternMatcher(
					new byte[] { (byte) 0xf3, (byte) 0x47, (byte) 0x2d, (byte) 0xe9 }, false),//stmdb sp!,{ r0 r1 r4 r5 r6 r7 r8 r9 r10 lr }
				new PatternMatcher(
					new byte[] { (byte) 0xf0, (byte) 0x41, (byte) 0x2d, (byte) 0xe9 }, false),//stmdb sp!,{ r4 r5 r6 r7 r8 lr }    
				new PatternMatcher(
					new byte[] { (byte) 0xf0, (byte) 0x4f, (byte) 0x2d, (byte) 0xe9 }, false),//stmdb sp!,{ r4 r5 r6 r7 r8 r9 r10 r11 lr }
				//new PatternMatcher(
					//new byte[] { (byte) 0xf7, (byte) 0x45, (byte) 0x2d, (byte) 0xe9 }, false),//stmdb sp!,{ r0 r1 r2 r4 r5 r6 r7 r8 r10 lr }

			};
		}
		
		return null;
	}

	private class PatternMatcher {
		byte[] expectedBytes;
		@SuppressWarnings("unused")
		boolean requiresEntyPoint;

		PatternMatcher(byte[] expectedBytes, boolean requiresEntryPoint) {
			this.expectedBytes = expectedBytes;
			this.requiresEntyPoint = requiresEntryPoint;
		}

		Address CheckIfMatch(Address start, Address end, MemoryBlock memoryblock) {
			Address found =
					memory.findBytes(start, end, expectedBytes, null, true, monitor);
			if ((found != null) && memoryblock.contains(found)) {
				return found;
			}
			
			return null;
		}
	}

}
