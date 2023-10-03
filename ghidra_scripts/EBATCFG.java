//TODO write a description for this script
// based on GraphAST AND BlockGraphTask
//@author Paris Panagiotou
//@category EBAT
//@keybinding 
//@menupath 
//@toolbar 

import java.util.*;
import ghidra.app.plugin.core.graph.AddressBasedGraphDisplayListener;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.service.graph.*;
import ghidra.util.Msg;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;


import ghidra.util.exception.CancelledException;

public class EBATCFG extends HeadlessScript  {
	
	
	
	class mPair {

		AttributedVertex source;
		AttributedVertex target;
		public mPair(AttributedVertex source, AttributedVertex target) {
			this.source = source;
			this.target = target;
		}

	}
	
	protected static final String COLOR_ATTRIBUTE = "Color";
	protected static final String ICON_ATTRIBUTE = "Icon";
	
	/**
	 * Edge flow tags
	 */
	protected final static int FALLTHROUGH = 0;
	protected final static int CONDITIONAL_RETURN = 1;
	protected final static int UNCONDITIONAL_JUMP = 2;
	protected final static int CONDITIONAL_JUMP = 3;
	protected final static int UNCONDITIONAL_CALL = 4;
	protected final static int CONDITIONAL_CALL = 5;
	protected final static int TERMINATOR = 6;
	protected final static int COMPUTED = 7;
	protected final static int INDIRECTION = 8;
	protected final static int ENTRY = 9; // from Entry Nexus
	
	protected final static String[] edgeNames =
		{ "1", "2", "3", "4", "5", "6", "7", "13", "14", "15" };
	
	// @formatter:off
	protected final static String[] edgeTypes = {
			"Fall-Through",
			"Conditional-Return",
			"Unconditional-Jump",
			"Conditional-Jump",
			"Unconditional-Call",
			"Conditional-Call",
			"Terminator",
			"Computed",
			"Indirection",
			"Entry" 
	};
	// @formatter:on
	
	private final static String ENTRY_NODE = "Entry";
	// "1";       // beginning of a block, someone calls it
	private final static String BODY_NODE = "Body";
	// "2";       // Body block, no flow
	private final static String EXIT_NODE = "Exit";
	// "3";       // Terminator
	private final static String SWITCH_NODE = "Switch";
	// "4";       // Switch/computed jump
	private final static String BAD_NODE = "Bad";
	// "5";       // Bad destination
	private final static String DATA_NODE = "Data";
	// "6";       // Data Node, used for indirection
	private final static String ENTRY_NEXUS = "Entry-Nexus";
	// "7";       //
	private final static String EXTERNAL_NODE = "External";
	// "8";       // node is external to program

	private final static String ENTRY_NEXUS_NAME = "Entry Points";
	
	private AddressSetView graphScope;
	CodeBlockModel blockModel;
	
	private boolean debug = false;

	@Override
	public void run() throws Exception{


		//BlockModelService blockModelService = state.getTool().getService(BlockModelService.class);
		//this.blockModel = blockModelService.getActiveBlockModel(currentProgram);
		
		SimpleBlockModel model = new SimpleBlockModel(currentProgram);
		this.blockModel = model;

		this.graphScope = getGraphScopeAndGenerateGraphTitle();
		AttributedGraph graph = createGraph();
		
		GsonBuilder builder = new GsonBuilder();
		Gson gson = builder.create();
		String jsonvertex = gson.toJson(graph.vertexSet());
		System.out.println("JSONCFG-VERTEX;" + jsonvertex);
		String jsonedge = gson.toJson(graph.edgeSet());
		System.out.println("JSONCFG-EDGE;"  + jsonedge);
		
		Dictionary<AttributedEdge, mPair> d = new Hashtable<>();
		
		for( AttributedVertex vsource : graph.vertexSet()) {
			for( AttributedVertex vtarget : graph.vertexSet()) {
				AttributedEdge e = graph.getEdge(vsource, vtarget);
				if (e == null) {
					continue;
				}

				d.put(e, new mPair(vsource, vtarget));
			}
		}
		
		System.out.println("JSONCFG;" + gson.toJson(d));
		
		if ((debug) && (!isRunningHeadless())) {

			PluginTool tool = state.getTool();
			tool = state.getTool();
			if (tool == null) {
				println("Script is not running in GUI");
				return;
			}
			
			
			GraphDisplayBroker graphDisplayBroker = tool.getService(GraphDisplayBroker.class);
			if (graphDisplayBroker == null) {
				Msg.showError(this, tool.getToolFrame(), "GraphAST Error",
					"No graph display providers found: Please add a graph display provider to your tool");
				return;
			}

			GraphDisplay graphDisplay =
				graphDisplayBroker.getDefaultGraphDisplay(false, monitor);
			String description = "Control Flow Graph";
			
			graphDisplay.setGraph(graph, description, false, monitor);
		}
	}
	
	
	protected AttributedGraph createGraph() throws CancelledException {
		int blockCount = 0;
		AttributedGraph graph = new AttributedGraph();

		CodeBlockIterator it = getBlockIterator();
		List<AttributedVertex> entryPoints = new ArrayList<>();

		while (it.hasNext()) {
			CodeBlock curBB = it.next();
			Address start = graphBlock(graph, curBB, entryPoints);

			if (start != null && (++blockCount % 50) == 0 && !isRunningHeadless()) {
				monitor.setMessage("Process Block: " + start.toString());
			}
		}

		// if option is set and there is more than one entry point vertex, create fake entry node
		// and connect to each entry point vertex
		//if (entryPoints.size() > 1) {
		//	addEntryEdges(graph, entryPoints);
		//}

		return graph;
	}
	
	private Address graphBlock(AttributedGraph graph, CodeBlock curBB,
			List<AttributedVertex> entries)
			throws CancelledException {

		Address[] startAddrs = curBB.getStartAddresses();

		if (startAddrs == null || startAddrs.length == 0) {
			Msg.error(this, "Block not graphed, missing start address: " + curBB.getMinAddress());
			return null;
		}

		AttributedVertex vertex = graphBasicBlock(graph, curBB);

		if (hasExternalEntryPoint(startAddrs)) {
			entries.add(vertex);
		}
		return startAddrs[0];
	}
	
	protected AttributedVertex graphBasicBlock(AttributedGraph graph, CodeBlock curBB)
			throws CancelledException {

		AttributedVertex fromVertex = getBasicBlockVertex(graph, curBB);

		// for each destination block
		//  create a vertex if it doesn't exit and add an edge to the destination vertex
		CodeBlockReferenceIterator refIter = curBB.getDestinations(monitor);
		while (refIter.hasNext()) {
			CodeBlockReference cbRef = refIter.next();

			CodeBlock db = cbRef.getDestinationBlock();

			// must be a reference to a data block
			if (db == null) {
				continue;
			}

			// don't include destination if it does not overlap selection
			// always include if selection is empty
			if (graphScope != null && !graphScope.isEmpty() && !graphScope.intersects(db)) {
				continue;
			}

			AttributedVertex toVertex = getBasicBlockVertex(graph, db);
			if (toVertex == null) {
				continue;
			}

			//	put the edge in the graph
			//String edgeAddr = cbRef.getReferent().toString();
			AttributedEdge newEdge = graph.addEdge(fromVertex, toVertex);

			// set it's attributes (really its name)
			setEdgeAttributes(newEdge, cbRef);
			//setEdgeColor(newEdge, fromVertex, toVertex);

		}
		return fromVertex;
	}
	
	private String getVertexId(CodeBlock bb) {
		// vertex has attributes of Name       = Label
		//                          Address    = address of blocks start
		//                          VertexType = flow type of vertex
		Address addr = bb.getFirstStartAddress();
		if (addr.isExternalAddress()) {
			Symbol s = bb.getModel().getProgram().getSymbolTable().getPrimarySymbol(addr);
			return s.getName(true);
		}
		return addr.toString();
	}
	
	protected AttributedVertex getBasicBlockVertex(AttributedGraph graph, CodeBlock bb)
			throws CancelledException {

		String vertexId = getVertexId(bb);
		AttributedVertex vertex = graph.getVertex(vertexId);

		if (vertex != null) {
			return vertex;
		}

		String vertexName = bb.getName();
		vertex = graph.addVertex(vertexId, vertexName);

		// add attributes for this vertex -
		setVertexAttributes(vertex, bb, vertexName.equals(vertexId) ? false : isEntryNode(bb));
		//setVertexColor(vertex, vertexType, firstStartAddress);

		return vertex;
	}
	
	/**
	 * Determine if the specified block is an entry node.
	 * @param block the basic block to test
	 * @return true  if the specified block is an entry node.
	 * @throws CancelledException if the operation is cancelled
	 */
	protected boolean isEntryNode(CodeBlock block) throws CancelledException {
		CodeBlockReferenceIterator iter = block.getSources(monitor);
		boolean isSource = true;
		while (iter.hasNext()) {
			isSource = false;
			if (iter.next().getFlowType().isCall()) {
				return true;
			}
		}
		return isSource;
	}
	
	protected void setEdgeAttributes(AttributedEdge edge, CodeBlockReference ref) {

		int edgeType;
		FlowType flowType = ref.getFlowType();
		if (flowType == RefType.FALL_THROUGH) {
			edgeType = FALLTHROUGH;
		}
		else if (flowType == RefType.UNCONDITIONAL_JUMP) {
			edgeType = UNCONDITIONAL_JUMP;
		}
		else if (flowType == RefType.CONDITIONAL_JUMP) {
			edgeType = CONDITIONAL_JUMP;
		}
		else if (flowType == RefType.UNCONDITIONAL_CALL) {
			edgeType = UNCONDITIONAL_CALL;
		}
		else if (flowType == RefType.CONDITIONAL_CALL) {
			edgeType = CONDITIONAL_CALL;
		}
		else if (flowType.isComputed()) {
			edgeType = COMPUTED;
		}
		else if (flowType.isIndirect()) {
			edgeType = INDIRECTION;
		}
		else if (flowType == RefType.TERMINATOR) {
			edgeType = TERMINATOR;
		}
		else { // only FlowType.CONDITIONAL_TERMINATOR remains unchecked
			edgeType = CONDITIONAL_RETURN;
		}
		// set attributes on this edge
		edge.setAttribute("Name", edgeNames[edgeType]);
		edge.setAttribute("EdgeType", edgeTypes[edgeType]);
	}
	
	protected void setVertexAttributes(AttributedVertex vertex, CodeBlock bb, boolean isEntry) {

		String vertexType = BODY_NODE;

		Address firstStartAddress = bb.getFirstStartAddress();
		if (firstStartAddress.isExternalAddress()) {
			vertexType = EXTERNAL_NODE;
		}
		else if (isEntry) {
			vertexType = ENTRY_NODE;
		}
		else {
			FlowType flowType = bb.getFlowType();
			if (flowType.isTerminal()) {
				vertexType = EXIT_NODE;
			}
			else if (flowType.isComputed()) {
				vertexType = SWITCH_NODE;
			}
			else if (flowType == RefType.INDIRECTION) {
				vertexType = DATA_NODE;
			}
			else if (flowType == RefType.INVALID) {
				vertexType = BAD_NODE;
			}
		}

		vertex.setAttribute("VertexType", vertexType);
	}

	private AddressSetView getGraphScopeAndGenerateGraphTitle() {
		/*
		if (selection != null && !selection.isEmpty()) {
			graphTitle += selection.getMinAddress().toString();
			return selection;
		}
		Function function = getContainingFunction(location);
		if (function != null) {
			graphTitle += function.getName();
			if (isCallGraph()) {
				return getScopeForCallGraph(function);
			}
			return function.getBody();
		}
		graphTitle += "(Entire Program)";
		*/
		return blockModel.getProgram().getMemory();
	}
	
	private CodeBlockIterator getBlockIterator() throws CancelledException {
		return blockModel.getCodeBlocksContaining(graphScope, monitor);
	}
	
	private boolean hasExternalEntryPoint(Address[] startAddrs) {
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		for (Address address : startAddrs) {
			if (symbolTable.isExternalEntryPoint(address)) {
				return true;
			}
		}
		return false;
	}
	
	class ASTGraphDisplayListener extends AddressBasedGraphDisplayListener {

		HighFunction highfunc;

		public ASTGraphDisplayListener(PluginTool tool, GraphDisplay display, HighFunction high,
				Program program) {
			super(tool, program, display);
			highfunc = high;
		}

		@Override
		protected Set<AttributedVertex> getVertices(AddressSetView selection) {
			return Collections.emptySet();
		}

		@Override
		protected AddressSet getAddresses(Set<AttributedVertex> vertices) {
			AddressSet set = new AddressSet();
			for (AttributedVertex vertex : vertices) {
				Address address = getAddress(vertex);
				if (address != null) {
					set.add(address);
				}
			}
			return set;
		}

		@Override
		protected Address getAddress(AttributedVertex vertex) {
			if (vertex == null) {
				return null;
			}
			String vertexId = vertex.getId();
			int firstcolon = vertexId.indexOf(':');
			if (firstcolon == -1) {
				return null;
			}

			int firstSpace = vertexId.indexOf(' ');
			String addrString = vertexId.substring(0, firstSpace);
			return getAddress(addrString);
		}

		@Override
		public GraphDisplayListener cloneWith(GraphDisplay graphDisplay) {
			return new ASTGraphDisplayListener(tool, graphDisplay, highfunc, currentProgram);
		}
	}
}
