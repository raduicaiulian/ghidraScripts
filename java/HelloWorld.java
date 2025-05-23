// Import necessary Ghidra classes
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.List;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlockReferenceIterator;

import ghidra.program.model.address.Address;


public class HelloWorld extends GhidraScript {

    private int getInternalFunctionCount(FunctionManager fm){
        int funcs_count = 0;

        FunctionIterator funcs = fm.getFunctions(true);
        for (Function func : funcs)
            funcs_count += 1;

        return funcs_count;
    }

    private int getExternalFunctionCount(FunctionManager fm){
        return fm.getFunctionCount() - getInternalFunctionCount(fm);
    }

    private List<String> getExternalFunctions(FunctionManager fm){
        // TO DO: check if external functions can be decompiled
        List<String> list = new ArrayList<>();

        FunctionIterator funcs = fm.getExternalFunctions();
        for (Function func : funcs){
            System.out.println("func.getClass(): " + func.getClass());
            list.add(func.getName(true));
        }
        return list;
    }

    private List<Function> getInternalFunctions(FunctionManager fm){
        List<Function> list = new ArrayList<>();

        FunctionIterator funcs = fm.getFunctions(true);
        for (Function func : funcs)
            list.add(func);
        return list;
    }
    // private List<String> getInternalFunctions(FunctionManager fm){
    //     List<String> list = new ArrayList<>();

    //     FunctionIterator funcs = fm.getFunctions(true);
    //     for (Function func : funcs)
    //         list.add(func.getName(true));
    //     return list;
    // }

    String decompile(Function func, Program cp){
        // source: https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html
        // Instantiate the interface
        DecompInterface ifc = new DecompInterface();
        FunctionManager fm = cp.getFunctionManager();

        // Setup any options or other initializationâ
        DecompileOptions xmlOptions = new DecompileOptions();
        ifc.setOptions(xmlOptions); // Inform interface of global options

        // Setup up the actual decompiler process for a
        // particular program, using all the above initialization
        ifc.openProgram(cp);

        TaskMonitor taskmonitor = TaskMonitor.DUMMY;
        // Make calls to the decompiler:
        DecompileResults res = ifc.decompileFunction(func,0,taskmonitor);

        // Check for error conditions
        if (!res.decompileCompleted()) {
            System.out.println(res.getErrorMessage());
            return res.getErrorMessage().toString();
        } else {
            System.out.println("Decompilation succeeded!");
            ClangTokenGroup tokgroup = res.getCCodeMarkup();
            return tokgroup.toString();

        }
    }

    String disasemble(Function func, Program cp){
        String assembly = "";
        Address addr = func.getEntryPoint();
        Listing listing = cp.getListing();
        InstructionIterator instructions = listing.getInstructions(addr, true);
        for (Instruction instruction : instructions){
            assembly += instruction.toString() + "\n";
            // import ghidra.program.model.pcode.PcodeOp;
            // for (PcodeOp pcode : instruction.getPcode()){
            //     System.out.println("pcode:" + pcode.getMnemonic());
            // }
        }
        return assembly;
    }

    //----------------------WIP------------------------
    // String create_cfg_function(Program cp, Function func, ConsoleTaskMonitor monitor) throws Exception {
    //     BasicBlockModel block_model_iterator = new BasicBlockModel(cp);
    //     AddressSetView function_addresses = func.getBody();
    //     System.out.println(func.getName());
    //     CodeBlockIterator code_blocks_iterator = block_model_iterator.getCodeBlocks(monitor);
    //     System.out.println("---------------");
    //     for(CodeBlock block: code_blocks_iterator){
    //         // System.out.println("block:" + block.toString());
    //         System.out.println("--------------^^^^^^^^^^^^^^^---------------------");
    //         System.out.println("block.getName: " + block.getName());
    //         // print("block type: ", type(block))
    //         System.out.println("block.getFlowType: " + block.getFlowType());
    //         System.out.println("block.getNumDestinations: " + block.getNumDestinations(monitor));
    //         System.out.println("--------------^^^^^^^^^^^^^^^---------------------");
    //         CodeBlockReferenceIterator dstBlocks = block.getDestinations(monitor);
    //         CodeBlockReferenceIterator srcBlocks = block.getSources(monitor);

    //         while(srcBlocks.hasNext()){
    //             CodeBlockReference source = srcBlocks.next();
    //             // vsrc = Vertex(source)
    //             // cfg.addVertex(vsrc)
    //             // edge1 = Edge(vsrc, v)
    //             // res = cfg.addEdge(edge1, vsrc, v )
    //             src_addr = hex(source.getSourceAddress().getOffset())
    //             #print(src_addr)
    //         }

    //     }
    //     System.out.println("---------------");
    //     return "aaaa";
    // }

    @Override
    protected void run() throws Exception {
        Program cp = currentProgram;
        FunctionManager fm = cp.getFunctionManager();

        System.out.println("number of internal functions= " + getInternalFunctionCount(fm));
        System.out.println("number of external functions= " + getExternalFunctionCount(fm));

        // List<String> list = getInternalFunctions(fm);
        // List<String> external_list = getExternalFunctions(fm);

        // System.out.println("InternalFunctionsList= " + list);
        // System.out.println("ExternalFunctionsList= " + external_list);

        for (Function func : getInternalFunctions(fm)){
            // disasemble
            System.out.println(disasemble(func, cp));
            System.out.println("--------------");
            // decompile
            System.out.println(decompile(func, cp));
            System.out.println("**************");
        }
        // ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();

        // String aa;
        // FunctionIterator funcs = fm.getFunctions(true);
        // for (Function func : funcs){
        //     if (func.getName().equals("FUN_00401000")){
        //         aa = create_cfg_function(cp, func, monitor);
        //     }
        //     else
        //     {
        //         System.out.println("function attempt failed:" + func.getName());
        //     }
        // }
    }
}

