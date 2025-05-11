from utils import check_file
import networkx as nx
import pyghidra, os, sys
import logging
from networkx.drawing.nx_pydot import write_dot 

pyghidra.start()

from ghidra.app.nav.NavigationUtils import getExternalLinkageAddresses
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.util.bin import MemoryByteProvider
from ghidra.program.model.block import SimpleBlockModel
from ghidra.app.util.bin.format.pe import PortableExecutable
from ghidra.app.nav.NavigationUtils import getExternalLinkageAddresses

fname = os.path.basename(os.environ['PATH_TO_PROGRAM_TO_ANALYSE']).split('.')[0] # Get File name

logger = logging.getLogger(__name__) # TO DO: this should be improved in the future to keep the function name
logging.basicConfig(filename=f"{fname}.log", encoding='utf-8', level=logging.DEBUG)
logging.getLogger().addHandler(logging.StreamHandler(sys.stdout)) #Log to STDOUT too

#Extract the entry address from the Portable Executable using Ghidra API
#Inspiration for this function:
#https://gitlab.com/saruman9/ghidra_scripts/-/blob/master/GetEntryPoints.java
def getEntryPointAddress(ghidra_program_object):
	logger.info("Getting Entry Address")
	byteProvider = MemoryByteProvider(ghidra_program_object.getMemory(),ghidra_program_object.getImageBase())
	pe = PortableExecutable(byteProvider, PortableExecutable.SectionLayout.MEMORY)
	optHeader = pe.getNTHeader().getOptionalHeader()
	entry_address = hex(optHeader.getAddressOfEntryPoint() + ghidra_program_object.getImageBase().getOffset()).replace('0x','')
	entry_address = '"'+entry_address.rjust(8,'0')+'"' #Pad from right with 0s
	logger.info("Entry at {}".format(entry_address))
	return entry_address

def f(path_to_pe_file):
	icfg = nx.DiGraph()
	check_file(path_to_pe_file)

	# TO DO - Iulian: Ideally, I would like to gave up on generator approach, but it doesn't seem posible A.T.M
	with pyghidra.open_program(path_to_pe_file,project_name=f"{fname}_ghidra",
					project_location=os.environ['OUTPUT_DIRECTORY'] + f"output_{fname}") as flat_api: #Analyze the binary file
		print(f"type={type(flat_api)}")
		program = flat_api.getCurrentProgram()

		if not program.getExecutableFormat() == 'Portable Executable (PE)' : return -1,-1
		programListing = program.getListing() #Get the Listing
		monitor = ConsoleTaskMonitor() #Spawn monitor

		# Use Simple Block to include CALL instructions as Flow instructions in the CFG
		bm = SimpleBlockModel(program)
		codeBlockIterator = bm.getCodeBlocks(monitor)

		#Build a symbol dictionary. We use this to translate external
		#CALL functions from their address to their function name.
		symbols = program.symbolTable.getExternalSymbols()
		external_pointers = dict()

		# Iterate through symbols, build the dictionary.
		# Key: External Linkage Address : Symbol
		for s in symbols:
			external_pointers[str(getExternalLinkageAddresses(program, s.getAddress())[0])] = str(s)

		#Parse all the blocks in the program
		while codeBlockIterator.hasNext(): 
			block = codeBlockIterator.next() 
			addr = str(block.getFirstStartAddress()) #Get start address
			code = "" #We save Code Instructions here

			#Extract the block's code
			codeUnit = programListing.getCodeUnits(block,True) #Get the code from the block

			# Parse each instruction in the block
			while codeUnit.hasNext(): 
				inst = codeUnit.next()

				# Process external CALL instructions
				if inst.getMnemonicString() == 'CALL':
					call_addr = str(inst.getOpObjects(0)[0]) # Get address argument
					if call_addr in external_pointers.keys(): # If the address is external
						inst = "CALL " + external_pointers[call_addr] # Substitute with the func. name
				code += str(inst)
				if codeUnit.hasNext(): code+='\n'

			icfg.add_node('"'+addr+'"',Code=code) # Add node to the ICFG (Note: We add quotes for .dot files)

			#We get the edges for this node by getting the block's destinations
			dest = bm.getDestinations(block,monitor) 

			# We generate the block's edges by its destinations/successors
			while dest.hasNext():
				d = dest.next()
				daddr = str(d.getDestinationAddress()) # Get address for destination
				flow = str(d.getFlowType()) # Get Flow Type

				icfg.add_edge('"'+addr+'"','"'+daddr+'"' ,EdgeType=flow) #Add it to the ICFG

		#Note:Ghidra includes blocks for external functions in their Graphs. 
		#Networkx generated nodes for missing nodes/blocks. 
		#The iterator doesn't usually parse these kind of nodes.
		#They have no attributes set if they are generated. 
		#Here, after building the ICFG, we process the empty generated blocks. 
		#External function blocks would have '?? ??' as the Code attribute.

		#We parse the nodes
		relabel_mapping = {} #Mapping for relabling external nodes
		for n in icfg.nodes:
			if not ('Code' in icfg.nodes[n]): #See which have no Code attribute
				icfg.add_node(n,Code="?? ??") # Update the node with a code attribute
				if 'EXTERNAL' in n: # If it's an external address
					symb = program.symbolTable.getExternalSymbols() 
					# Find which symbol it is, add it to relabel_mapping.
					for s in symb:
						symaddr = str(s.getAddress())
						if n.strip('"') == symaddr : 
							relabel_mapping[n] = '"'+str(s)+'"'
							break

		icfg = nx.relabel_nodes(icfg, relabel_mapping) #Relabel external function nodes

		#Get the Entry Point of the Portable Executable
		entry_address = getEntryPointAddress(program)


		logger.info("ICFG Built..")
		write_dot(icfg, f"{fname}.dot") #Dump the ICFG into a Graphviz DOT File
		return icfg,entry_address

f(os.environ['PATH_TO_PROGRAM_TO_ANALYSE'])