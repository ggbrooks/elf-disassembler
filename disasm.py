#libraries
import argparse
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

#create an ArgumentParser object to handle reading input from command line
parser = argparse.ArgumentParser(
    description="Disassemble a given ELF binary using pyelftools + Capstone"
)
#tells the parser to expect one positional arguement, called binary
#binary is the name of the variable the user will supply, help= helpful message 
#if someone runs python disasm.py --help
parser.add_argument("binary", help="Path to ELF binary")
#parses the user input and stores it in an args object
args = parser.parse_args()

print("Binary path is:", args.binary)

##########LOAD AND PARSE THE ELF FILE#######
#opens file path that was passed from command line
# rb means read binary mode (necessary b/c ELF files are not plain text)
#f is a file object, which ELFFile needs to work
with open(args.binary, 'rb') as f:
    #creates an ELFFile object from the file, allowing me to inspect sections like .txt, .data, headers, etc.
    elf = ELFFile(f)
    
    # .text section contains the excutable instructions, this line searches through ELF's sections and returns the one named .text
    text_section = elf.get_section_by_name('.text')
    #error handling
    if not text_section:
        print("No .text section found in this binary")
    
    # extracts the raw bytes of the .text section (machine code to disassemble)
    code = text_section.data()
    #gets starting address of .text section in memory (Capstone needs this to show correct disassembly offsets)
    addr = text_section['sh_addr']

######DISASSEMBLE THE CODE WITH CAPSTONE#####
#create Capstone disassembler object & using Cs cpastone class (telling the arch and mode we are disassembling)
disemb = Cs (CS_ARCH_X86, CS_MODE_64)

#telling it to disassemble the machiner code starting at the address and loop through
for instr in disemb.disasm(code, addr):
    # printing address = memory address of instruction, mnemonic = assembly instruction, op_str = the operands
    print(f"0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
