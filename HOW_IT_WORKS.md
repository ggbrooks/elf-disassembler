## How the Disassembler Works

This project disassembles ELF binaries using [pyelftools](https://github.com/eliben/pyelftools) for parsing
and [Capstone](http://www.capstone-engine.org/) for disassembly.  
Below is a breakdown of each part of the script:

### 1. Imports
```python
import argparse
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
```
- **What it does:** Loads required libraries (`argparse`, `pyelftools`, `capstone`).
- **Why I added it/need it:**
  * `argparse`: accepts a file path from the command line
  * `ELFFile`(pyelftools): opens and inspects ELF structure such as headers, .text, and symbols.
  * `capstone`: turns raw machine code bytes into readable assembly.
- **Tools/libraries:**
  * Python stdlib: `argparse`
  * Third-party: `pyelftools`, `capstone`

### 2. Symbol Resolution
```python
def load_symbols(elf):
    symbols = {}
    for section_name in ['.symtab', '.dynsym']:
        section = elf.get_section_by_name(section_name)
        if section:
            for sym in section.iter_symbols():
                if sym['st_value'] != 0:
                    symbols[sym['st_value']] = sym.name
    return symbols
```
- **What it does:**
  * Builds a dictionary that maps memory addresses to symbol names
- **Why it’s needed:** When disassembling, showing function names alongside addresses makes the output much more readable
- **How it works:**
  1. The function takes in the ELF File.
  2. I created an empty dictionary called symbols
  3. Check two ELF sections: full symbols table and the dynamic table
  4. if the file has either of those tables, it loops through every symbol inside
  5. it will ignore the symbol if it has an address of 0 because it does not point anywhere
  6. it then adds an entry and puts the name and address together
  7. then it returns the dictionary for use in the disassembly loop
- **Tools:**
  * `pyelftools` - used for accessing full and dynamic symbol tables

### 3. Command-Line Parsing
```python
parser = argparse.ArgumentParser(
    description="Disassemble a given ELF binary using pyelftools + Capstone"
)
parser.add_argument("binary", help="Path to ELF binary")
args = parser.parse_args()
print("Binary path is:", args.binary)
```
- **What it does:** Uses `argparse` to accept the ELF file path as input.
- **Why it’s needed:** Makes the tool flexible, allowing to analyze any ELF binary without changing the code.
- **How it works:**
  1. Create a parser
  2. Add a required argument `"binary"`, which is the file path
  3. Call `parse_args()` to read what the user typed
  4. access the path through `args.binary`
- **Tools:** `argparse`

### 4. Opening the ELF
- **What it does:** 
- **Why it’s needed:**
- **How it works:**
- **Tools:** 

### 5. Extracting the `.text` Section
- **What it does:** 
- **Why it’s needed:**
- **How it works:**
- **Tools:** 

### 6. Capstone Disassembly
- **What it does:** 
- **Why it’s needed:**
- **How it works:**
- **Tools:** 

### 7. Symbol Integration
- **What it does:** 
- **Why it’s needed:**
- **How it works:**
- **Tools:** 

