## How the Disassembler Works

This project disassembles ELF binaries using [pyelftools](https://github.com/eliben/pyelftools) for parsing
and [Capstone](http://www.capstone-engine.org/) for disassembly.  
Below is a breakdown of each part of the script:

### 1. Imports
- **What it does:** Loads required libraries (`argparse`, `pyelftools`, `capstone`).
- **Why it’s needed:** These provide CLI parsing, ELF parsing, and disassembly.

### 2. Symbol Resolution
- **What it does:** Reads `.symtab` and `.dynsym` sections to map addresses → symbol names.
- **Why it’s needed:** Helps annotate disassembly with function names (e.g., `<main>`).
- **Tools:** pyelftools

### 3. Command-Line Parsing
- **What it does:** Uses `argparse` to accept the ELF binary path.
- **Why it’s needed:** Lets you run `python disasm.py ./a.out` on any binary.
- **Tools:** argparse

### 4. Opening the ELF
- **What it does:** Opens the binary with `ELFFile`.
- **Why it’s needed:** Allows access to sections, headers, and symbols.
- **Tools:** pyelftools

### 5. Extracting the `.text` Section
- **What it does:** Pulls machine code bytes and the load address.
- **Why it’s needed:** This is what Capstone decodes.
- **Tools:** pyelftools

### 6. Capstone Disassembly
- **What it does:** Disassembles bytes into instructions with addresses.
- **Why it’s needed:** Core functionality of the disassembler.
- **Tools:** capstone

### 7. Symbol Integration
- **What it does:** Annotates disassembly with function names if available.
- **Why it’s needed:** Makes output more readable and debugger-like.
- **Tools:** pyelftools + capstone

