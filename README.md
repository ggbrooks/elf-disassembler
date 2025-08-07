# ELF Disassembler

![Python](https://img.shields.io/badge/python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)
![Last Commit](https://img.shields.io/github/last-commit/ggbrooks/elf-disassembler)

---

## About The Project

This is a custom **ELF disassembler** built in **Python** using **pyelftools** and **Capstone**. It takes in an ELF binary, parses the `.text` section, and prints a human-readable disassembly of the machine code.

I started this project to deepen my understanding of reverse engineering and low-level binary analysis. It was also an opportunity to get hands-on experience with Capstone and pyelftools, two powerful libraries often used in reverse engineering workflows.

*While disassemblers already exist, I built this from scratch as a personal project to challenge myself and gain hands-on experience with the underlying concepts.*

---

## Built With
[![Python][python-badge]][python-url]  
[![Capstone][capstone-badge]][capstone-url]  
[![pyelftools][pyelftools-badge]][pyelftools-url]

## Development Environment
[![VS Code][vscode-badge]][vscode-url]  
[![macOS][macos-badge]][macos-url]  
[![VMware Fusion][vmware-badge]][vmware-url]  
[![Kali Linux][kali-badge]][kali-url]


## Getting Started

### Prerequisites
- Python 3.7+
- Virtualenv (recommended)

### Installation
1. Clone the repo
   ```bash
   git clone https://github.com/ggbrooks/elf-disassembler.git
   cd elf-disassembler
2. Create and activate a virtual environment (optional but recommended)  
   ```bash
   python3 -m venv disasm-env
   source disasm-env/bin/activate
   ```
3. Install dependencies  
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage
Run the disassembler script on an ELF binary:  
```bash
python disasm.py /path/to/your/elf_binary
```

Example output:  
```
Binary path is: /Users/giannabrooks/Documents/VMShared/test1
0x680: pop     rdi
0x681: and     al, 3
```

---

## Roadmap
- [x] Basic disassembly of `.text` section
- [ ] Add symbol resolution – Use pyelftools to read and display symbol names from `.symtab` or `.dynsym` if available
- [ ] Allow selective disassembly – Let users disassemble specific address ranges or functions
- [ ] Output to file – Support exporting disassembly to `.txt` or `.json` for analysis
- [ ] Disassemble additional sections – Handle `.plt`, `.init`, `.fini`, and `.got` entries
- [ ] Visualize control flow (optional) – Use networkx or Graphviz to generate a basic control flow graph (CFG)
- [ ] Add test ELF binaries and CI check – Keep a few sample binaries and test cases for future improvements
- [ ] Write a blog post or walkthrough – Share what you learned building this

Progress will be tracked in the [Update Log](#update-log) section.

---

## Contributing
Contributions are welcome!

---

## License
Distributed under the MIT License. See `LICENSE` for more information.

---

## Acknowledgments
- [Capstone Engine](https://www.capstone-engine.org/)
- [pyelftools by Eli Bendersky](https://github.com/eliben/pyelftools)
- Thanks to my reverse engineering course for inspiring the idea!

---

## Update Log
- **Aug 7, 2025** – Initial version: parses `.text` section and disassembles basic ELF input
- **Planned** – Add symbol resolution and section-specific disassembly

---
[python-badge]: https://img.shields.io/badge/Python-3.7%2B-3776AB?style=for-the-badge&logo=python&logoColor=white
[python-url]: https://www.python.org/

[capstone-badge]: https://img.shields.io/badge/Capstone-Disassembly-000000?style=for-the-badge
[capstone-url]: https://www.capstone-engine.org/

[pyelftools-badge]: https://img.shields.io/badge/pyelftools-ELF%20parsing-0A66C2?style=for-the-badge
[pyelftools-url]: https://github.com/eliben/pyelftools

[vscode-badge]: https://img.shields.io/badge/VS%20Code-007ACC?style=for-the-badge&logo=visualstudiocode&logoColor=white
[vscode-url]: https://code.visualstudio.com/

[macos-badge]: https://img.shields.io/badge/macOS-000000?style=for-the-badge&logo=apple&logoColor=white
[macos-url]: https://www.apple.com/macos/

[vmware-badge]: https://img.shields.io/badge/VMware%20Fusion-607078?style=for-the-badge&logo=vmware&logoColor=white
[vmware-url]: https://www.vmware.com/products/fusion.html

[kali-badge]: https://img.shields.io/badge/Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white
[kali-url]: https://www.kali.org/


