## Tooling:
- [Angr](https://angr.io/)
- [CyberChef](https://github.com/gchq/CyberChef)
- [GDB](https://www.sourceware.org/gdb/)
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [IDA](https://hex-rays.com/ida-pro/)
- [Wireshark](https://www.wireshark.org/)
- [x64dbg](https://github.com/x64dbg/x64dbg)
___
## Helpful GDB Commands:
- `x` to display memory
- `dump` dump memory to a file
- `x/i` or `disasm` to disassemble instructions
- `info registers` to display register values
- `print` to display values
- `info proc mappings` get an overview of the process address space
- `help` to receive help
- `starti` to break at first executed instruction
- `b *0x<address>` to set a breakpoint at an address when there are no symbols
- `si` and `ni` to step into and step over an instruction (and calls)
- `bt` bracktrace of call stack
- `f <frame_number>` to jump to a different stack frame
