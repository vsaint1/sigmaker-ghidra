# SigMaker for Ghidra

A Ghidra script that replicates the functionality of the SigMaker plugin for IDA Pro
(based on [A200K/IDA-Pro-SigMaker](https://github.com/A200K/IDA-Pro-SigMaker)).
Generates byte signatures from code addresses and searches for signatures in any supported format.

---

## What it does

- Creates unique byte signatures at any code address or function entry point
- Finds the shortest XREF signature by signing call sites that reference a target address
- Copies selected instruction bytes as a raw signature with no wildcards
- Searches the loaded binary for any pasted signature, auto-detecting the format
- Outputs all four signature formats simultaneously to the console
- Copies the selected format directly to the clipboard

---

## Requirements

- Ghidra 10.x or later
- A binary that has been loaded and analyzed (auto-analysis run)
- The cursor must be placed in the Listing view or Decompiler view before running

---

## Installation

Copy `SigMaker.java` to your Ghidra scripts directory:

    Windows : C:\Users\<user>\ghidra_scripts\
    Linux   : ~/ghidra_scripts/
    macOS   : ~/ghidra_scripts/

---

## Usage

1. Open your binary in Ghidra and run auto-analysis
2. Place your cursor on the instruction or function you want to sign
3. Open the Script Manager: Window > Script Manager
4. Find SigMaker in the list (category: Signature) and click Run,
   or use the assigned hotkey: **CTRL + ALT + S**

The main dialog opens. Select an action, choose your output format, configure
options if needed, and click OK.

---

## Main dialog

### Select action

Option | Description
------ | -----------
Create unique Signature for current code address | Walks forward from the cursor byte by byte, wildcarding variable operands, until the pattern matches exactly once in the entire binary
Find shortest XREF Signature for current data or code address | Finds all code references to the current address and signs each call site, returning the shortest unique result
Copy selected code | Copies the raw bytes of the instruction at the cursor as a concrete IDA-style hex string with no wildcards
Search for a signature | Opens a search dialog where you can paste any signature and find all matches in the binary

### Output format

Format | Example
------ | -------
IDA Signature | `E8 ? ? ? ? 45 33 F6 66 44 89 34 33`
x64Dbg Signature | `E8 ?? ?? ?? ?? 45 33 F6 66 44 89 34 33`
C Byte Array Signature + String mask | `\xE8\x00\x00\x00\x00\x45\x33\xF6  x????xxx`
C Raw Bytes Signature + Bitmask | `0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xF6  0b11100001`

The selected format is copied to the clipboard. All four formats are always printed
to the Ghidra console regardless of which format is selected.

### Options

Option | Description
------ | -----------
Wildcards for operands | When enabled, variable operand bytes are replaced with wildcards. Disable to produce fully concrete signatures.
Continue when leaving function scope | When disabled (default), generation stops at the end of the containing function. Enable to cross function boundaries.

---

## Operand types dialog

Click **Operand types...** to control which categories of operands are wildcarded.
This button is only active when **Wildcards for operands** is checked.

Operand type | What it wildcards
------------ | -----------------
Jumps / branches | Short and near conditional and unconditional jumps (EB, 7x, 0F 8x, E9)
Calls | Direct call targets (E8) and indirect calls (FF /2)
Immediate values | Multi-byte immediates such as `mov eax, 0x12345678`
Displacements | Memory access offsets such as `mov [rax+18h], rcx`, including single-byte struct field offsets
Direct offsets / addresses | Absolute address operands and direct memory references
Memory references | RIP-relative and absolute references to non-executable data sections

---

## Search dialog

Paste a signature in any of the four supported formats. The format is detected
automatically — you do not need to specify it.

- Results list each match with its address, offset from the image base, and a byte preview
- Double-click any result row to navigate to that address in the Listing view
- All matches are also printed to the Ghidra console

---

## Console output

Every generated signature is printed to the Ghidra console in all four formats:

```
=== Signature @ 00c67940 ===
IDA Signature         : 48 8B C4 4C 89 40 ? 48 89 48 ? 55 53 41 54
x64Dbg Signature      : 48 8B C4 4C 89 40 ?? 48 89 48 ?? 55 53 41 54
C Byte Array + mask   : \x48\x8B\xC4\x4C\x89\x40\x00\x48\x89\x48\x00\x55\x53\x41\x54  xxxxxx?xxxx?xxx
C Raw Bytes + bitmask : 0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x40, 0x00, ...  0b111111011110111
Length : 15 bytes
>> Copied to clipboard (IDA).
```

---

## Wildcarding rules

Bytes are wildcarded when they encode values that change between binary builds:

- **Call and jump targets** — the displacement bytes in `E8`, `E9`, `EB`, `7x`, and
  `0F 8x` instructions are always wildcarded because they encode absolute addresses
  that shift with every recompile
- **Relocation entries** — any byte covered by a PE relocation record is wildcarded
  unconditionally, regardless of operand type settings
- **Struct field offsets** — small displacements like `[rax+18h]` are wildcarded when
  Displacements is enabled, because struct layouts can change when fields are added or removed
- **Large immediates** — values wider than one byte that appear in instructions like
  `mov eax, 0x12345678` are wildcarded when Immediate values is enabled
- **Opcode bytes are never wildcarded** — the first byte of every instruction is always
  kept concrete regardless of settings

---

## Limitations

- The binary must be analyzed before running. Signatures are generated from the
  disassembled listing, not raw bytes.
- Uniqueness is verified against the entire loaded memory image. Signatures that are
  unique in one module may not be unique if multiple modules are loaded simultaneously.
- Very short or highly repetitive functions such as stubs and thunks may not yield a
  unique signature within the default 1000-byte scan limit.
- The script does not use AVX2-optimized searching. For large binaries the search
  phase may take a few seconds per query.

---

## How it works

**Signature generation** walks forward from the start address one instruction at a
time. For each instruction it computes a wildcard mask: relocation-covered bytes are
masked first, then the instruction is classified by mnemonic to identify displacement
and immediate operands, which are masked according to the active operand type settings.
Call and jump displacement bytes are always masked via direct opcode inspection
independent of the operand settings. After each instruction is appended,
`Memory.findBytes` is called with the current pattern. The loop stops as soon as
exactly one match exists in the binary.

**XREF mode** calls `ReferenceManager.getReferencesTo` for the target address,
runs the generation algorithm from each call site, collects all unique results,
sorts by length, and prints the shortest five to the console.

**Search** normalises the pasted string to IDA flat format regardless of which of
the four input formats was used, then calls `Memory.findBytes` in a loop advancing
one byte past each match until the end of the address space.
