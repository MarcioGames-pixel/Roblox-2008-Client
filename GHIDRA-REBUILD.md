# Roblox 2008 client: Ghidra reconstruction

This repository includes a manual GitHub Actions workflow that runs the official Ghidra headless analyzer against PE binaries stored in the repository.

## Run it

1. Merge the branch containing this workflow into the default branch so GitHub can expose the `workflow_dispatch` action.
2. Open **Actions → Ghidra decompile Roblox 2008 client → Run workflow**.
3. Leave `binary_path` empty to scan the repository for EXE, DLL, OCX and SYS files, or enter one repository-relative path such as `client/Roblox.exe`.
4. Download the artifact named `roblox-2008-ghidra-decompiled`.

The artifact contains a C-like decompiler listing for each analyzed module and a CSV index of functions, addresses, signatures and decompilation status.

## Important: decompiler output is not original source

Ghidra reconstructs C-like pseudocode from machine code. It does not recover the original C++ project, original class declarations, templates, comments, variable names, build system or exact source files. Some output will need manual correction and may not compile as-is.

The intended approach is incremental reconstruction:

- use the CSV and function addresses to track recovered functions;
- group functions by subsystem using strings, imports, cross-references and call relationships;
- rebuild data structures, class layouts and interfaces as they become clear;
- implement recovered behavior in clean C/C++ modules;
- compile and test each subsystem independently before integrating it.

Do not treat a 100% function export count as 100% source recovery. The workflow is an extraction/analysis starting point, not an automatic native-to-WASM converter.

## Binary handling

The workflow analyzes binaries already committed to this repository. Keep large binaries and any files you are not allowed to redistribute out of the repository; use the repository's existing permitted client files or a permitted local copy. The workflow does not download proprietary client files from third-party mirrors.
