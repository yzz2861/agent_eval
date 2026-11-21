![Supported Python versions](https://img.shields.io/badge/python-3.7+-blue.svg) [![Twitter](https://img.shields.io/twitter/follow/skelsec?label=skelsec&style=social)](https://twitter.com/intent/follow?screen_name=skelsec)

## :triangular_flag_on_post: Sponsors

If you like this project, consider sponsoring it on GitHub! [Sponsors](https://github.com/sponsors/skelsec/)

# minidump
Python library to parse and read Microsoft minidump file format. Can create minidumps on Windows machines using the windows API (implemented with ctypes).

# Requirements
Python >= 3.6

# Basic Usage
This module is primarily intended to be used as a library, however for the sake of demonstarting its capabilities there is a command line tool implemented called `minidump`. This tool has the following modes of operation.

#### Console
One-shot parsing and information retrieval.  
  
```minidump.py --all <mindidump file>  ```  
See help for possible options.
#### Shell
There is and interactive command shell to get all info (modules, threads, excetpions etc) and browse the virtual memory of the process dumped (read/read int/read uint/move/peek/tell)  
  
```minidump.py -i <mindidump file>  ```  
Once in the shell, all commands are documented. Use the `?` command to see all options.

# Advanced usage
After parsing the minidump file, you can use the MinidumpFileReader and MinidumpBufferedReader objects to perform various searches/reads in the dumped process' address space.  
Those objects will be able to read and search the VA of the dumped process and have a notion on integer sizes based on the CPU arch.

# Creating minidump file
The ```createminidump.py``` script in the utils folder uses the Windows API to create minidump files. This script can also dump processes running on a different user context by enabling ```SeDebugPrivilege```.  
Of course it only works if you are running it as administrator or a use that has ```SeDebugPrivilege```.

# Restricted read-only hand-off view
For external review, `minidump.restricted.RestrictedMinidumpView` exposes only an approved list of virtual address ranges while the original minidump stays with the evidence holder.

- The view is built from a sync `MinidumpFileReader` (`from_reader`) or an async `AMinidumpFileReader` (`from_async_reader`); only bytes inside the approved ranges that are present in the dump are copied, and the file handle is never retained.
- `read()` / `aread()` return a `RestrictedReadResult` whose `data` always has the requested length. Undisclosed positions (cross-range gaps or approved-but-undumped addresses) are filled and reported through `available`, `mask` and `missing_ranges`.
- Reads whose start address is outside every approved range raise `RestrictedRangeError`; the error text references the approved ranges only.
- Several virtual mappings that point at the same underlying evidence keep the original disclosure restriction: access is decided by the approved virtual address, never by the backing bytes.
- `to_bytes()` / `from_bytes()` hand the materialized view to another party without the original minidump. Sync and async reads produce byte-identical results.

# Installing
```python3 setup.py install```
