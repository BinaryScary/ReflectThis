# ReflectThis
- Supports Native and .NET PE files
- Load Native or .NET PE file hosted on web server
- IAT Hook to common commandline functions to fix arguments
- Set proper permissions on loaded sections
- ETW and AMSI patching
- TLS Callback support

## Usage
```ps
> .\ReflectThis.exe [url] [args...]
resolving function GetCommandLineA -> 5c18c0
resolving function GetCurrentProcess -> 77be3550
resolving function GetProcAddress -> 77bdfb80
resolving function FreeLibrary -> 77be11b0
resolving function VirtualQuery -> 77bdfba0
resolving function GetProcessHeap -> 77bdf9b0
resolving function HeapFree -> 77bde590
resolving function HeapAlloc -> 77de5e70
resolving function GetLastError -> 77bde640
resolving function GetModuleHandleW -> 77be1520
resolving function IsProcessorFeaturePresent -> 77be1240
resolving function GetStartupInfoW -> 77be1c20
resolving function SetUnhandledExceptionFilter -> 77be1df0
resolving function UnhandledExceptionFilter -> 77bf62e0
...SNIP...
```
