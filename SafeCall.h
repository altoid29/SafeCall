/*
	SafeCall is an x86 library made for the Windows OS that is used for ensuring
	that the ReturnAddress doesn't correspond with the actual location that
	a function was called (i.e: app.exe) but rather the gadget address area.

	MIT License

	Copyright (c) 2023 Landon. (altoid29)

	Github repository can be found at https://github.com/altoid29/SafeCall

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
*/

#pragma once

#if defined(_WIN32) || defined(_WIN64)

#ifdef _M_IX86
#include <iostream>
#include <vector>
#include <algorithm>
#include <minwindef.h>
#include <intrin.h>

typedef struct PEB_LOADER_DATA {
	UINT8 _PADDING_[12];
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LOADER_DATA, * PPEB_LOADER_DATA;

typedef struct PEB_NEW {
#ifdef _WIN64
	UINT8 _PADDING_[24];
#else
	UINT8 _PADDING_[12];
#endif
	PEB_LOADER_DATA* Ldr;
} PEB_NEW, * PPEB_NEW;

typedef struct _UNICODE_STRINGG {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRINGG;

typedef struct LOADER_TABLE_ENTRY {
	LIST_ENTRY				InLoadOrderLinks;
	LIST_ENTRY				InMemoryOrderLinks;
	LIST_ENTRY				InInitializationOrderLinks;
	uintptr_t				DllBase;
	uintptr_t				EntryPoint;
	uint32_t				SizeOfImage;
	UNICODE_STRINGG			FullDllName;
	UNICODE_STRINGG			BaseDllName;
	uint8_t					FlagGroup[4];
	uint32_t				Flags;
	uint16_t				ObsoleteLoadCount;
	uint16_t				TlsIndex;
	LIST_ENTRY				HashLinks;
	uint32_t				TimeDateStamp;
	uintptr_t				EntryPointActivationContext;
	uintptr_t				Lock;
	uintptr_t				DdagNode;
	LIST_ENTRY				NodeModuleLink;
	uintptr_t				LoadContext;
	uintptr_t				ParentDllBase;
} LOADER_TABLE_ENTRY, * PLOADER_TABLE_ENTRY;

namespace SafeCall {
	namespace Address {
		inline HMODULE GetModule(const std::string moduleName) {
			// Get PEB data.
#ifdef _WIN64
			PEB_NEW* peb = (PEB_NEW*)__readgsqword(0x60);
#else
			PEB_NEW* peb = (PEB_NEW*)__readfsdword(0x30);
#endif
			if (peb == nullptr)
				return nullptr;

			PLIST_ENTRY listEntry = peb->Ldr->InLoadOrderModuleList.Flink;
			PLOADER_TABLE_ENTRY tableEntry = nullptr;

			// Iterate each module.
			while (listEntry != &peb->Ldr->InLoadOrderModuleList && listEntry) {
				// Declare table.
				tableEntry = CONTAINING_RECORD(listEntry, LOADER_TABLE_ENTRY, InLoadOrderLinks);

				std::wstring wideNameString(tableEntry->BaseDllName.Buffer);
				std::string currentIteratedModuleName(wideNameString.begin(), wideNameString.end());

				// Convert string to lowercase, since all modules in memory are lowercase.
				std::transform(currentIteratedModuleName.begin(), currentIteratedModuleName.end(), currentIteratedModuleName.begin(), ::tolower);

				HMODULE base = (HMODULE)tableEntry->DllBase;

				if (!strcmp(moduleName.c_str(), currentIteratedModuleName.c_str()))
					return (HMODULE)tableEntry->DllBase;

				// Update flink.
				listEntry = listEntry->Flink;
			}

			return nullptr;
		}

		// Note - 1.26.2023 - May eventually be used.
		/*inline std::vector<std::string>GetAllModules(std::vector<std::string>list) {
			// Get PEB data.
#ifdef _WIN64
			PEB_NEW* peb = (PEB_NEW*)__readgsqword(0x60);
#else
			PEB_NEW* peb = (PEB_NEW*)__readfsdword(0x30);
#endif
			if (!peb)
				return list;

			PLOADER_TABLE_ENTRY tableEntry = nullptr;
			PLIST_ENTRY listEntry = peb->Ldr->InLoadOrderModuleList.Flink;

			// Iterate all modules.
			while (listEntry != &peb->Ldr->InLoadOrderModuleList && listEntry) {
				// Initialize tableEntry.
				tableEntry = CONTAINING_RECORD(listEntry, LOADER_TABLE_ENTRY, InLoadOrderLinks);

				// Get wstring dllNameBuffer.
				std::wstring buf(tableEntry->BaseDllName.Buffer);

				// Convert to std::string, from begin to end.
				std::string name(buf.begin(), buf.end());

				// Lowercase conversion.
				std::transform(name.begin(), name.end(), name.begin(), ::tolower);

				list.push_back(name);
			
				// Update listEntry.
				listEntry = listEntry->Flink;
			}

			return list;
		}*/

		inline uintptr_t GetExport(const std::string moduleName, const std::string exportName) {
			unsigned char* base = reinterpret_cast<unsigned char*>(GetModule(moduleName));
			if (!base)
				return NULL;

			// Get header data.
			const PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
			const PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)(base) + dosHeader->e_lfanew);

			// Get export table.
			const PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((uintptr_t)base + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

			// Iterate export table and print useful data.
			for (size_t i = 0; i < exportDirectory->NumberOfNames; i++) {
				const char* currentExportName = reinterpret_cast<const char*>(base + reinterpret_cast<ULONG*>(base + exportDirectory->AddressOfNames)[i]);

				if (!strcmp(exportName.c_str(), currentExportName)) {
					const USHORT ordinal = reinterpret_cast<USHORT*>(base + exportDirectory->AddressOfNameOrdinals)[i];
					return reinterpret_cast<uintptr_t>(base + reinterpret_cast<ULONG*>(base + exportDirectory->AddressOfFunctions)[ordinal]);
				}
			}

			// return Value.
			return NULL;
		}

		inline uintptr_t GetGadget(const std::string moduleName) {
			constexpr const char* signature = "FF 23"; // jmp dword ptr [ebx]
			std::vector<uint8_t*>addresses{};

			const HMODULE moduleAddress = GetModule(moduleName.c_str());

			// Failed to find base address.
			if (!moduleAddress)
				return NULL;

			static auto PatternToByte = [](const char* pattern) {
				auto bytes = std::vector<int>{};
				auto start = const_cast<char*>(pattern);
				auto end = const_cast<char*>(pattern) + std::strlen(pattern);

				for (auto current = start; current < end; current++) {
					if (*current == '?') {
						current++;

						if (*current == '?')
							current++;

						bytes.push_back(-1);
					}
					else
						bytes.push_back(std::strtoul(current, &current, 16));
				}

				return bytes;
			};

			auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(moduleAddress) + reinterpret_cast<PIMAGE_DOS_HEADER>(moduleAddress)->e_lfanew);
			auto imageSize = nt->OptionalHeader.SizeOfImage;
			auto patternBytes = PatternToByte(signature);
			auto scannedBytes = reinterpret_cast<std::uint8_t*>(moduleAddress);

			auto size = patternBytes.size();
			auto data = patternBytes.data();

			for (auto i = 0ul; i < imageSize - size; i++) {
				bool found = true;

				for (auto j = 0ul; j < size; j++) {
					if (scannedBytes[i + j] != data[j] && data[j] != -1) {
						found = false;
						break;
					}
				}

				// We found a valid address.
				if (found)
					addresses.push_back(&scannedBytes[i]);
			}

			// Iterate through all addresses to ensure we have a valid address. 
			if (addresses.size()) {
				for (auto c : addresses) {
					if (c != nullptr)
						return (uintptr_t)c;
				}
			}

			// Failed to find FF 23.
			return NULL;
		}
	}

	namespace Impl {
		struct Data {
			ULONG oldEbx{};
			ULONG addressToJumpToInGadget{};
			ULONG invokedReturnAddress{};
		};

		template <typename T, typename... Parameters>
		inline __declspec(naked) T __fastcall Fastcall(uintptr_t ecx, uintptr_t edx, uintptr_t functionAddress, Data& data, uintptr_t gadgetAddress, Parameters... parameters) {
			__asm {
				mov eax, [esp + 8];
				mov[eax], ebx;
				lea ebx, ReturnHereFromGadget; // Load effective address of Gadget into ebx.
				mov[eax + 4], ebx;
				pop dword ptr[eax + 8];

				lea ebx, [eax + 4];
				ret 4;

				ReturnHereFromGadget:
				push[ebx + 4];
				mov ebx, [ebx - 4];
				ret;
			}
		}

		template <typename T, typename... Parameters>
		inline __declspec(naked) T __cdecl Cdecl(uintptr_t functionAddress, Data& data, uintptr_t gadgetAddress, Parameters... parameters) {
			__asm {
				mov eax, [esp + 8];
				mov[eax], ebx;
				lea ebx, ReturnHereFromGadget; // Load effective address of Gadget into ebx.
				mov[eax + 4], ebx;
				pop dword ptr[eax + 8];

				lea ebx, [eax + 4];
				ret 4;

				ReturnHereFromGadget:
				sub esp, 12;
				push[ebx + 4];
				mov ebx, [ebx - 4];
				ret;
			}
		}
	}

	namespace Type {
		template <typename T, typename... Parameters>
		inline T Fastcall(std::uintptr_t ecx, std::uintptr_t edx, std::uintptr_t functionAddress, std::uintptr_t gadgetAddress, Parameters... parameters) {
			Impl::Data data;
			return Impl::Fastcall<T>(ecx, edx, functionAddress, data, gadgetAddress, parameters...);
		}

		template <typename T, typename... Parameters>
		inline T Thiscall(uintptr_t ecx, uintptr_t functionAddress, uintptr_t gadgetAddress, Parameters... parameters) {
			return Fastcall<T>(ecx, NULL, functionAddress, gadgetAddress, parameters...);
		}

		template <typename T, typename... Parameters>
		inline T Stdcall(uintptr_t functionAddress, uintptr_t gadgetAddress, Parameters... parameters) {
			return Thiscall<T>(NULL, functionAddress, gadgetAddress, parameters...);
		}

		template <typename T, typename... Parameters>
		inline T Cdecl(uintptr_t functionAddress, uintptr_t gadgetAddress, Parameters... parameters) {
			Impl::Data data{};
			return Impl::Cdecl<T>(functionAddress, data, gadgetAddress, parameters...);
		}
	}
}

// type = Function value type.
// moduleName = Module name to get the export in.
// exportName = Export name to get in the module.
// moduleNameToGetGadgetFrom = The module (.dll or .exe) to have the return address appear in.
#define SAFECALL_STDCALL(type, moduleName, exportName, moduleNameToGetGadgetFrom, ...) \
SafeCall::Type::Stdcall<type>(SafeCall::Address::GetExport(moduleName, exportName), SafeCall::Address::GetGadget(moduleNameToGetGadgetFrom), __VA_ARGS__);

// type = Function value type.
// moduleName = Module name to get the export in.
// exportName = Export name to get in the module.
// moduleNameToGetGadgetFrom = The module (.dll or .exe) to have the return address appear in.
#define SAFECALL_THISCALL(type, moduleName, exportName, moduleNameToGetGadgetFrom, ...) \
SafeCall::Type::Thiscall<type>(NULL, SafeCall::Address::GetExport(moduleName, exportName), SafeCall::Address::GetGadget(moduleNameToGetGadgetFrom), __VA_ARGS__);

// type = Function value type.
// moduleName = Module name to get the export in.
// exportName = Export name to get in the module.
// moduleNameToGetGadgetFrom = The module (.dll or .exe) to have the return address appear in.
#define SAFECALL_FASTCALL(type, moduleName, exportName, moduleNameToGetGadgetFrom, ...) \
SafeCall::Type::Fastcall<type>(NULL, NULL, SafeCall::Address::GetExport(moduleName, exportName), SafeCall::Address::GetGadget(moduleNameToGetGadgetFrom), __VA_ARGS__);

// type = Function value type.
// moduleName = Module name to get the export in.
// exportName = Export name to get in the module.
// moduleNameToGetGadgetFrom = The module (.dll or .exe) to have the return address appear in.
#define SAFECALL_CDECL(type, moduleName, exportName, moduleNameToGetGadgetFrom, ...) \
SafeCall::Type::Cdecl<type>(SafeCall::Address::GetExport(moduleName, exportName), SafeCall::Address::GetGadget(moduleNameToGetGadgetFrom), __VA_ARGS__);
#endif

#endif
