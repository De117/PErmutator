#pragma once
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <string.h>
#include <fstream>
#include <stdlib.h>
#include <stdexcept>
#include "Types.h"

// Opens a file and returns a handle to it
void OpenFile(const char* fileName, std::fstream& hFile);

// Load the chosen section from PE file to memory
BYTE* LoadSection(std::fstream& hFile, PIMAGE_SECTION_HEADER pSectionHeader);

// Writes the given section back to file on disk
BOOL WriteSection(std::ofstream& hFile, PIMAGE_SECTION_HEADER pSectionHeader, unsigned char *buffer);

// Read the header to memory based on its size and offset in file on disk
LPVOID ReadHeader(std::fstream& hFile, DWORD dwHeaderSize, DWORD dwOffset);

// Returns a pointer to a section header based on relative virtual address(RVA)
PIMAGE_SECTION_HEADER FindSection(std::fstream& hFile, DWORD dwRVA, DWORD dwFstSectionHeader, WORD wNumSections);

// Aligns the dwSize argument
DWORD AlignUp(DWORD dwSize, DWORD dwAlign);

// Read part of the data from given buffer
BYTE* ReadData(unsigned char*buffer, DWORD dwOffset, DWORD dwSize);

// Check if legitimate function name
BOOL IsFunctionName(char *buffer);

// Write the PE section header at the appropriate offset in file
BOOL WriteSectionHeader(PIMAGE_SECTION_HEADER pSectionHeader, DWORD dwSectionID, std::ofstream& hFile, DWORD dwFstSctHeaderOffset);

// Add a new section to file
PIMAGE_SECTION_HEADER AddSection(std::fstream& hFile, unsigned char *sectionData, DWORD dwSectionDataSize,
	DWORD dwFstSectionHeaderOffset, PIMAGE_NT_HEADERS pNtHeader, const char *sectionName);

// Write certain amount of data to file
BOOL WriteDataToFile(std::ofstream& hFile, DWORD dwOffset, DWORD dwSize, BYTE* data);

// Load the section which contains executable code to memory
BYTE* LoadExecutableSection(std::fstream& hFile, PIMAGE_DOS_HEADER pDosHeader, PIMAGE_NT_HEADERS pNtHeader,
	DWORD dwFstSctHdrOffset, PIMAGE_SECTION_HEADER* pSectionHeader);

// Check if a given file is a valid PE file
BOOL ValidateFile(std::fstream& hFile);

BYTE* ExtractOverlays(std::fstream& hFile, PIMAGE_SECTION_HEADER pLastSectionHeader, DWORD *overlay_size);

// ### added for ELF support:

// Check if ELF file is valid and supported
BOOL elf_supported(Elf32_Ehdr *hdr);

// Finds section containing executable code
Elf32_Shdr *ElfFindSection(std::fstream& hFile, Elf32_Ehdr *hdr);

// Load the chosed section from ELF file to memory
BYTE *ElfLoadSection(std::fstream& hFile, Elf32_Shdr *shdr);

// Writes the given section back to file on disk
BOOL ElfWriteSection(std::ofstream& hFile, Elf32_Shdr *pElfSectionHeader,
						unsigned char *buffer);
//
// Write the ELF section header at the appropriate offset in file
BOOL ElfWriteSectionHeader(Elf32_Shdr *pElfSectionHeader, int index, 
								std::ofstream& hFile, int shoff);
