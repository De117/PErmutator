#include "PEFunctions.h"

void OpenFile(const char *fileName, std::fstream& hFile)
{
	try
	{
		hFile.open(fileName, std::ios::in | std::ios::binary);
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "OpenFile: Error while opening file: " << e.what() << std::endl;
		return;
	}
}

BYTE* LoadSection(std::fstream& hFile, PIMAGE_SECTION_HEADER pSectionHeader)
{
	unsigned char *buffer;

	buffer = (unsigned char *)malloc(pSectionHeader->SizeOfRawData);
	if (buffer == nullptr)
	{
		std::cerr << "LoadSection: Unable to allocate memory, invalid size: " << pSectionHeader->SizeOfRawData << std::endl;
		return nullptr;
	}

	try
	{
		hFile.seekg(pSectionHeader->PointerToRawData, std::ios::beg);
		hFile.read((char *)buffer, pSectionHeader->SizeOfRawData);
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "LoadSection: Unable to read file: " << e.what() << std::endl;
		return nullptr;
	}
	

	return buffer;
}

BOOL WriteSection(std::ofstream& hFile, PIMAGE_SECTION_HEADER pSectionHeader, unsigned char *buffer)
{
	try
	{
		hFile.seekp(pSectionHeader->PointerToRawData, std::ios::beg);
		hFile.write((char*)buffer, pSectionHeader->SizeOfRawData);
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "WriteSection: Error while writing section data: " << e.what() << std::endl;
		return FALSE;
	}

	return TRUE;
}

LPVOID ReadHeader(std::fstream& hFile, DWORD dwHeaderSize, DWORD dwOffset)
{
	LPVOID pHeader;

	pHeader = malloc(dwHeaderSize);
	if (pHeader == nullptr)
	{
		std::cerr << "ReadHeader: Unable to allocate memory" << std::endl;
		return nullptr;
	}

	try
	{
		hFile.seekg(dwOffset, std::ios::beg);
		hFile.read((char*)pHeader, dwHeaderSize);
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "ReadHeader: Error while reading header: " << e.what() << std::endl;
		return nullptr;
	}

	return pHeader;
}

PIMAGE_SECTION_HEADER FindSection(std::fstream& hFile, DWORD dwRVA, DWORD dwFstSectionHeader, WORD wNumSections)
{
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr;

	for (WORD i = 0; i < wNumSections; ++i)
	{
		pSectionHeader = (PIMAGE_SECTION_HEADER)ReadHeader(hFile, IMAGE_SIZEOF_SECTION_HEADER, dwFstSectionHeader + i*IMAGE_SIZEOF_SECTION_HEADER);
		if (pSectionHeader == nullptr)
		{
			std::cerr << "FindSection: Invalid section header read" << std::endl;
			continue;
		}

		if ((dwRVA >= pSectionHeader->VirtualAddress) &&
			(dwRVA < (pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)))
		{
			return pSectionHeader;
		}

		free(pSectionHeader);
		pSectionHeader = nullptr;
	}

	return nullptr;
}

Elf32_Shdr *ElfFindSection(std::fstream& hFile, Elf32_Ehdr *hdr)
{
	Elf32_Shdr *shdr;
	//  Elf32_Addr entry = pElfHeader->e_entry;		// entry point (RVA)
	//  Elf32_Off shoffset = pElfHeader->e_shoff;	// section headers offset
	//  Elf32_Half shnum = pElfHeader->e_shnum;		// number of section headers
	Elf32_Shdr *shstrtabhdr = nullptr;	// section header stringtable header
	char *shstrtable = nullptr;			// section header stringtable

	shstrtabhdr = (Elf32_Shdr *)ReadHeader(hFile, sizeof(Elf32_Shdr),
					hdr->e_shoff + hdr->e_shstrndx*sizeof(Elf32_Shdr));
	shstrtable = (char *)ReadHeader(hFile, 
									shstrtabhdr->sh_size,
									shstrtabhdr->sh_offset);
	
	for (int i=0; i<(int)hdr->e_shoff; i++) {
		shdr = (Elf32_Shdr *)ReadHeader(hFile, sizeof(Elf32_Shdr), 
										hdr->e_shoff + i*sizeof(Elf32_Shdr));
		if (!strcmp(".text", ((const char *)(shstrtable + shdr->sh_name)))) {
			return shdr;
			free(shstrtable);
		} else
			free(shdr);
	}
	free(shstrtable);
	return nullptr;
}

BYTE *ElfLoadSection(std::fstream& hFile, Elf32_Shdr *shdr)
{
	return (BYTE *)ReadHeader(hFile, shdr->sh_size, shdr->sh_offset);
}

BOOL ElfWriteSection(std::ofstream& hFile, Elf32_Shdr *pElfSectionHeader,
						unsigned char *buffer)
{
	if (pElfSectionHeader->sh_type == SHT_NULL || 
		pElfSectionHeader->sh_type == SHT_NOBITS)
		return TRUE;
	try
	{
		hFile.seekp(pElfSectionHeader->sh_offset, std::ios::beg);
		hFile.write((char*)buffer, pElfSectionHeader->sh_size);
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "WriteSection: Error while writing section data: " 
					<< e.what() << std::endl;
		return FALSE;
	}

	return TRUE;
}

BOOL ElfWriteSectionHeader(Elf32_Shdr *pElfSectionHeader, int index, 
								std::ofstream& hFile, int shoff)
{
	if (pElfSectionHeader->sh_type == SHT_NULL)
		return TRUE;
	try
	{
		hFile.seekp(shoff + index*sizeof(Elf32_Shdr), std::ios::beg);
		hFile.write((char*)pElfSectionHeader, sizeof(Elf32_Shdr));
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "WriteSectionHeader: Error while writing the section header: "
					<< e.what() << std::endl;
		return FALSE;
	}

	return TRUE;
}
DWORD AlignUp(DWORD dwSize, DWORD dwAlign)
{
	return ((dwSize + dwAlign - 1) - (dwSize + dwAlign - 1) % dwAlign);
}

BYTE* ReadData(unsigned char*buffer, DWORD dwOffset, DWORD dwSize)
{
	unsigned char *data_segment;

	data_segment = (unsigned char*)malloc(dwSize);
	if (data_segment == nullptr)
	{
		std::cerr << "ReadData: Unable to allocate memory" << std::endl;
		return nullptr;
	}
	memset(data_segment, 0, dwSize);
	std::memcpy(data_segment, buffer + dwOffset, dwSize);

	return data_segment;
}

BOOL IsFunctionName(char *buffer)
{
	DWORD length = strlen(buffer);

	for (DWORD i = 0; i < length; ++i)
	{
		if ((buffer[i] >= 65 && buffer[i] <= 90) ||
			(buffer[i] >= 97 && buffer[i] <= 122))
		{
			continue;
		}
		else
		{
			return FALSE;
		}
	}

	return TRUE;
}

BOOL WriteSectionHeader(PIMAGE_SECTION_HEADER pSectionHeader, DWORD dwSectionID, std::ofstream& hFile, DWORD dwFstSctHeaderOffset)
{
	DWORD dwSectionOffset;

	dwSectionOffset = dwFstSctHeaderOffset + IMAGE_SIZEOF_SECTION_HEADER*dwSectionID;

	try
	{
		hFile.seekp(dwSectionOffset, std::ios::beg);
		hFile.write((char*)pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "WriteSectionHeader: Error while writing the section header: " << e.what() << std::endl;
		return FALSE;
	}

	return TRUE;
}

PIMAGE_SECTION_HEADER AddSection(std::fstream& hFile, unsigned char *sectionData, DWORD dwSectionDataSize,
	DWORD dwFstSectionHeaderOffset, PIMAGE_NT_HEADERS pNtHeader, const char *sectionName)
{
	PIMAGE_SECTION_HEADER pLastSectionHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;

	// Read the last section header
	pLastSectionHeader = (PIMAGE_SECTION_HEADER)ReadHeader(hFile, IMAGE_SIZEOF_SECTION_HEADER,
		dwFstSectionHeaderOffset + IMAGE_SIZEOF_SECTION_HEADER*(pNtHeader->FileHeader.NumberOfSections - 1));
	if (pLastSectionHeader == nullptr)
	{
		std::cerr << "AddSection: Error while reading the last section header" << std::endl;
		return nullptr;
	}

	// Allocate memory for new section header
	pSectionHeader = (PIMAGE_SECTION_HEADER)malloc(IMAGE_SIZEOF_SECTION_HEADER);
	if (pSectionHeader == nullptr)
	{
		std::cerr << "AddSection: Error while allocating memory for new section header" << std::endl;
		return nullptr;
	}

	// Populate the section header
	std::memcpy(pSectionHeader->Name, sectionName, IMAGE_SIZEOF_SHORT_NAME);
	pSectionHeader->Misc.VirtualSize = dwSectionDataSize;
	pSectionHeader->VirtualAddress = AlignUp(pLastSectionHeader->VirtualAddress + pLastSectionHeader->Misc.VirtualSize,
		pNtHeader->OptionalHeader.SectionAlignment);
	pSectionHeader->SizeOfRawData = AlignUp(dwSectionDataSize, pNtHeader->OptionalHeader.FileAlignment);
	pSectionHeader->PointerToRawData = AlignUp(pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData,
		pNtHeader->OptionalHeader.FileAlignment);
	pSectionHeader->PointerToRelocations = 0;
	pSectionHeader->PointerToLinenumbers = 0;
	pSectionHeader->NumberOfRelocations = 0;
	pSectionHeader->NumberOfLinenumbers = 0;
	pSectionHeader->Characteristics = 0xE0000020;

	try
	{
		// Position the file pointer where the new section header should be written
		hFile.seekg(dwFstSectionHeaderOffset + IMAGE_SIZEOF_SECTION_HEADER*pNtHeader->FileHeader.NumberOfSections, std::ios::beg);

		// Write the new section header
		hFile.write((char*)pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);

		// Position the file pointer to where the section data should be written
		hFile.seekg(pSectionHeader->PointerToRawData, std::ios::beg);

		// Write the section data
		hFile.write((char*)sectionData, pSectionHeader->SizeOfRawData);
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "AddSection: Error occured while writing new section with data to file: " << e.what() << std::endl;
		return nullptr;
	}

	// Update the PE header
	pNtHeader->FileHeader.NumberOfSections++;
	pNtHeader->OptionalHeader.SizeOfImage = AlignUp(pNtHeader->OptionalHeader.SizeOfImage + pSectionHeader->Misc.VirtualSize,
		pNtHeader->OptionalHeader.SectionAlignment);

	return pSectionHeader;
}

BOOL WriteDataToFile(std::ofstream& hFile, DWORD dwOffset, DWORD dwSize, BYTE* data)
{
	try
	{
		hFile.seekp(dwOffset, std::ios::beg);
		hFile.write((char*)data, dwSize);
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "WriteDataToFile: Error while writing data to file: " << e.what() << std::endl;
		return FALSE;
	}
	

	return TRUE;
}

BYTE* LoadExecutableSection(std::fstream& hFile, PIMAGE_DOS_HEADER pDosHeader, PIMAGE_NT_HEADERS pNtHeader,
	DWORD dwFstSctHdrOffset, PIMAGE_SECTION_HEADER* pSectionHeader)
{
	BYTE* sectionData = nullptr;
	//PIMAGE_SECTION_HEADER pSectionHeader = nullptr;

	for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i)
	{
		*pSectionHeader = (PIMAGE_SECTION_HEADER)ReadHeader(hFile, IMAGE_SIZEOF_SECTION_HEADER, dwFstSctHdrOffset + i*IMAGE_SIZEOF_SECTION_HEADER);
		if (*pSectionHeader == nullptr)
		{
			std::cerr << "LoadExecutableSection: Invalid section header read, offset: " <<
				dwFstSctHdrOffset + i*IMAGE_SIZEOF_SECTION_HEADER << std::endl;
			continue;
		}

		//if (((*pSectionHeader)->Characteristics & 0x00000020) && ((*pSectionHeader)->Characteristics & 0x20000000))
		//{
			if ((pNtHeader->OptionalHeader.AddressOfEntryPoint >= (*pSectionHeader)->VirtualAddress) &&
				(pNtHeader->OptionalHeader.AddressOfEntryPoint < ((*pSectionHeader)->VirtualAddress + (*pSectionHeader)->Misc.VirtualSize)))
			{
				break;
			}
		//}

		free(*pSectionHeader);
		*pSectionHeader = nullptr;
	}

	if (*pSectionHeader == nullptr)
	{
		std::cerr << "LoadExecutableSection: Error while reading executable section header" << std::endl;
		return nullptr;
	}

	sectionData = LoadSection(hFile, *pSectionHeader);
	if (sectionData == nullptr)
	{
		std::cerr << "LoadExecutableSection: Unable to load section with executable code to memory" << std::endl;
		return nullptr;
	}

	return sectionData;
}

BOOL ValidateFile(std::fstream& hFile)
{
	BYTE buffer[2];

	hFile.read((char*)buffer, 2);

	if (buffer[0] != 'M' || buffer[1] != 'Z')
		return FALSE;


	return TRUE;
}

BYTE* ExtractOverlays(std::fstream& hFile, PIMAGE_SECTION_HEADER pLastSectionHeader, DWORD *overlay_size)
{
	DWORD fileSize;
	DWORD overlaySize;
	DWORD begin, end;
	unsigned char *overlayBuffer;

	try
	{
		// Get the file size
		hFile.seekg(0, std::ios::beg);
		begin = (DWORD)hFile.tellg();
		hFile.seekg(0, std::ios::end);
		end = (DWORD)hFile.tellg();
		fileSize = end - begin;
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "ExtractOverlays: Error while calculating file size: " << e.what() << std::endl;
		return nullptr;
	}

	// Position where the overlay starts
	DWORD overlayStart = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;

	// Check if the overlay exists
	if (overlayStart == fileSize)
	{
		// NO overlay
		return nullptr;
	}

	// Position the file pointer to the beginning of overlay
	hFile.seekg(overlayStart, std::ios::beg);

	// Calculate overlay size and allocate memory for buffer
	overlaySize = fileSize - overlayStart;
	overlayBuffer = (unsigned char *)malloc(overlaySize * sizeof(unsigned char));
	if (overlayBuffer == nullptr)
	{
		std::cerr << "ExtractOverlays: Insufficient memory for overlay buffer!" << std::endl;
		std::cerr << "----------------------------------------" << std::endl;
		return nullptr;
	}

	try
	{
		// Read the overlay into the buffer
		hFile.read((char*)overlayBuffer, overlaySize);
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "ExtractOverlays: Error while reading overlay to memory: " << e.what() << std::endl;
		return nullptr;
	}
	
	*overlay_size = overlaySize;
	return overlayBuffer;
}

BOOL elf_supported(Elf32_Ehdr *hdr) {

	if (!hdr) return FALSE;

	// not an ELF file
	if(hdr->e_ident[EI_MAG0] != ELFMAG0 || hdr->e_ident[EI_MAG1] != ELFMAG1
	|| hdr->e_ident[EI_MAG2] != ELFMAG2 || hdr->e_ident[EI_MAG3] != ELFMAG3)
		return FALSE;
	// unsupported ELF file class (must have 32-bit objects)
	if(hdr->e_ident[EI_CLASS] != ELFCLASS32)
		return FALSE;
	// unsupported ELF file byte order (must be little-endian)
	if(hdr->e_ident[EI_DATA] != ELFDATA2LSB)
		return FALSE;
	// unsupported machine architecture	(must be x86)
	if(hdr->e_machine != EM_386)
		return FALSE;
	// unsupported ELF file version (must be current)
	if(hdr->e_ident[EI_VERSION] != EV_CURRENT)
		return FALSE;
	// unsupported ELF file type (must be relocatable or executable)
	if(hdr->e_type != ET_REL && hdr->e_type != ET_EXEC)
		return FALSE;

	// check existence of shdr and phdr
	if(!hdr->e_shoff || !hdr->e_phoff)
		return FALSE;

	return TRUE;
}
