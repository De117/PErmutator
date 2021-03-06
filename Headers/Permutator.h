#pragma once
#include "PEFunctions.h"
#include "Graph.h"
#include "distorm.h"
#include <vector>
#include <queue>
#include <sstream>

#ifdef _WIN32
#pragma comment(lib, "Lib\\distorm.lib")
#endif

#define MAX_INSTRUCTIONS (100)

typedef struct _Block
{
	_OffsetType offset;
	_OffsetType parentOffset;
	DWORD blockSize = 0;
} Block;

class Permutator
{
public:
	Permutator(char* fileName);
	~Permutator();

	Graph* GetGraph();

	int CreateGraph(int creationMode);
	bool VisualizeGraph(Node* n);
	bool WriteModifiedFile();

private:
	std::fstream hInputFile;
	std::ofstream outputFile;
	std::ofstream gvFile;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	PIMAGE_SECTION_HEADER pExecSectionHeader;
	DWORD dwFstSctHdrOffset;
	Graph graph;
	std::vector<Node* > dataNodes;
	BYTE* dataBytes;
	DWORD dataSize;

	// ###
	BOOL elfMode;
	Elf32_Ehdr *pElfHeader;
	Elf32_Shdr *pElfSectionHeader;
	Elf32_Shdr *pElfExecSectionHeader;
	// ###


		
	void InitPermutator(char* fileName);
	void _CreateGraph(BYTE* sectionData, _OffsetType blockOffset, DWORD dwSectionSize, _OffsetType parentOffset, 
		std::vector<Block>& targets);
	void __CreateGraph(BYTE* sectionData, _OffsetType blockOffset, DWORD dwSectionSize, _OffsetType parentOffset);
	bool CheckRange(QWORD qOffset);
	bool IsJump(std::string mnemonic);
	bool IsRegister(std::string operand);
	bool IsFunctionOperandValid(std::string operand);
	void ProcessNode(Node* n, std::ofstream& gvFile);
	void CreatePath(Node* n, std::ofstream& gvFile);
	void CreateDataNodes(BYTE* sectionData);
	void WriteGraph(Node* n, BYTE* sectionData);
	void WriteData(BYTE* sectionData);
};

