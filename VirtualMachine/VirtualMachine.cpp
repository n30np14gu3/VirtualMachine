#include "VMCore.h"
#include <cstdlib>
#include <iostream>


VMCore core;

int main()
{
	std::cout << "V1r7u41 M4ch1n3 by <@shockbyte>" << std::endl;


	FILE* vmFile = nullptr;
	byte* dump = new byte[1340];

	fopen_s(&vmFile, "vm_dump.vm", "rb");
	if (vmFile == nullptr)
		exit(0);
	fread_s(dump, 1340, 1, 1340, vmFile);
	fclose(vmFile);

	core.load(dump, 1340);
#if !NDEBUG
	core.de_exec();
#else
	core.exec();
#endif

	delete[] dump;
	system("\r\npause");
}
