#include "stdafx.h"
#include <DbgHelp.h>
#include <Windows.h>

#pragma comment(lib,"DbgHelp.lib")


extern "C" __declspec(dllexport) int DecryptSymbolName(char* name, char* t)
{
	char buffer[256];

	UnDecorateSymbolName(name, buffer, 256, 0);

	int len = strlen(buffer);

	for (size_t i = 0; i < len; i++)
	{
		*(t + i) = *(i + buffer);
	}

	return 0;
}
