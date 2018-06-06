#ifndef PEINFECT_H
#define PEINFECT_H

#include <Windows.h>
#include <stdio.h>
#include <string>
#include <vector>

enum PEINFECTION_RESULT;

PEINFECTION_RESULT PEInfect(std::wstring PETargetFilePath, std::vector<BYTE> ShellCode);
#endif // PEINFECT_H
