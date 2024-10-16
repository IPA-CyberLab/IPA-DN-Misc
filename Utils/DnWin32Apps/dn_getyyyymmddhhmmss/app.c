#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

int main(int argc, char *argv[])
{
	SYSTEMTIME tm = { 0 };

	int systemTimeMode = 0;
	int printMode = 0;
	int delimiter = 0;
	int millisecs = 0;

	if (argc >= 2)
	{
		if (strcmpi(argv[1], "/?") == 0 || strcmpi(argv[1], "/help") == 0 || strcmpi(argv[1], "-?") == 0 || strcmpi(argv[1], "--help") == 0 || strcmpi(argv[1], "-h") == 0)
		{
			printf("Usage:\n [systemTimeMode=0|1] [printMode=0|1|2] [delimiter=0|1|2|3] [millisecs=0|1] \n");
			return -1;
		}

		systemTimeMode = (int)strtol(argv[1], NULL, 0);
	}

	if (argc >= 3)
	{
		printMode = (int)strtol(argv[2], NULL, 0);
	}

	if (argc >= 4)
	{
		delimiter = (int)strtol(argv[3], NULL, 0);
	}

	if (argc >= 5)
	{
		millisecs = (int)strtol(argv[4], NULL, 0);
	}

	if (systemTimeMode)
	{
		GetSystemTime(&tm);
	}
	else
	{
		GetLocalTime(&tm);
	}

	char dst[512] = { 0 };

	char yyyymmdd[128] = { 0 };
	char hhmmss[128] = { 0 };
	char msecs[128] = { 0 };
	char delimiterstr[128] = { 0 };

	if (delimiter == 1)
	{
		strcpy(delimiterstr, "_");
	}
	else if (delimiter == 2)
	{
		strcpy(delimiterstr, "-");
	}
	else if (delimiter == 3)
	{
		strcpy(delimiterstr, " ");
	}

	sprintf(yyyymmdd, "%04d%02d%02d", tm.wYear, tm.wMonth, tm.wDay);
	sprintf(hhmmss, "%02d%02d%02d", tm.wHour, tm.wMinute, tm.wSecond);
	sprintf(msecs, ".%03d", tm.wMilliseconds);

	if (printMode == 1)
	{
		strcpy(dst, yyyymmdd);
	}
	else if (printMode == 2)
	{
		strcpy(dst, hhmmss);

		if (millisecs)
		{
			strcat(dst, msecs);
		}
	}
	else
	{
		strcpy(dst, yyyymmdd);
		strcat(dst, delimiterstr);
		strcat(dst, hhmmss);

		if (millisecs)
		{
			strcat(dst, msecs);
		}
	}

	printf("%s\n", dst);

	return 0;
}
