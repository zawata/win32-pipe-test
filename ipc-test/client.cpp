#include <windows.h> 
#include <stdio.h>
#include <conio.h>
#include <tchar.h>

#define BUFSIZE 512

int main(void)
{
    HANDLE hPipe;
    DWORD dwWritten;
    LPCTSTR lpszPipename = TEXT("\\\\.\\pipe\\mynamedpipe");

    hPipe = CreateFile(lpszPipename,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (hPipe != INVALID_HANDLE_VALUE)
    {
        WriteFile(hPipe,
            "Hello Pipe\n",
            12,   // = length of string + terminating '\0' !!!
            &dwWritten,
            NULL);

        CloseHandle(hPipe);
        _tprintf(L"close\n");
    }
    _tprintf(TEXT("Could not open pipe. GLE=%d\n"), GetLastError());

    return (0);
}