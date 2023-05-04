#include <Windows.h>
#include <aclapi.h>
#include <stdio.h>
#include <tchar.h>

int pipe_chmod(HANDLE handle) {
    SID_IDENTIFIER_AUTHORITY sid_world = { SECURITY_WORLD_SID_AUTHORITY };
    PACL old_dacl, new_dacl;
    PSECURITY_DESCRIPTOR sd;
    EXPLICIT_ACCESS ea;
    PSID everyone;
    int error = 0;

    if (!AllocateAndInitializeSid(&sid_world,
        1,
        SECURITY_WORLD_RID,
        0, 0, 0, 0, 0, 0, 0,
        &everyone)) {
        _tprintf(_T("AllocateAndInitializeSid Error %u\n"), GetLastError());
        goto done;
    }

    if (GetSecurityInfo(handle,
        SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        &old_dacl,
        NULL,
        &sd)) {
        _tprintf(_T("GetSecurityInfo Error %u\n"), GetLastError());
        goto clean_sid;
    }

    memset(&ea, 0, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions |= GENERIC_READ;
    ea.grfAccessPermissions |= GENERIC_WRITE;
    ea.grfAccessPermissions |= SYNCHRONIZE;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPTSTR)everyone;

    if (SetEntriesInAcl(1, &ea, old_dacl, &new_dacl)) {
        _tprintf(_T("SetEntriesInAcl Error %u\n"), GetLastError());
        goto clean_sd;
    }

    if (SetSecurityInfo(handle,
        SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        new_dacl,
        NULL)) {
        _tprintf(_T("SetSecurityInfo Error %u\n"), GetLastError());
        goto clean_dacl;
    }

    error = 0;

clean_dacl:
    LocalFree((HLOCAL)new_dacl);
clean_sd:
    LocalFree((HLOCAL)sd);
clean_sid:
    FreeSid(everyone);
done:
    if (error) {
        
    }

    return 0;
}

int main(void)
{
    HANDLE hPipe;
    char buffer[1024];
    DWORD dwRead;
    LPCTSTR lpszPipename = TEXT("\\\\.\\pipe\\mynamedpipe");

    DWORD dwRes;
    PSID everyone = NULL;
    PACL pACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS ea;
    SID_IDENTIFIER_AUTHORITY sid_world = { SECURITY_WORLD_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
    SECURITY_ATTRIBUTES sa;

    if (!AllocateAndInitializeSid(&sid_world,
        1,
        SECURITY_WORLD_RID,
        0, 0, 0, 0, 0, 0, 0,
        &everyone)) {
        _tprintf(_T("AllocateAndInitializeSid Error %u\n"), GetLastError());
        return 1;
    }

    memset(&ea, 0, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions |= GENERIC_READ;
    ea.grfAccessPermissions |= GENERIC_WRITE;
    ea.grfAccessPermissions |= SYNCHRONIZE;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPTSTR)everyone;

    // Create a new ACL that contains the new ACEs.
    dwRes = SetEntriesInAcl(1, &ea, NULL, &pACL);
    if (ERROR_SUCCESS != dwRes)
    {
        _tprintf(_T("SetEntriesInAcl Error %u\n"), GetLastError());
        return 1;
    }

    // Initialize a security descriptor.  
    pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,
        SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (NULL == pSD)
    {
        _tprintf(_T("LocalAlloc Error %u\n"), GetLastError());
        return 1;
    }

    if (!InitializeSecurityDescriptor(pSD,
        SECURITY_DESCRIPTOR_REVISION))
    {
        _tprintf(_T("InitializeSecurityDescriptor Error %u\n"),
            GetLastError());
        return 1;
    }

    // Add the ACL to the security descriptor. 
    if (!SetSecurityDescriptorDacl(pSD,
        TRUE,     // bDaclPresent flag   
        pACL,
        FALSE))   // not a default DACL 
    {
        _tprintf(_T("SetSecurityDescriptorDacl Error %u\n"),
            GetLastError());
        return 1;
    }

    // Initialize a security attributes structure.
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;


    hPipe = CreateNamedPipe(lpszPipename,
        PIPE_ACCESS_DUPLEX | WRITE_DAC, // FILE_FLAG_FIRST_PIPE_INSTANCE is not needed but forces CreateNamedPipe(..) to fail if the pipe already exists...
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,
        1024 * 16,
        1024 * 16,
        NMPWAIT_USE_DEFAULT_WAIT,
        NULL);
    while (hPipe != INVALID_HANDLE_VALUE)
    {
        pipe_chmod(hPipe);
        if (ConnectNamedPipe(hPipe, NULL) != FALSE)   // wait for someone to connect to the pipe
        {
            while (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL) != FALSE)
            {
                /* add terminating zero */
                buffer[dwRead] = '\0';

                /* do something with data in buffer */
                printf("%s\n", buffer);
            }
        }

        DisconnectNamedPipe(hPipe);
    }

    _tprintf(TEXT("Could not open pipe. GLE=%d\n"), GetLastError());

    return 0;
}