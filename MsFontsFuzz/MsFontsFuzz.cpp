#include "stdafx.h"

#define USE_INCORRECT_CRC_FIXING

#define WND_CLASS "MsFontsFuzz"
#define WND_TITLE "MsFontsFuzz"

#define WND_W 500
#define WND_H 500

#define LOG_FILE_NAME "MsFontsFuzz.log"

#define XALIGN_DOWN(x, align)(x &~ (align - 1))
#define XALIGN_UP(x, align)((x & (align - 1)) ? XALIGN_DOWN(x, align) + align : x)

#define M_ALLOC(_size_) LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, (ULONG)(_size_))
#define M_FREE(_addr_) LocalFree((_addr_))

char m_szTable[0xff + 0x20];
LPCTSTR m_lpFontPath = NULL, m_lpFontName = NULL;
TCHAR m_TmpFontPath[MAX_PATH];
HINSTANCE m_hInstance = NULL;
HWND m_hWnd = NULL;

// fuzzer startup options
BOOL m_bTest = FALSE, m_bResume = FALSE, m_bNoisy = FALSE, m_bFixCrcs = FALSE;

DWORD m_dwCasesProcessed = 0;

#define FONT_TYPE_GENERIC   0
#define FONT_TYPE_OTF       1
#define FONT_TYPE_TTF       2

DWORD m_dwFontType = FONT_TYPE_GENERIC;

// data buffers
DWORD m_dwDataSize = 0, m_dwAlignedDataSize = 0;
PVOID m_pData = NULL, m_pAlignedData = NULL;

HANDLE m_hDbgFile = NULL, m_hWndEvent = NULL;

#define BIG_BUFFER_LENGTH 0x1000

/**
 * Data generator global settings
 */
DWORD BLOCK_SIZE        = 2;
DWORD FILE_RANGE_START  = 0;
DWORD FILE_RANGE_END    = 0;
DWORD BLOCK_RANGE_START = 0;
DWORD BLOCK_RANGE_END   = 0xFFFF;
DWORD BLOCK_RANGE_N     = 0x100;

typedef struct _ENGINE_PARAM
{
    LPCTSTR lpName;
    PDWORD pdwValue;    

} ENGINE_PARAM;

ENGINE_PARAM m_Params[] =
{
    { _T("BLOCK_SIZE"),         &BLOCK_SIZE         },
    { _T("FILE_RANGE_START"),   &FILE_RANGE_START   },
    { _T("FILE_RANGE_END"),     &FILE_RANGE_END     },
    { _T("BLOCK_RANGE_START"),  &BLOCK_RANGE_START  },
    { _T("BLOCK_RANGE_END"),    &BLOCK_RANGE_END    },
    { _T("BLOCK_RANGE_N"),      &BLOCK_RANGE_N      }
};

#define MAX_CASES_PER_PROCESS 1000
//--------------------------------------------------------------------------------------
LPCTSTR _tGetNameFromFullPath(LPCTSTR lpPath)
{
    LPCTSTR lpName = lpPath;

    for (size_t i = 0; i < _tcslen(lpPath); i++)
    {
        if (lpPath[i] == '\\' || lpPath[i] == '/')
        {
            lpName = lpPath + i + 1;
        }
    }

    return lpName;
}
//--------------------------------------------------------------------------------------
char *GetNameFromFullPath(char *lpPath)
{
    char *lpName = lpPath;

    for (size_t i = 0; i < strlen(lpPath); i++)
    {
        if (lpPath[i] == '\\' || lpPath[i] == '/')
        {
            lpName = lpPath + i + 1;
        }
    }

    return lpName;
}
//--------------------------------------------------------------------------------------
BOOL DbgInit(char *lpszDbgLogPath)
{  
    if (m_bResume)
    {
        m_hDbgFile = CreateFileA(
            lpszDbgLogPath, 
            GENERIC_READ | GENERIC_WRITE, 
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, 
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        SetFilePointer(m_hDbgFile, 0, NULL, FILE_END);
    }
    else
    {
        m_hDbgFile = CreateFileA(
            lpszDbgLogPath, 
            GENERIC_READ | GENERIC_WRITE, 
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, 
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
    }    

    if (m_hDbgFile != INVALID_HANDLE_VALUE)
    {         
        return TRUE;
    }
    else
    {                
        printf("CreateFile() ERROR %d\n", GetLastError());
    }

    m_hDbgFile = NULL;
    return FALSE;
}
//--------------------------------------------------------------------------------------
void DbgMsg(char *lpszFile, int Line, char *lpszMsg, ...)
{
    va_list mylist;
    va_start(mylist, lpszMsg);

    size_t len = _vscprintf(lpszMsg, mylist) + 0x100;

    char *lpszBuff = (char *)LocalAlloc(LMEM_FIXED, len);
    if (lpszBuff == NULL)
    {
        va_end(mylist);
        return;
    }

    char *lpszOutBuff = (char *)LocalAlloc(LMEM_FIXED, len);
    if (lpszOutBuff == NULL)
    {
        LocalFree(lpszBuff);
        va_end(mylist);
        return;
    }

    vsprintf_s(lpszBuff, len, lpszMsg, mylist);	
    va_end(mylist);

    sprintf_s(
        lpszOutBuff, len, "[%.5d] .\\%s(%d) : %s", 
        GetCurrentProcessId(), GetNameFromFullPath(lpszFile), Line, lpszBuff
    );	

    OutputDebugStringA(lpszOutBuff);

    HANDLE hStd = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStd != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten = 0;
        WriteFile(hStd, lpszBuff, lstrlenA(lpszBuff), &dwWritten, NULL);    
    }

    if (m_hDbgFile)
    {
        DWORD dwWritten = 0;
        WriteFile(m_hDbgFile, lpszBuff, strlen(lpszBuff), &dwWritten, NULL);
    }

    LocalFree(lpszOutBuff);
    LocalFree(lpszBuff);
}
//--------------------------------------------------------------------------------------
BOOL DumpToFile(LPCTSTR lpFileName, PVOID pData, ULONG DataSize)
{
    HANDLE hFile = CreateFile(lpFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten = 0;
        WriteFile(hFile, pData, DataSize, &dwWritten, NULL);

        CloseHandle(hFile);

        return TRUE;
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): CreateFile() ERROR %d\n", GetLastError());
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
BOOL ReadFromFile(LPCTSTR lpFileName, PVOID *pData, PDWORD lpdwDataSize)
{
    BOOL bRet = FALSE;
    HANDLE hFile = CreateFile(
        lpFileName, 
        GENERIC_READ, 
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
        NULL,
        OPEN_EXISTING, 
        0, 
        NULL
    );
    if (hFile != INVALID_HANDLE_VALUE)
    {
        *lpdwDataSize = GetFileSize(hFile, NULL);
        if (*pData = LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, *lpdwDataSize))
        {
            DWORD dwReaded = 0;
            ReadFile(hFile, *pData, *lpdwDataSize, &dwReaded, NULL);

            bRet = TRUE;
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): LocalAlloc() ERROR %d\n", GetLastError());
            *lpdwDataSize = 0;
        }

        CloseHandle(hFile);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): CreateFile() ERROR %d\n", GetLastError());
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
HFONT FAR PASCAL MyCreateFont(void) 
{
    CHOOSEFONT cf;
    LOGFONT lf; 
    HFONT hFont; 

    // Initialize members of the LOGFONT structure. 
    ZeroMemory(&lf, sizeof(lf));
    lf.lfHeight = -36;
    lf.lfWidth = 0;
    lf.lfEscapement = 0;
    lf.lfOrientation = 0;
    lf.lfWeight = 0;
    lf.lfItalic = 0;
    lf.lfUnderline = 0;
    lf.lfStrikeOut = 0;
    lf.lfCharSet = 0;
    lf.lfOutPrecision = 0;
    lf.lfClipPrecision = 0;
    lf.lfQuality = 0;
    lf.lfPitchAndFamily = 0;
    _tcscpy_s(lf.lfFaceName, m_lpFontName);

    // Заполняем CHOOSEFONT
    ZeroMemory(&cf, sizeof(cf));
    cf.lStructSize = sizeof(cf);
    cf.lpLogFont = &lf;
    cf.rgbColors = 0;
    cf.Flags = CF_SCREENFONTS | CF_EFFECTS;

    // Create a logical font based on the user's 
    // selection and return a handle identifying 
    // that font. 
    hFont = CreateFontIndirect(&lf);
    return hFont; 
} 
//--------------------------------------------------------------------------------------
#define ID_CLOSE 1

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            RECT area;            

            HDC hDC = BeginPaint(hWnd, &ps);
            GetClientRect(hWnd, &area);
            SetBkMode(hDC, TRANSPARENT);

            // draw caption with the fuzzed font
            HFONT hFont = MyCreateFont(); 
            HFONT hOldFont = (HFONT)SelectObject(hDC, hFont);
            if (hOldFont) 
            { 
                DrawTextA(hDC, m_szTable, -1, &area, DT_CENTER | DT_VCENTER);
                SelectObject(hDC, hOldFont); 
            } 
            
            EndPaint(hWnd, &ps);

            break;
        }

    case WM_COMMAND:
        {
            switch (wParam)
            {
            case ID_CLOSE:

#ifdef TEST_MSG
                MessageBoxA(0, __FUNCTION__, "ID_CLOSE", MB_ICONINFORMATION);
#endif
                // window can be closed now
                SetEvent(m_hWndEvent);
                break;
            }

            break;
        }

    case WM_DESTROY:

        PostQuitMessage(0);
        break;

    default:

        return DefWindowProc(hWnd, message, wParam, lParam);
    }

    return 0;
}
//--------------------------------------------------------------------------------------
DWORD WINAPI FuzzIterationThread(LPVOID lpParam)
{
    MSG Msg;

    // load fuzzed font
    if (AddFontResource(m_TmpFontPath) == 0)
    {
        DbgMsg(__FILE__, __LINE__, "AddFontResource() fails\n");
        return -1;
    }

#ifdef USE_BOADCAST_MESSAGES

    SendMessage(HWND_BROADCAST, WM_FONTCHANGE, 0, 0);

#endif

    int x = (GetSystemMetrics(SM_CXSCREEN) - WND_W) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - WND_H) / 2;

    // create new empty window
    m_hWnd = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        _T(WND_CLASS), _T(WND_TITLE), 
        WS_OVERLAPPEDWINDOW,
        x, y, WND_W, WND_H, 
        NULL, NULL, 
        m_hInstance, 
        NULL
    );
    if (m_hWnd)
    {
        ShowWindow(m_hWnd, SW_SHOWNORMAL);
        UpdateWindow(m_hWnd);

        SendMessage(m_hWnd, WM_COMMAND, ID_CLOSE, 0);

        // Main message loop
        while (GetMessage(&Msg, NULL, 0, 0))
        {
            TranslateMessage(&Msg);
            DispatchMessage(&Msg);
        }
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "CreateWindow() ERROR %d\n", GetLastError());
    }    

    // unload fuzzed font
    if (!RemoveFontResource(m_TmpFontPath))
    {
        DbgMsg(__FILE__, __LINE__, "RemoveFontResource() fails\n");
    }

#ifdef USE_BOADCAST_MESSAGES

    SendMessage(HWND_BROADCAST, WM_FONTCHANGE, 0, 0);

#endif

    return 0;
}
//--------------------------------------------------------------------------------------
BOOL FuzzIteration(void)
{
    ResetEvent(m_hWndEvent);

    // create window in a new thread
    HANDLE hThread = CreateThread(NULL, 0, FuzzIterationThread, NULL, 0, NULL);
    if (hThread)
    {
        HANDLE Objects[2];
        Objects[0] = hThread;
        Objects[1] = m_hWndEvent;

        if (m_bTest)
        {
            WaitForSingleObject(hThread, INFINITE);
            goto end;
        }

        if (WaitForMultipleObjects(2, Objects, FALSE, INFINITE) == WAIT_OBJECT_0)
        {
            // thread has been terminated
            goto end;
        }

        // close window
        SendMessage(m_hWnd, WM_CLOSE, 0, 0);
        WaitForSingleObject(hThread, INFINITE);
end:
        CloseHandle(hThread);

        return TRUE;
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "CreateThread() ERROR %d\n");
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
typedef struct _OTF_FILE_HEADER
{
    ULONG sfntVersion;      // 0x00010000 for version 1.0.
    USHORT numTables;       // Number of tables.
    USHORT searchRange;     // (Maximum power of 2 <= numTables) x 16.
    USHORT entrySelector;   // Log2(maximum power of 2 <= numTables).
    USHORT rangeShift;      // NumTables x 16-searchRange.

} OTF_FILE_HEADER,
*POTF_FILE_HEADER;

typedef struct _OTF_TABLE_HEADER
{
    ULONG tag;      // 4-byte identifier.
    ULONG checkSum; // CheckSum for this table.
    ULONG offset;   // Offset from beginning of TrueType font file.
    ULONG length;   // Length of this table.

} OTF_TABLE_HEADER,
*POTF_TABLE_HEADER;

ULONG OTF_CalcTableChecksum(ULONG *Table, ULONG Length)
{
    ULONG Sum = 0;
    ULONG nLongs = (XALIGN_UP(Length, sizeof(ULONG))) / sizeof(ULONG);

    for (ULONG i = 0; i < nLongs; i++, Table++)
    {
        Sum += htonl(*Table);
    }

    return Sum;
}

POTF_TABLE_HEADER OTF_TableByOffset(PVOID Data, ULONG ByteOffset)
{
    POTF_FILE_HEADER Hdr = (POTF_FILE_HEADER)Data;
    POTF_TABLE_HEADER Table = (POTF_TABLE_HEADER)((PUCHAR)Data + sizeof(OTF_FILE_HEADER));

    // enumerate tables
    for (USHORT i = 0; i < htons(Hdr->numTables); i++)
    {
        char Tag[5];
        ULONG Offset = htonl(Table->offset), Length = htonl(Table->length);
        ULONG Sum = OTF_CalcTableChecksum((ULONG *)((PUCHAR)Data + Offset), Length);

        strncpy(Tag, (char *)&Table->tag, sizeof(ULONG));
        Tag[sizeof(ULONG)] = 0;        

        if (ByteOffset == (ULONG)-1)
        {
            DbgMsg(
                __FILE__, __LINE__, 
                "0x%.8x: %s Offset=0x%.8x Len=0x%.8x Sum=0x%.8x [%s]\n", 
                i, Tag, Offset, Length,
                Sum, (Sum == htonl(Table->checkSum)) ? "OK" : "ERR"
            );

#ifdef USE_INCORRECT_CRC_FIXING

            if (Sum != htonl(Table->checkSum))
            {
                // fix invalid table checksum
                Table->checkSum = htonl(Sum);
                printf("NOTE: Incorrect table CRC was fixed!\n");
            }
#endif 

        }   
        else
        {
            if (ByteOffset >= Offset &&
                ByteOffset < Offset + Length)
            {
                return Table;
            }
        }

        Table += 1;
    }

    return NULL;
}
//--------------------------------------------------------------------------------------
BOOL WriteVal(
    DWORD Ptr, 
    DWORD Size, 
    DWORD Val_1, DWORD Val_2, DWORD Val_3)
{
    ZeroMemory(m_pAlignedData, m_dwAlignedDataSize);
    memcpy(m_pAlignedData, m_pData, m_dwDataSize);

    if (m_bNoisy)
    {
        DbgMsg(
            __FILE__, __LINE__, 
            __FUNCTION__"(): Probing value 0x%.2x 0x%.4x 0x%.8x\n", 
            (UCHAR)Val_1, (USHORT)Val_2, Val_3
        );
    }    

    // zero-bytes stuff
    switch (Size)
    {
    case 1:
        *(PUCHAR)((PUCHAR)m_pAlignedData + Ptr) = (UCHAR)Val_1;
        break;

    case 2:
        *(PUSHORT)((PUCHAR)m_pAlignedData + Ptr) = (USHORT)Val_2;
        break;

    case 4:
        *(PULONG)((PUCHAR)m_pAlignedData + Ptr) = Val_3;
        break;
    }

    POTF_TABLE_HEADER Table = NULL;
    if (m_dwFontType == FONT_TYPE_OTF || m_dwFontType == FONT_TYPE_TTF)
    {
        Table = OTF_TableByOffset(m_pAlignedData, Ptr);     
    }

    if (Table)
    {
        // fix OTF/TTF table checksum
        ULONG Offset = htonl(Table->offset), Length = htonl(Table->length);
        ULONG Sum = OTF_CalcTableChecksum((ULONG *)((PUCHAR)m_pAlignedData + Offset), Length);
        Table->checkSum = htonl(Sum);
    }

    // dump output file
    if (DumpToFile(m_TmpFontPath, m_pAlignedData, m_dwDataSize))
    {
        FuzzIteration();
        m_dwCasesProcessed++;
        return TRUE;
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
LONG WINAPI UnhandledExceptionError(PEXCEPTION_POINTERS ExceptionInfo)
{
    DbgMsg(__FILE__, __LINE__, "Exception 0x%.8x at address 0x%.8x, thread %.4X:%.4X\n", 
        ExceptionInfo->ExceptionRecord->ExceptionCode,
        ExceptionInfo->ExceptionRecord->ExceptionAddress,
        GetCurrentProcessId(), GetCurrentThreadId()
    );

    __asm int 3;

    return EXCEPTION_EXECUTE_HANDLER;
}
//--------------------------------------------------------------------------------------
int _tmain(int argc, _TCHAR* argv[])
{    
    m_hInstance = (HINSTANCE)GetModuleHandle(NULL);

    if (argc >= 3)
    {
        m_lpFontPath = argv[2];
        m_lpFontName = argv[1];
        printf(__FUNCTION__"(): Using external font %ws \"%ws\"\n", m_lpFontName, m_lpFontPath);
    }
    else
    {
        printf("USAGE: MsFontsFuzz.exe <font_name> <font_file> [options]\n");
        goto end;
    }    

    _stprintf_s(m_TmpFontPath, _T("__TMP__%s"), _tGetNameFromFullPath(m_lpFontPath));
    DbgMsg(__FILE__, __LINE__, "[+] Temporary font file is \"%ws\"\n", m_TmpFontPath);

    if (_tcslen(m_TmpFontPath) >= 4)
    {
        _tcslwr(m_TmpFontPath + _tcslen(m_TmpFontPath) - 4);
        if (!_tcscmp(m_TmpFontPath + _tcslen(m_TmpFontPath) - 4, _T(".otf")))
        {
            m_dwFontType = FONT_TYPE_OTF;
            DbgMsg(__FILE__, __LINE__, "[+] Font type is .OTF\n");
        }
        else if (!_tcscmp(m_TmpFontPath + _tcslen(m_TmpFontPath) - 4, _T(".ttf")))
        {
            m_dwFontType = FONT_TYPE_TTF;
            DbgMsg(__FILE__, __LINE__, "[+] Font type is .TTF\n");
        }
    }    

    RemoveFontResource(m_TmpFontPath);

#ifdef USE_BOADCAST_MESSAGES

    SendMessage(HWND_BROADCAST, WM_FONTCHANGE, 0, 0);

#endif

    char ch = 0;
    memset(m_szTable, '.', sizeof(m_szTable) - 1);
    
    for (int i = 0; i < sizeof(m_szTable); i++)
    {
        if (i != 0 && i % 16 == 0)
        {
            m_szTable[i] = '\n';
            continue;
        }

        if (ch >= 0x20)
        {
            m_szTable[i] = ch;
        }

        if (ch == 0x7f)
        {
            m_szTable[i] = 0;
            break;
        }

        ch += 1;
    }

    if (argc > 3)
    {
        // enumerate additional parameters
        for (int i = 3; i < argc; i++)
        {
            if (!_tcscmp(argv[i], _T("--test")))
            {
                // single launch mode
                m_bTest = TRUE;
            }
            else if (!_tcscmp(argv[i], _T("--resume")))
            {
                // resume fuzzing in the new process
                m_bResume = TRUE;
            }
            else if (!_tcscmp(argv[i], _T("--noisy")))
            {
                // show lot of output information
                m_bNoisy = TRUE;
            }
            else if (!_tcscmp(argv[i], _T("--text")) && argc - i > 1)
            {
#ifdef UNICODE
                // use caller-specified text for display
                WideCharToMultiByte(
                    CP_ACP, 0, 
                    argv[i + 1], 
                    -1, 
                    m_szTable,
                    sizeof(m_szTable) - 1, 
                    NULL, NULL
                );
#else
                strcpy_s(m_szTable, argv[i + 1]);
#endif
                i++;
            }
            else if (!_tcscmp(argv[i], _T("--fix-crcs")))
            {
                // fix incorrect checksums for the original font file
                m_bFixCrcs = TRUE;
            }
            else if (argc - i > 1 && argv[i][0] == '-')
            {
                /**
                 * Process data generation options.
                 */

                LPCTSTR lpParam = argv[i] + 1;
                DWORD dwValue = 0;
                BOOL bFound = FALSE;

                if (!StrToIntEx(argv[i + 1], STIF_SUPPORT_HEX, (int *)&dwValue))
                {
                    DbgMsg(__FILE__, __LINE__, "[!] ERROR: Invalid value for parameter \"%ws\"\n", argv[i]);
                    continue;
                }

                for (int i_n = 0; i_n < sizeof(m_Params) / sizeof(ENGINE_PARAM); i_n++)
                {
                    // search parameter by name
                    if (!_tcscmp(m_Params[i_n].lpName, lpParam))
                    {
                        *(m_Params[i_n].pdwValue) = dwValue;
                        bFound = TRUE;
                        break;
                    }
                }

                if (!bFound)
                {
                    DbgMsg(__FILE__, __LINE__, "[!] ERROR: Unknown parameter \"%ws\"\n", argv[i]);
                }

                i++;
            }            
        }
    }

    DbgInit(LOG_FILE_NAME);

    // check block size and range
    if (BLOCK_SIZE == 1)
    {
        if (BLOCK_RANGE_START >= 0xFF)
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Invalid BLOCK_RANGE_START value (it must be <0xFF)\n");
            goto end;
        }

        if (BLOCK_RANGE_END > 0xFF)
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Invalid BLOCK_RANGE_END value (it must be <=0xFF)\n");
            goto end;
        }
    }
    else if (BLOCK_SIZE == 2)
    {
        if (BLOCK_RANGE_START >= 0xFFFF)
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Invalid BLOCK_RANGE_START value (it must be <0xFFFF)\n");
            goto end;
        }

        if (BLOCK_RANGE_END > 0xFFFF)
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Invalid BLOCK_RANGE_END value (it must be <=0xFFFF)\n");
            goto end;
        }
    }
    else if (BLOCK_SIZE == 4)
    {
        if (BLOCK_RANGE_START >= 0xFFFFFFFF)
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Invalid BLOCK_RANGE_START value (it must be <0xFFFFFFFF)\n");
            goto end;
        }

        if (BLOCK_RANGE_END > 0xFFFFFFFF)
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Invalid BLOCK_RANGE_END value (it must be <=0xFFFFFFFF)\n");
            goto end;
        }
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Invalid BLOCK_SIZE value (it must be 1, 2 or 4)\n");
        goto end;
    }

    // check step size
    if (BLOCK_RANGE_N > BLOCK_RANGE_END)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Invalid BLOCK_RANGE_N value (it must be <=BLOCK_RANGE_END)\n");
        goto end;
    }

    WNDCLASSEX wcex;
    ZeroMemory(&wcex, sizeof(wcex));
    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.hInstance = m_hInstance;    
    wcex.lpszClassName = _T(WND_CLASS);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    m_hWndEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (m_hWndEvent == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "CreateEvent() ERROR %d\n", GetLastError());
        goto end;
    }

    // register window class
    if (RegisterClassEx(&wcex) == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "RegisterClassEx() ERROR %d\n", GetLastError());
        goto end;
    }    
    
    // init random number generator
    init_genrand(GetTickCount());

    SetUnhandledExceptionFilter(UnhandledExceptionError);
        
    // read input file
    if (ReadFromFile(m_lpFontPath, &m_pData, &m_dwDataSize))
    {
        if (FILE_RANGE_START >= m_dwDataSize)
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Invalid FILE_RANGE_START value (it must be <=FILE_SIZE)\n");
            M_FREE(m_pData);
            return -1;
        }

        if (FILE_RANGE_END > m_dwDataSize)
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Invalid FILE_RANGE_END value (it must be <FILE_SIZE)\n");
            M_FREE(m_pData);
            return -1;
        }        

        if (FILE_RANGE_END == 0)
        {
            FILE_RANGE_END = m_dwDataSize;
        }

        if (FILE_RANGE_START >= FILE_RANGE_END)
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Invalid FILE_RANGE_START/FILE_RANGE_END values\n");
            M_FREE(m_pData);
            return -1;
        }

        DbgMsg(__FILE__, __LINE__, "[+] %d bytes readed from \"%ws\"\n", m_dwDataSize, m_lpFontPath);

        if (!m_bResume && (m_dwFontType == FONT_TYPE_OTF || m_dwFontType == FONT_TYPE_TTF))
        {
            OTF_TableByOffset(m_pData, (ULONG)-1);
        }

        if (m_bFixCrcs)
        {
            // write fixed checksums into the original file
            if (DumpToFile(m_lpFontPath, m_pData, m_dwDataSize))
            {
                DbgMsg(__FILE__, __LINE__, "[+] Checksums has been fixed for font file \"%ws\"\n", m_lpFontPath);
            }
        }
        else if (m_bTest)
        {
            // single run with the unchanged font file
            if (DumpToFile(m_TmpFontPath, m_pData, m_dwDataSize))
            {
                FuzzIteration();
            }
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "[+] Fuzzing params:\n\n");

            // print parameters values
            for (int i_n = 0; i_n < sizeof(m_Params) / sizeof(ENGINE_PARAM); i_n++)
            {            
                DbgMsg(__FILE__, __LINE__, " %20ws = 0x%.8x\n", m_Params[i_n].lpName, *(m_Params[i_n].pdwValue));
            }

            DbgMsg(__FILE__, __LINE__, "\n");
            DbgMsg(__FILE__, __LINE__, "[+] Processing cases...\n\n");

            // align buffer size by block size
            m_dwAlignedDataSize = XALIGN_UP(m_dwDataSize, BLOCK_SIZE);

            // allocate output buffer
            if (m_pAlignedData = M_ALLOC(m_dwAlignedDataSize))
            {         
                char *lpszBigBuff = (char *)M_ALLOC(BIG_BUFFER_LENGTH);
                if (lpszBigBuff)
                {
                    FillMemory(lpszBigBuff, BIG_BUFFER_LENGTH, 'A');
                }

                PVOID pBigData = M_ALLOC(m_dwDataSize + BIG_BUFFER_LENGTH);
                
                // for each byte/word/dword of input file...
                for (DWORD i = FILE_RANGE_START; i < FILE_RANGE_END; i += BLOCK_SIZE)
                {                
                    DbgMsg(__FILE__, __LINE__, "Offset=0x%.8x TotalSize=0x%.8x File=%.8x\n", i, m_dwDataSize, m_dwCasesProcessed);

                    POTF_TABLE_HEADER Table = NULL;
                    if (m_dwFontType == FONT_TYPE_OTF || m_dwFontType == FONT_TYPE_TTF)
                    {
                        Table = OTF_TableByOffset(m_pData, i);
                        if (Table == NULL)
                        {
                            // skip OTF/TTF data outside the tables
                            continue;
                        }
                    }                    

                    if (BLOCK_RANGE_N > 0)
                    {
                        // fuze each value with the step size == BLOCK_RANGE_N
                        for (DWORD n = XALIGN_DOWN(BLOCK_RANGE_START, BLOCK_RANGE_N); 
                             n < XALIGN_DOWN(BLOCK_RANGE_END, BLOCK_RANGE_N); 
                             n += BLOCK_RANGE_N)
                        {                            
                            // write plain value
                            WriteVal(i, BLOCK_SIZE, n, n, n);                

                            if (BLOCK_SIZE > 1)
                            {
                                // write randomized value
                                WriteVal(i, BLOCK_SIZE, 
                                    n, 
                                    n + getrand(0, BLOCK_RANGE_N - 1), 
                                    n + getrand(0, BLOCK_RANGE_N - 1)
                                );                                    
                            }                    
                        }
                    }

                    // zero-bytes stuff
                    WriteVal(i, BLOCK_SIZE, 0x00, 0x0000, 0x00000000);                

                    // integer overflow stuff
                    WriteVal(i, BLOCK_SIZE, 0xFF, 0xFFFF, 0xFFFFFFFF);

                    // invalid user-mode pointers
                    WriteVal(i, BLOCK_SIZE, 0x0D, 0x0D0D, 0x0D0D0D0D);

                    if (lpszBigBuff && pBigData)
                    {
                        /**
                         * Write big ASCI data after the each byte.
                         */

                        memcpy(pBigData, m_pData, i);
                        memcpy((PUCHAR)pBigData + i, lpszBigBuff, BIG_BUFFER_LENGTH);
                        memcpy((PUCHAR)pBigData + i + BIG_BUFFER_LENGTH, (PUCHAR)m_pData + i, m_dwDataSize - i);

                        if (m_dwFontType == FONT_TYPE_OTF || m_dwFontType == FONT_TYPE_TTF)
                        {
                            POTF_FILE_HEADER Hdr = (POTF_FILE_HEADER)pBigData;
                            POTF_TABLE_HEADER Table = (POTF_TABLE_HEADER)((PUCHAR)pBigData + sizeof(OTF_FILE_HEADER));
                            POTF_TABLE_HEADER CurrentTable = NULL;

                            for (USHORT t = 0; t < htons(Hdr->numTables); t++)
                            {
                                ULONG Offset = htonl(Table->offset), Length = htonl(Table->length);

                                if (i >= Offset &&
                                    i < Offset + Length)
                                {
                                    // fix OTF/TTF table checksum and length
                                    ULONG Sum = OTF_CalcTableChecksum((ULONG *)((PUCHAR)pBigData + Offset), Length);
                                    
                                    Table->checkSum = htonl(Sum);
                                    Table->length = htonl(Length);
                                    CurrentTable = Table;

                                    break;
                                }

                                Table += 1;
                            }

                            if (CurrentTable)
                            {
                                Table = (POTF_TABLE_HEADER)((PUCHAR)pBigData + sizeof(OTF_FILE_HEADER));

                                for (USHORT t = 0; t < htons(Hdr->numTables); t++)
                                {
                                    ULONG Offset = htonl(Table->offset), Length = htonl(Table->length);

                                    if (Offset > htonl(CurrentTable->offset))
                                    {
                                        // fix offsets of the other tables
                                        Table->offset = htonl(Offset + BIG_BUFFER_LENGTH);
                                    }

                                    Table += 1;
                                }
                            }
                        }

                        if (DumpToFile(m_TmpFontPath, pBigData, m_dwDataSize + BIG_BUFFER_LENGTH))
                        {
                            FuzzIteration();
                            m_dwCasesProcessed++;
                        }
                    }

                    if (m_dwCasesProcessed > MAX_CASES_PER_PROCESS)
                    {
                        TCHAR szSelf[MAX_PATH], szCmdLine[MAX_PATH];
                        GetModuleFileName(GetModuleHandle(NULL), szSelf, MAX_PATH);

                        _stprintf_s(
                            szCmdLine, MAX_PATH, 
                            _T("\"%s\" \"%s\" \"%s\" -BLOCK_SIZE 0x%x -BLOCK_RANGE_START 0x%x -BLOCK_RANGE_END 0x%x -BLOCK_RANGE_N 0x%x -FILE_RANGE_START 0x%x --resume Y"),
                            szSelf, m_lpFontName, m_lpFontPath, BLOCK_SIZE, BLOCK_RANGE_START, BLOCK_RANGE_END, BLOCK_RANGE_N, i
                        );

                        if (m_bNoisy)
                        {
                            _tcscat(szCmdLine, _T(" --noisy Y"));
                        }

                        STARTUPINFO si;
                        PROCESS_INFORMATION pi;

                        ZeroMemory(&pi, sizeof(pi));
                        ZeroMemory(&si, sizeof(si));
                        si.cb = sizeof(si);                            

                        // create a new fuzzer instance
                        if (!CreateProcess(NULL, szCmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
                        {
                            MessageBox(0, _T("CreateProcess() fails"), _T("ERROR"), MB_ICONERROR);
                        }

                        ExitProcess(0);
                    }
                }

                DbgMsg(__FILE__, __LINE__, "Done; %d cases processed\n", m_dwCasesProcessed);

                if (pBigData)
                {
                    M_FREE(pBigData);
                }

                if (lpszBigBuff)
                {
                    M_FREE(lpszBigBuff);
                }

                M_FREE(m_pAlignedData);
            }
        }        

        M_FREE(m_pData);        
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Error while reading input file\n");
    }

end:

    if (m_hWndEvent)
    {
        CloseHandle(m_hWndEvent);
    }

    printf("Press any key to quit...\n");
    _getch();

	return 0;
}
//--------------------------------------------------------------------------------------
// EoF
