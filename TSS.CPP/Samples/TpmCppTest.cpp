/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

#include "stdafx.h"
#include "Tpm2.h"

#include "Samples.h"

#if __linux__
#define TCHAR   char 
#define _tcscmp strcmp
#define _T(s)   s
#endif

using namespace std;
using namespace TpmCpp;

bool UseSimulator = true;
std::string outFilePath;
std::string parentPassword;
std::string keyPassword;

static bool
CmdLine_IsOpt(
    const TCHAR* opt,               // Command line parameter to check
    const TCHAR* optFull,           // Expected full name
    const TCHAR* optShort = nullptr // Expected short (single letter) name
    )
{
    return 0 == _tcscmp(opt, optFull)
        || (   (opt[0] == '/' || opt[0] == '-')
            && (   0 == _tcscmp(opt + 1, optFull)
                || (optShort && opt[1] == optShort[0] && opt[2] == 0)
                || (opt[0] == '-' && opt[1] == '-' && 0 == _tcscmp(opt + 2, optFull))));
}

void CmdLine_Help(ostream& ostr)
{
    ostr << "One command line option can be specified." << endl
        << "An option can be in the short form (one letter preceded with '-' or '/')" << endl
        << "or in the full form (preceded with '--' or without any sigil)." << endl
        << "Supported options:" << endl
        << "   -h (help|?) - print this message" << endl
        << "   -s (sim) - use locally running TPM simulator" << endl
        << "   -t (tbs|sys) - use system TPM" << endl
        << "   -o (out) - output file" << endl
        << "   -w (parentpw) - specify parent password" << endl
        << "   -p (pw) - use child key password" << endl;
}

int CmdLine_Parse(int argc, TCHAR *argv[])
{
    if (argc > 8)
    {
        cerr << "Too many command line option can be specified." << endl;
        CmdLine_Help(cerr);
        return -1;
    }

    if (argc == 1 ||
        CmdLine_IsOpt(argv[1], _T("help"), _T("h")) ||
        CmdLine_IsOpt(argv[1], _T("?"), _T("?")))
    {
        CmdLine_Help(cout);
        return 1;
    }

    if (argc < 4)
    {
        cerr << "Insufficient command line options specified." << endl;
        CmdLine_Help(cerr);
        return -1;
    }

    int invalidOptPosition = -1;

    if (CmdLine_IsOpt(argv[1], _T("sim"), _T("s")))
    {
        UseSimulator = true;
    }
    else if (CmdLine_IsOpt(argv[1], _T("tbs"), _T("t")) ||
        CmdLine_IsOpt(argv[1], _T("sys")))
    {
        UseSimulator = false;
    }
    else
    {
        invalidOptPosition = 1;
    }

    if (argc > 3)
    {
        if (invalidOptPosition < 0)
        {
            if (CmdLine_IsOpt(argv[2], _T("out"), _T("o")))
            {
                outFilePath.assign(argv[3]);
            }
            else
            {
                invalidOptPosition = 2;
            }
        }
    }

    bool parentpwFound = false;
    bool keypwFound = false;
    if (argc > 5) {
        if (invalidOptPosition < 0) {
            if (CmdLine_IsOpt(argv[4], _T("parentpw"), _T("a"))) {
                parentPassword = std::string((char*)argv[5]);
                parentpwFound = true;
            }
            else if (CmdLine_IsOpt(argv[4], _T("pw"), _T("p"))) {
                keyPassword = std::string((char*)argv[5]);
                keypwFound = true;
            } else {
                invalidOptPosition = 4;
            }
        }
    }

    if (argc > 7) {
        if (invalidOptPosition < 0) {
            if (!parentpwFound) {
                if (CmdLine_IsOpt(argv[6], _T("parentpw"), _T("a"))) {
                    parentPassword = std::string((char*)argv[7]);
                    parentpwFound = true;
                }
            }

            if (!keypwFound) {
                if (CmdLine_IsOpt(argv[6], _T("pw"), _T("p"))) {
                    keyPassword = std::string((char*)argv[7]);
                    keypwFound = true;
                }
            }

            if (!parentpwFound || !keypwFound) {
                invalidOptPosition = 6;
            }
        }
    }

    if (invalidOptPosition > 0) {
        cerr << "Unrecognized command line option: '" << argv[invalidOptPosition] << "'" << endl;
        CmdLine_Help(cerr);
        return -2;
    }
    return 0;
}


#ifdef WIN32
_CrtMemState MemState;

int _tmain(int argc, TCHAR *argv[])
{
    _CrtMemCheckpoint(&MemState);

#elif __linux__

int main(int argc, char *argv[])
{
#endif

    int res = CmdLine_Parse(argc, argv);
    if (res != 0)
        return res;

    try {
        Samples s;
        s.RunCreatePrimaryKey(outFilePath, parentPassword, keyPassword);
    }
    catch (const runtime_error& exc) {
        cerr << "TpmCppTester: " << exc.what() << "\nExiting...\n";
    }

#ifdef WIN32
    HMODULE h = LoadLibrary(_T("TSS.CPP.dll"));
    _ASSERT(h != NULL);

    BOOL ok = FreeLibrary(h);
    _ASSERT(ok);
    _CrtMemDumpAllObjectsSince(&MemState);
#endif

    return 0;
}
