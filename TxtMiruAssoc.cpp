// TxtMiruAssoc.cpp : アプリケーションのエントリ ポイントを定義します。
//

#include "stdafx.h"
#include <shlobj.h>
#include <shellapi.h>
#include <locale.h>
#include "stdio.h"
#include "tchar.h"
#include <string>
#include "TxtMiruAssoc.h"

static bool Run(LPCTSTR lpFile)
{
	SHELLEXECUTEINFO si = { sizeof(SHELLEXECUTEINFO) };
	si.fMask  = SEE_MASK_NOCLOSEPROCESS;
	si.lpFile = lpFile;
	si.nShow  = SW_SHOW;
	if(!ShellExecuteEx(&si)){
		return false;
	}
	if (si.hProcess) {
		WaitForSingleObject(si.hProcess, INFINITE);
	}
	SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_FLUSHNOWAIT, nullptr, nullptr);
	return true;
}

namespace std {
	using tstring = basic_string<TCHAR>;
	void replace_str(tstring& str, LPCTSTR src, LPCTSTR dst)
	{
		if(str.empty() || src == nullptr || *src == '\0' || dst == nullptr || lstrcmp(src, dst) == 0){
			return;
		}
		const auto src_len(lstrlen(src));
		const auto dst_len(lstrlen(dst));

		for(tstring::size_type pos(0); (pos = str.find(src, pos, src_len)) != tstring::npos; pos += dst_len){
			str.replace(pos, src_len, dst, dst_len);
		}
	}
};

static bool assocFileType(LPCTSTR filename, LPCTSTR lpExe, LPCTSTR lpWorkDir)
{
	std::tstring path(lpExe);
	std::replace_str(path, _T("/"), _T("\\"));
	std::replace_str(path, _T("\\"), _T("\\\\"));

	std::tstring reg_path(lpWorkDir);
	std::replace_str(reg_path, _T("/"), _T("\\"));
	if(reg_path.size() > 0 && reg_path[reg_path.size()-1] != _T('\\')){
		reg_path += _T("\\");
	}
	reg_path += filename;
	FILE *fp_in = nullptr;
	FILE *fp_out = nullptr;
	auto e = fopen_s(&fp_in, "assoc_regist.reg.org", "r");
	if (e != 0) {
		return false;
	}
	e = _tfopen_s(&fp_out, reg_path.c_str(), _T("w"));
	if (e != 0) {
		fclose(fp_in);
		return false;
	}
	char buf[1024];
	while(fgets(buf, sizeof(buf), fp_in)){
		auto *p1st = buf;
		auto *p = buf;
		for(; *p; ++p){
			if(*p == '~'){
				fwrite(p1st, 1, p-p1st, fp_out);
				_ftprintf(fp_out, _T("%s"), path.c_str());
				p1st = p+1;
			}
		}
		if(p1st != p){
			fwrite(p1st, 1, p-p1st, fp_out);
		}
	}
	fclose(fp_in );
	fclose(fp_out);
	return Run(reg_path.c_str());
}

static bool removeAssocFileType(LPCTSTR filename)
{
	return Run(filename);
}

int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
					   _In_opt_ HINSTANCE hPrevInstance,
					   _In_ LPTSTR    lpCmdLine,
					   _In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	TCHAR szLanguageName[100];
	auto idLocal = GetSystemDefaultLCID();
	::GetLocaleInfo(idLocal, LOCALE_SENGLANGUAGE, szLanguageName, _countof(szLanguageName));
	_tsetlocale(LC_ALL,szLanguageName);

	if(lpCmdLine){
		int nArgs;
		auto *lplpszArgsBegin = CommandLineToArgvW(lpCmdLine, &nArgs);
		if (!lplpszArgsBegin) {
			return 0;
		}
		auto *lplpszArgs = lplpszArgsBegin;
		LPCTSTR lpExeFile = nullptr;
		LPCTSTR lpWorkDir = _T(".\\");
		bool bRemove = false;
		for(int i=0; i<nArgs; ++i, ++lplpszArgs){
			auto lpArgs = *lplpszArgs;
			if(lpArgs[0] == _T('-')){
				if(_tcsncicmp(lpArgs, _T("-A="), 3) == 0){
					lpExeFile = lpArgs + 3;
				} else if(_tcsncicmp(lpArgs, _T("-D="), 3) == 0){
					lpWorkDir = lpArgs + 3;
				} else if(_tcsncicmp(lpArgs, _T("-DEL"), 4) == 0){
					bRemove = true;
				}
			}
		}
		if(bRemove){
			// ソース中に.regファイル名を記述するとVirusチェックに引っかかるのでリソースから取得する
			TCHAR filename[1024];
			LoadString(hInstance, IDS_ASSOC_REMOVE, filename, _countof(filename));
			removeAssocFileType(filename);
		}
		if(lpExeFile){
			TCHAR filename[1024];
			LoadString(hInstance, IDS_ASSOC_REGIST, filename, _countof(filename));
			assocFileType(filename, lpExeFile, lpWorkDir);
		}
		if(lplpszArgsBegin){
			LocalFree(lplpszArgsBegin);
		}
	}

	return 0;
}
