/* u3util.c
 * Utility routines for U3 device support
 *
 * $Id: u3util.c 28594 2009-06-02 11:56:28Z gal $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* Adapted from Microsoft Knowledge Base Article 178893
 *
 * http://support.microsoft.com/?kbid=178893
 *
 * and the U3 Answer 106
 *
 * https://u3.custhelp.com/cgi-bin/u3/php/enduser/std_adp.php?p_faqid=106
 *
 * Indentation logic: 2-space
 */

#include <windows.h>
#include <winreg.h>
#include <shlobj.h>


#define WIRESHARK_ASSOC "u3-wireshark-file"
#define WIRESHARK_DESC  "U3 Wireshark File"

#define SHELL                "\\Shell"
#define SHELL_OPEN           "\\Shell\\open"
#define SHELL_OPEN_COMMAND   "\\Shell\\open\\command"
#define DEFAULT_ICON         "\\DefaultIcon"

#define WINPCAP_KEY          "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\WinPcapInst"
#define WINPCAP_UNINSTALL    "UninstallString"
#define WINPCAP_U3INSTALLED  "U3Installed"  /* indicate the U3 device that installed WinPcap */

#define VCREDIST_PACKAGE     "\\vcredist_x86.exe"
#define VCREDIST_KEY         "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{9A25302D-30C0-39D9-BD6F-21E6EC160475}"
#define VCREDIST_UNINSTALL    "UninstallString"
#define VCREDIST_U3INSTALLED  "U3Installed"  /* indicate the U3 device that installed the redistributable */


#define WINDOWS_VERSION_KEY  "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
#define WINDOWS_VERSION      "CurrentVersion"
#define VISTA_VERSION        "6.0"

#define NPF_KEY              "SYSTEM\\CurrentControlSet\\Service\\NPF"
#define NPF_START            "Start"
#define NPF_START_VAL        2 /* SERVICE_AUTO_START */

#define MY_CAPTURES          "\\My Captures"

#define BUFSIZ              256
#define FILEBUFSIZ          4096

#define ENV_FILENAME        "\\u3_environment.txt"
#define U3UTIL_APPSTART     "\\u3util.exe appStart %1"
#define WIRESHARK_EXE       "\\wireshark.exe"

static char *extensions[] = {
  ".5vw",
  ".acp",
  ".apc",
  ".atc",
  ".bfr",
  ".cap",
  ".enc",
  ".erf",
  ".fdc",
  ".pcap",
  ".pkt",
  ".tpc",
  ".tr1",
  ".trace",
  ".trc",
  ".wpc",
  ".wpz",
  /* and BER encoded files */
  ".cer",
  ".crt",
  ".crl",
  ".p12",
  ".pfx",
  ".asn",
  ".spf",
  ".p7c",
  ".p7s",
  ".p7m",
  NULL
};

static char *environmentvars[] = {
  "U3_DEVICE_SERIAL",
  "U3_DEVICE_PATH",
  "U3_DEVICE_DOCUMENT_PATH",
  "U3_DEVICE_VENDOR",
  "U3_DEVICE_PRODUCT",
  "U3_DEVICE_VENDOR_ID",
  "U3_APP_DATA_PATH",
  "U3_HOST_EXEC_PATH",
  "U3_DEVICE_EXEC_PATH",
  "U3_ENV_VERSION",
  "U3_ENV_LANGUAGE",
  NULL,
};

#define TA_FAILED 0
#define TA_SUCCESS_CLEAN 1
#define TA_SUCCESS_KILL 2
#define TA_SUCCESS_16 3

DWORD TerminateApp( DWORD dwPID, DWORD dwTimeout ) ;
DWORD Terminate16App( DWORD dwPID, DWORD dwThread, WORD w16Task, DWORD dwTimeout );

#include <vdmdbg.h>

typedef struct
{
  DWORD   dwID ;
  DWORD   dwThread ;
} TERMINFO ;

/* Declare Callback Enum Functions. */
BOOL CALLBACK TerminateAppEnum( HWND hwnd, LPARAM lParam ) ;
BOOL CALLBACK Terminate16AppEnum( HWND hwnd, LPARAM lParam ) ;

/*----------------------------------------------------------------
  DWORD TerminateApp( DWORD dwPID, DWORD dwTimeout )

  Purpose:
      Shut down a 32-Bit Process (or 16-bit process under Windows 95)

  Parameters:
      dwPID
         Process ID of the process to shut down.

      dwTimeout
         Wait time in milliseconds before shutting down the process.

   Return Value:
      TA_FAILED - If the shutdown failed.
      TA_SUCCESS_CLEAN - If the process was shutdown using WM_CLOSE.
      TA_SUCCESS_KILL - if the process was shut down with
         TerminateProcess().
      NOTE:  See header for these defines.
   ----------------------------------------------------------------*/

DWORD TerminateApp( DWORD dwPID, DWORD dwTimeout )
{
  HANDLE   hProc ;
  DWORD   dwRet ;

  /* If we can't open the process with PROCESS_TERMINATE rights,
   * then we give up immediately. */
  hProc = OpenProcess(SYNCHRONIZE|PROCESS_TERMINATE, FALSE, dwPID);

  if(hProc == NULL){
    return TA_FAILED;
  }

  if(dwTimeout) {
    /* we are prepared to wait */

    /* TerminateAppEnum() posts WM_CLOSE to all windows whose PID */
    /* matches your process's. */
    EnumWindows((WNDENUMPROC)TerminateAppEnum, (LPARAM) dwPID) ;

    /* Wait on the handle. If it signals, great. If it times out, */
    /* then you kill it. */
    if(WaitForSingleObject(hProc, dwTimeout)!=WAIT_OBJECT_0)
      dwRet=(TerminateProcess(hProc,0)?TA_SUCCESS_KILL:TA_FAILED);
    else
      dwRet = TA_SUCCESS_CLEAN ;
  } else {
    /* we immediately kill the proces */
    dwRet=(TerminateProcess(hProc,0)?TA_SUCCESS_KILL:TA_FAILED);
  }

  CloseHandle(hProc) ;

  return dwRet ;
}

/*----------------------------------------------------------------
  DWORD Terminate16App( DWORD dwPID, DWORD dwThread,
                        WORD w16Task, DWORD dwTimeout )

   Purpose:
      Shut down a Win16 APP.

   Parameters:
      dwPID
         Process ID of the NTVDM in which the 16-bit application is
         running.

      dwThread
         Thread ID of the thread of execution for the 16-bit
         application.

      w16Task
         16-bit task handle for the application.

      dwTimeout
         Wait time in milliseconds before shutting down the task.

   Return Value:
      If successful, returns TA_SUCCESS_16
      If unsuccessful, returns TA_FAILED.
      NOTE:  These values are defined in the header for this
      function.

   NOTE:
      You can get the Win16 task and thread ID through the
      VDMEnumTaskWOW() or the VDMEnumTaskWOWEx() functions.
   ----------------------------------------------------------------*/

DWORD Terminate16App( DWORD dwPID, DWORD dwThread, WORD w16Task, DWORD dwTimeout )
{
  HINSTANCE      hInstLib ;
  TERMINFO      info ;

  /* You will be calling the functions through explicit linking */
  /* so that this code will be binary compatible across */
  /* Win32 platforms. */
  BOOL (WINAPI *lpfVDMTerminateTaskWOW)(DWORD dwProcessId, WORD htask) ;

  hInstLib = LoadLibraryA( "VDMDBG.DLL" ) ;
  if( hInstLib == NULL )
    return TA_FAILED ;

  /* Get procedure addresses. */
  lpfVDMTerminateTaskWOW = (BOOL (WINAPI *)(DWORD, WORD ))
    GetProcAddress( hInstLib, "VDMTerminateTaskWOW" ) ;

  if( lpfVDMTerminateTaskWOW == NULL )
    {
      FreeLibrary( hInstLib ) ;
      return TA_FAILED ;
    }

  /* Post a WM_CLOSE to all windows that match the ID and the */
  /* thread. */
  info.dwID = dwPID ;
  info.dwThread = dwThread ;
  EnumWindows((WNDENUMPROC)Terminate16AppEnum, (LPARAM) &info) ;

  /* Wait. */
  Sleep( dwTimeout ) ;

  /* Then terminate. */
  lpfVDMTerminateTaskWOW(dwPID, w16Task) ;

  FreeLibrary( hInstLib ) ;
  return TA_SUCCESS_16 ;
}

BOOL CALLBACK TerminateAppEnum( HWND hwnd, LPARAM lParam )
{
  DWORD dwID ;

  GetWindowThreadProcessId(hwnd, &dwID) ;

  if(dwID == (DWORD)lParam)
    {
      PostMessage(hwnd, WM_CLOSE, 0, 0) ;
    }

  return TRUE ;
}

BOOL CALLBACK Terminate16AppEnum( HWND hwnd, LPARAM lParam )
{
  DWORD      dwID ;
  DWORD      dwThread ;
  TERMINFO   *termInfo ;

  termInfo = (TERMINFO *)lParam ;

  dwThread = GetWindowThreadProcessId(hwnd, &dwID) ;

  if(dwID == termInfo->dwID && termInfo->dwThread == dwThread )
    {
      PostMessage(hwnd, WM_CLOSE, 0, 0) ;
    }

  return TRUE ;
}


void ExecuteAndWait(char *buffer)
{
  STARTUPINFO         si;
  PROCESS_INFORMATION pi;

  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&pi, sizeof(pi));

  if(CreateProcess(NULL, buffer, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
    /* wait for the uninstall to finish */
    (void) WaitForSingleObject(pi.hProcess, INFINITE);

    (void)CloseHandle(pi.hProcess);
    (void)CloseHandle(pi.hThread);

  }
}

void uninstall(char *regkey, char *u3installed, char *uninstall)
{
  char buffer[BUFSIZ];
  int buflen = BUFSIZ;
  char *u3_device_serial;
  char reg_key[BUFSIZ];
  HKEY  key;

  /* UNINSTALL ONLY IF WE INSTALLED IT */
  buffer[0] = '\0';

  /* see if it is installed */
  if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, regkey, 0, (KEY_READ | KEY_WRITE), &key) == ERROR_SUCCESS) {

    buflen = BUFSIZ;

    /* see if a U3 device installed the package */
    if(RegQueryValueEx(key, u3installed, NULL, NULL, buffer, &buflen) == ERROR_SUCCESS) {

      u3_device_serial = getenv("U3_DEVICE_SERIAL");

      /* see if this U3 device installed the package */
      if(!strncmp(buffer, u3_device_serial, strlen(u3_device_serial) + 1)) {

	buffer[0] = '"';
	buflen = BUFSIZ-1;
	/* we installed WinPcap - we should now uninstall it - read the uninstall string */
	(void) RegQueryValueEx(key, uninstall, NULL, NULL, &buffer[1], &buflen);


	if(!strncmp(buffer, "\"MsiExec.exe", 12)) {
	  /* run msiexec.exe quietly */
	  strncat(buffer, " /qn", 5);

	}

	strncat(buffer, "\"", 2); /* close the quotes */

	/* delete our value */
	RegDeleteValue(key, u3installed);

      } else {
	/* empty the buffer */
	buffer[0] = '\0';
      }
    }

    RegCloseKey(key);
  }

  if(*buffer) {
#if 0
    MessageBox(NULL,
	       buffer,
	       "Uninstall",
	       MB_YESNO|MB_TOPMOST|MB_ICONQUESTION);
#endif 

    /* we have an uninstall string */
    ExecuteAndWait(buffer);
  }
}


void winpcap_auto_start()
{

  HKEY  key;
  HKEY  npfKey;
  char buffer[BUFSIZ+1];
  int  buflen = 0;
  DWORD startVal = NPF_START_VAL;
  
  if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, WINDOWS_VERSION_KEY, 0, (KEY_READ), &key) == ERROR_SUCCESS) {

    if(RegQueryValueEx(key, WINDOWS_VERSION, NULL, NULL, buffer, &buflen) == ERROR_SUCCESS) {

      if(!strcmp(buffer, VISTA_VERSION)) {
	/* this is Vista - set the autostart */
	/* if installation was successful this key will now exist */
	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, NPF_KEY, 0, (KEY_READ | KEY_WRITE), &npfKey) == ERROR_SUCCESS) {

	  (void)RegSetValueEx(npfKey, NPF_START, 0, REG_DWORD, (BYTE*)&startVal, sizeof(DWORD));
	  
	  RegCloseKey(npfKey);

	}
      }
    }
    RegCloseKey(key);
  }
}


void app_start(int argc, char *argv[])
{
  char *u3hostexecpath;
  char *envvar;
  char *end;
  char buffer[BUFSIZ+1];
  char inBuffer[FILEBUFSIZ+1];
  HANDLE *file;
  DWORD numRead = 0;
  int i;

  /* read any environment variables that may be set as we are probably running this from a file association */

  buffer[0] = '\0';
  strncat(buffer, argv[0], strlen(argv[0]) + 1);

  /* truncate at last \\ */
  if(end = strrchr(buffer, '\\'))
    *end = '\0';

  strncat(buffer, ENV_FILENAME, strlen(ENV_FILENAME) + 1);

  /* open the file */
  if((file = CreateFile(buffer, FILE_READ_DATA, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE) {

    /* read the whole file in in one go */
    if(ReadFile(file, &inBuffer, FILEBUFSIZ, &numRead, NULL) != 0) {
      /* we were successful - parse the lines */
      inBuffer[numRead] = '\0'; /* null terminate the data */

      envvar = inBuffer;

      while(end = strchr(envvar, '\n')) {
	/* we have a line */
	*end++ = '\0';

	_putenv(envvar);

	/* point the next envar to the end */
	envvar = end;
      }
    }

    /* close the file */
    CloseHandle(file);

  }

  /* exec wireshark */
  if((u3hostexecpath = getenv("U3_HOST_EXEC_PATH")) != NULL) {

    buffer[0] = '\0';
    strncat(buffer, u3hostexecpath, strlen(u3hostexecpath) + 1);
    strncat(buffer, WIRESHARK_EXE, strlen(WIRESHARK_EXE) + 1);

    /* copy the remaining arguments across */
    for(i = 2; i < argc; i++) {
      strncat(buffer, " ", 2);
      strncat(buffer, argv[i], strlen(argv[i]) + 1);
    }

    ExecuteAndWait(buffer);

  }

}


void app_stop(DWORD timeOut)
{
  DWORD  pid = 0;
  HANDLE hFind = INVALID_HANDLE_VALUE;
  WIN32_FIND_DATA find_file_data;
  DWORD dwError;
  char *u3_host_exec_path;
  char dir_spec[MAX_PATH+1];
  char file_name[MAX_PATH+1];

  u3_host_exec_path = getenv("U3_HOST_EXEC_PATH");

  strncpy(dir_spec, u3_host_exec_path, strlen(u3_host_exec_path) + 1);
  strncat(dir_spec, "\\*.pid", 7);

  hFind = FindFirstFile(dir_spec, &find_file_data);

  if(hFind != INVALID_HANDLE_VALUE) {

    do {

      pid = (DWORD)atoi(find_file_data.cFileName);

      if(pid)
	TerminateApp(pid, timeOut);

      strncpy(file_name, u3_host_exec_path, strlen(u3_host_exec_path) + 1);
      strncat(file_name, "\\", 2);
      strncat(file_name, find_file_data.cFileName, strlen(find_file_data.cFileName) + 1);

      DeleteFile(TEXT(file_name));

    } while(FindNextFile(hFind, &find_file_data) != 0);

    FindClose(hFind);

  }

}

/* associate

Associate an filetype (extension) with the U3 Wireshark if it doesn't already have an association

*/

void associate(char *extension)
{
  HKEY key;
  DWORD disposition;
  char buffer[BUFSIZ];
  int  buflen = BUFSIZ;

  buffer[0] = '\0';

  /* open the HKCR  extension  key*/
  if(RegCreateKeyEx(HKEY_CLASSES_ROOT, extension, 0, NULL, 0, (KEY_READ | KEY_WRITE), NULL, &key, &disposition) == ERROR_SUCCESS) {

    /* we could look at the disposition - but we don't bother */
    if((RegQueryValueEx(key, "", NULL, NULL, buffer, &buflen) != ERROR_SUCCESS) || (buffer[0] == '\0')) {

      (void)RegSetValueEx(key, "", 0, REG_SZ, WIRESHARK_ASSOC, strlen(WIRESHARK_ASSOC) + 1);
    }

    RegCloseKey(key);
  }

}

BOOL save_environment()
{
  char **envptr;
  char *envval;
  HANDLE *file;
  char buffer[BUFSIZ+1];
  DWORD  buflen;
  DWORD  numWritten;
  BOOL   retval = FALSE;

  envval = getenv("U3_HOST_EXEC_PATH");

  buffer[0] = '\0';
  strncat(buffer, envval, strlen(envval) + 1);
  strncat(buffer, ENV_FILENAME, strlen(ENV_FILENAME) + 1);

  /* open the file */
  if((file = CreateFile(buffer, FILE_WRITE_DATA, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE) {

    for(envptr = environmentvars; *envptr; envptr++) {

      if(envval = getenv(*envptr)) {
	/* write it out */

	buffer[0] = '\0';
	strncat(buffer, *envptr, strlen(*envptr) + 1);
	strncat(buffer, "=", 2);
	strncat(buffer, envval, strlen(envval) + 1);
	strncat(buffer, "\n", 2);

	buflen = strlen(buffer);

	WriteFile(file, buffer, buflen, &numWritten, NULL);
      }

    }

    /* close the file */
    CloseHandle(file);

    retval = TRUE;

  }

  return retval;

}


/* disassociate

Remove any file types that are associated with the U3 Wireshark (which is being removed)

*/


void disassociate(char *extension)
{
  HKEY key;
  DWORD disposition;
  char buffer[BUFSIZ];
  int  buflen = BUFSIZ;
  boolean delete_key = FALSE;

  buffer[0] = '\0';

  /* open the HKCR  extension  key*/
  if(RegOpenKeyEx(HKEY_CLASSES_ROOT, extension, 0, (KEY_READ | KEY_WRITE), &key) == ERROR_SUCCESS) {

    if(RegQueryValueEx(key, "", NULL, NULL, buffer, &buflen) == ERROR_SUCCESS) {

      if(!strncmp(buffer, WIRESHARK_ASSOC, strlen(WIRESHARK_ASSOC) + 1))
	delete_key = TRUE;
    }

    RegCloseKey(key);
  }

  if(delete_key)
    RegDeleteKey(HKEY_CLASSES_ROOT, extension);
}

/* host_configure

Configure the host for the U3 Wireshark. This involves:
1) registering the U3 Wireshark with capture file types
2) installing WinPcap if not already installed
3) create a "My Captures" folder on the U3 device if it doesn't already exist
*/

void host_configure(void)
{
  char **pext;
  HKEY  key;
  DWORD disposition;
  char *u3_host_exec_path;
  char *u3_device_exec_path;
  char *u3_device_serial;
  char *u3_device_document_path;
  char wireshark_path[MAX_PATH+1];
  char winpcap_path[MAX_PATH+1];
  char vcredist_path[MAX_PATH+1];
  char my_captures_path[MAX_PATH+1];
  char reg_key[BUFSIZ];
  char buffer[BUFSIZ];
  int  buflen = BUFSIZ;
  boolean hasWinPcap = FALSE;
  boolean hasRedist = FALSE;

  /* CREATE THE U3 Wireshark TYPE */
  if(RegCreateKeyEx(HKEY_CLASSES_ROOT, WIRESHARK_ASSOC, 0, NULL, 0,
		    (KEY_READ | KEY_WRITE), NULL, &key, &disposition) == ERROR_SUCCESS) {

    (void)RegSetValueEx(key, "", 0, REG_SZ, WIRESHARK_DESC, strlen(WIRESHARK_DESC) + 1);

    RegCloseKey(key);
  }

  /* compute the U3 path to wireshark */
  u3_host_exec_path = getenv("U3_HOST_EXEC_PATH");
  strncpy(wireshark_path, u3_host_exec_path, strlen(u3_host_exec_path) + 1);
  strncat(wireshark_path, U3UTIL_APPSTART, strlen(U3UTIL_APPSTART) + 1);

  strncpy(reg_key, WIRESHARK_ASSOC, strlen(WIRESHARK_ASSOC) + 1);
  strncat(reg_key, SHELL_OPEN_COMMAND, strlen(SHELL_OPEN_COMMAND) + 1);

  /* associate the application */
  if(RegCreateKeyEx(HKEY_CLASSES_ROOT, reg_key, 0, NULL, 0,
		    (KEY_READ | KEY_WRITE), NULL, &key, &disposition) == ERROR_SUCCESS) {
    (void)RegSetValueEx(key, "", 0, REG_SZ, wireshark_path, strlen(wireshark_path) + 1);

    RegCloseKey(key);

  }

  /* associate the icon */
  strncpy(reg_key, WIRESHARK_ASSOC, strlen(WIRESHARK_ASSOC) + 1);
  strncat(reg_key, DEFAULT_ICON, strlen(DEFAULT_ICON) + 1);

  /* the icon is in the exe */
  strncpy(wireshark_path, u3_host_exec_path, strlen(u3_host_exec_path) + 1);
  strncat(wireshark_path, WIRESHARK_EXE, strlen(WIRESHARK_EXE) + 1);
  strncat(wireshark_path, ",1", 3);

  /* associate the application */
  if(RegCreateKeyEx(HKEY_CLASSES_ROOT, reg_key, 0, NULL, 0,
		    (KEY_READ | KEY_WRITE), NULL, &key, &disposition) == ERROR_SUCCESS) {

    (void)RegSetValueEx(key, "", 0, REG_SZ, wireshark_path, strlen(wireshark_path) + 1);

    RegCloseKey(key);
  }

  /* CREATE THE FILE ASSOCIATIONS */

  for(pext = extensions; *pext; pext++)
    associate(*pext);

  /* update icons */
  SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, 0, 0);

  /* START WINPCAP INSTALLATION IF NOT ALREADY INSTALLED */

  if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, WINPCAP_KEY, 0, (KEY_READ), &key) == ERROR_SUCCESS) {

    if(RegQueryValueEx(key, WINPCAP_UNINSTALL, NULL, NULL, buffer, &buflen) == ERROR_SUCCESS) {

      if(buffer[0] != '\0')
	hasWinPcap = TRUE;
    }

    RegCloseKey(key);
  }

  if(!hasWinPcap &&
     (MessageBox(NULL,
		 TEXT("If you want to capture packets from the network you will need to install WinPcap.\nIt will be uninstalled when you remove your U3 device.\n\nDo you want to install WinPcap?"),
		 TEXT("U3 Wireshark: Install WinPcap?"),
		 MB_YESNO|MB_TOPMOST|MB_ICONQUESTION) == IDYES)) {

    /* compute the U3 path to the WinPcap installation package - it stays on the device */
    u3_device_exec_path = getenv("U3_DEVICE_EXEC_PATH");
    strncpy(winpcap_path, "\"", 2);
    strncat(winpcap_path, u3_device_exec_path, strlen(u3_device_exec_path) + 1);
    strncat(winpcap_path, WINPCAP_PACKAGE, strlen(WINPCAP_PACKAGE) + 1);
    strncat(winpcap_path, "\"", 2);

    ExecuteAndWait(winpcap_path);

    /* if installation was successful this key will now exist */
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, WINPCAP_KEY, 0, (KEY_READ | KEY_WRITE), &key) == ERROR_SUCCESS) {

      u3_device_serial = getenv("U3_DEVICE_SERIAL");

      (void)RegSetValueEx(key, WINPCAP_U3INSTALLED, 0, REG_SZ, u3_device_serial, strlen(u3_device_serial) + 1);

      winpcap_auto_start();

    }
  }

  /* START VCREDIST INSTALLATION IF NOT ALREADY INSTALLED */

  if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, VCREDIST_KEY, 0, (KEY_READ), &key) == ERROR_SUCCESS) {

    buflen = BUFSIZ;

    if(RegQueryValueEx(key, VCREDIST_UNINSTALL, NULL, NULL, buffer, &buflen) == ERROR_SUCCESS) {

      if(buffer[0] != '\0')
	hasRedist = TRUE;
    }

    RegCloseKey(key);

  } 

  if(!hasRedist) {

    /* compute the U3 path to the Visual C++  redistributables package - it stays on the device */
    u3_device_exec_path = getenv("U3_DEVICE_EXEC_PATH");
    strncpy(vcredist_path, "\"", 2);
    strncat(vcredist_path, u3_device_exec_path, strlen(u3_device_exec_path) + 1);
    strncat(vcredist_path, VCREDIST_PACKAGE, strlen(VCREDIST_PACKAGE) + 1);
    strncat(vcredist_path, "\" /q", 5); /* do things quietly */

    ExecuteAndWait(vcredist_path);

    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, VCREDIST_KEY, 0, (KEY_READ | KEY_WRITE), &key) == ERROR_SUCCESS) {

      u3_device_serial = getenv("U3_DEVICE_SERIAL");

      (void)RegSetValueEx(key, VCREDIST_U3INSTALLED, 0, REG_SZ, u3_device_serial, strlen(u3_device_serial) + 1);

    }
  }


  /* CREATE THE "My Captures" FOLDER IF IT DOESN'T ALREADY EXIST */

  u3_device_document_path = getenv("U3_DEVICE_DOCUMENT_PATH");
  strncpy(my_captures_path, u3_device_document_path, strlen(u3_device_document_path) + 1);
  strncat(my_captures_path, MY_CAPTURES, strlen(MY_CAPTURES) + 1);

  /* don't care if it succeeds or fails */
  (void) CreateDirectory(my_captures_path, NULL);

  /* Save the environment so we can use it in the file assocation */
  save_environment();
}

/* host_cleanup

Remove any references to the U3 Wireshark from the host. This involves:
1) Removing the U3 Wireshark file type associations
2) Uninstalling WinPcap if we installed it.
   If the user cancels the uninstallation of WinPcap, we will not try and remove it again.

*/

void host_clean_up(void)
{
  DWORD disposition;
  char **pext;
  char *u3_device_serial;
  char reg_key[BUFSIZ];

  /* the device has been removed -
     just close the application as quickly as possible */

  app_stop(0);

  /* DELETE THE FILE ASSOCIATIONS */
  for(pext = extensions; *pext; pext++)
    disassociate(*pext);

  /* update icons */
  SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, 0, 0);

  /* DELETE THE U3 Wireshark TYPE */
  strncpy(reg_key, WIRESHARK_ASSOC, strlen(WIRESHARK_ASSOC) + 1);
  strncat(reg_key, SHELL_OPEN_COMMAND, strlen(SHELL_OPEN_COMMAND) + 1);

  RegDeleteKey(HKEY_CLASSES_ROOT, reg_key);

  /* delete the open key */
  strncpy(reg_key, WIRESHARK_ASSOC, strlen(WIRESHARK_ASSOC) + 1);
  strncat(reg_key, SHELL_OPEN, strlen(SHELL_OPEN) + 1);

  RegDeleteKey(HKEY_CLASSES_ROOT, reg_key);

  /* delete the shell key */
  strncpy(reg_key, WIRESHARK_ASSOC, strlen(WIRESHARK_ASSOC) + 1);
  strncat(reg_key, SHELL, strlen(SHELL) + 1);

  RegDeleteKey(HKEY_CLASSES_ROOT, reg_key);

  /* delete the icon key */
  strncpy(reg_key, WIRESHARK_ASSOC, strlen(WIRESHARK_ASSOC) + 1);
  strncat(reg_key, DEFAULT_ICON, strlen(DEFAULT_ICON) + 1);

  RegDeleteKey(HKEY_CLASSES_ROOT, reg_key);

  /* finally delete the toplevel key */
  RegDeleteKey(HKEY_CLASSES_ROOT, WIRESHARK_ASSOC);

  uninstall(WINPCAP_KEY, WINPCAP_U3INSTALLED, WINPCAP_UNINSTALL);
  uninstall(VCREDIST_KEY, VCREDIST_U3INSTALLED, VCREDIST_UNINSTALL);

}

main(int argc, char *argv[])
{
  DWORD time_out = 0;
  char *u3_is_device_available;
#if 0 
  char **envptr;
  char *envval;
# endif 
  u3_is_device_available = getenv("U3_IS_DEVICE_AVAILABLE");

  if(u3_is_device_available && !strncmp(u3_is_device_available, "true", 4))
    /* the device is available - wait for user to respond to any dialogs */
    time_out = INFINITE;
#if 0
  for(envptr = environmentvars; *envptr; envptr++) {
    envval = getenv(*envptr);

    MessageBox(NULL,
	       envval ? envval : "NULL",
	       *envptr,
	       MB_YESNO|MB_TOPMOST|MB_ICONQUESTION);
  }
#endif

  if(argc > 1) {

    if(!strncmp(argv[1], "hostConfigure", 13))
      host_configure();
    else if(!strncmp(argv[1], "appStart", 9))
      app_start(argc, argv);
    else if(!strncmp(argv[1], "appStop", 8))
      app_stop(time_out);
    else if(!strncmp(argv[1], "hostCleanUp", 11))
      host_clean_up();

  }

  exit(0);
}
