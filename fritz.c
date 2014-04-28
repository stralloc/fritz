/*
	Diese Datei ist Teil von fritz.

	fritz ist Freie Software: Sie können es unter den Bedingungen
	der GNU General Public License, wie von der Free Software Foundation,
	Version 3 der Lizenz oder (nach Ihrer Option) jeder späteren
	veröffentlichten Version, weiterverbreiten und/oder modifizieren.

	fritz wird in der Hoffnung, dass es nützlich sein wird, aber
	OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
	Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FÜR EINEN BESTIMMTEN ZWECK.
	Siehe die GNU General Public License für weitere Details.

	Sie sollten eine Kopie der GNU General Public License zusammen mit diesem
	Programm erhalten haben. Wenn nicht, siehe <http://www.gnu.org/licenses/>
*/

#include <windows.h>
#include <wincrypt.h>
#include <process.h> // thread handling with _beginthread, _endthread
/*
"A thread in an executable that is linked to the static C run-time library (CRT) should use _beginthread and _endthread for thread management rather than CreateThread and ExitThread." http://msdn.microsoft.com/en-us/library/windows/desktop/ms682659(v=vs.85).aspx
*/

#include <stdio.h>
#include <Commctrl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <time.h>

#include "rsrc.inc"
#include "base64.h"
#include "stralloc.h"

#include "selftests.h"

#ifndef WITH_LIBSODIUM
	#include "crypto_box.h"
	#include "crypto_hashblocks_sha256.h"
	#include "crypto_hash_sha256.h"
	#include "crypto_stream_xsalsa20.h"
#else
	#include "sodium.h"
#endif
	
#define DIALOG_TITLE "Fritz v6"
#define URL "http://xn--njr-tna.de/Projekte/fritz.html?from=v6"

#define MAX_NAME 128
#define MAX_INPUT 131068
#define MAX_INPUT_BASE64  174861 // we need more space for base64 encrypted text
#define FILE_BLOCK 32767
#define KEY64_SIZE 45
#define DROP_DIALOG_SIZE 100000
#define MAX_PASSWORD 128

// http://stackoverflow.com/questions/727918/what-happens-when-gettickcount-wraps
#define TICKS_DIFF(prev, cur) ((cur) >= (prev)) ? ((cur)-(prev)) : ((0xFFFFFFFF-(prev))+(cur)+1)

#define ENCRYPT 0
#define DECRYPT 1
static struct crypt_file {
	HWND window;
	HWND progress_window;
	char path[MAX_PATH];
	int type;
	size_t size;
} cryptfile;

static struct crypt_message {
	HWND window;
	int type;
} cryptmessage;

static stralloc sabuf;
static stralloc sabuf64;
HICON hicon;

HCRYPTPROV	hCryptProv;

#define THREAD_OFF 1
#define THREAD_RUN 2
#define THREAD_DYING 3
static unsigned int thread_status;

static unsigned char key_file_hash[crypto_hash_sha256_BYTES];
static unsigned char password_hash[crypto_hash_sha256_BYTES];

#define MIN_PASSWORD_LEN 10

// each sign must be present MIN_COUNT times 
#define MIN_COUNT 2

#define PASSWORD_OK 0
#define PASSWORD_TO_SHORT 1
#define PASSWORD_LOWER_CASE 2
#define PASSWORD_UPPER_CASE 3
#define PASSWORD_NUMBERS 4
#define PASSWORD_SPECIAL_CHARACTER 5
#define PASSWORD_NOT_EQUAL 6
#define PASSWORD_NOT_CHANGED 7

static unsigned int check_passwords(const char *password1,const char *password2);
static void copyToClipboard(const char *str);
static unsigned long RefreshKeyList(HWND window, int box);

void thread_hash_file(void *param);
void thread_crypt_file(void *param);
void thread_crypt_message(void *param);

INT_PTR CALLBACK DialogCreatePassword(HWND window, UINT uMsg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DialogManageKeys(HWND window, UINT uMsg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DialogProgressFile(HWND window, UINT uMsg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DialogMain(HWND window, UINT uMsg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DialogGetPassword(HWND window, UINT uMsg, WPARAM wParam, LPARAM lParam);

#ifndef BUFSIZ
	#define BUFSIZ 4048
#endif

static FILE * secure_fopen(const char *path, const char *mode, char *buf, size_t buf_len) {
	FILE *fd = fopen(path,mode);
	if(fd && buf && buf_len>0) {
		setvbuf(fd, buf, _IOFBF, buf_len); 
		return fd;
	}
	if(fd) fclose(fd);

	return NULL;
}

static void secure_fclose(FILE *fd, char *buf, size_t buf_len) {
	
	if(fd) fclose(fd);
	if(buf && buf_len>0) rand_mem(buf,buf_len);

	return;
}

void secure_randombytes(unsigned char *x,size_t xlen) {

	size_t i;
	MEMORYSTATUS memstat;

	if(!CryptGenRandom(hCryptProv,xlen,(unsigned char*)x)) {

		memstat.dwLength = sizeof (memstat);
		GlobalMemoryStatus(&memstat);

		srand((unsigned int)GetTickCount()^time(NULL)
			^memstat.dwMemoryLoad
			^memstat.dwTotalPhys
			^memstat.dwAvailPhys
			^memstat.dwTotalPageFile
			^memstat.dwAvailPageFile
			^memstat.dwTotalVirtual
			^memstat.dwAvailVirtual);

		for(i=0;i<xlen;++i) {
			x[i]=rand()%256;
		}
	}
}

static unsigned int check_passwords(const char *password1,const char *password2) {

	char little_chars[] = "abcdefghijklmnopqrstuvwxyz";
	unsigned int little_chars_count;
	
	char big_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	unsigned int big_chars_count;
	
	char numbers[] = "0123456789";
	unsigned int numbers_count;
	
	char special_chars[] = "°^!\"§²³{[]}\\$%&/()=?`´*~+'#;><|,µ.:-_öäüß";
	unsigned int special_chars_count;
	
	size_t i, password1_len = strlen(password1);
	size_t j, password2_len = strlen(password2);

	unsigned char hash[crypto_hash_sha256_BYTES];
	
	if(password1_len<MIN_PASSWORD_LEN) {
		return PASSWORD_TO_SHORT;
	}

	little_chars_count = big_chars_count = numbers_count = special_chars_count = 0;
	for(i=0;i<password1_len;++i) {
	
		// little_chars
		if(little_chars_count<MIN_COUNT) {
			for(j=0;j<sizeof(little_chars);++j) {
				if(password1[i]==little_chars[j]) {
					if(++little_chars_count>=MIN_COUNT) break;
				}
			}
		}
		
		// big_chars
		if(big_chars_count<MIN_COUNT) {
			for(j=0;j<sizeof(big_chars);++j) {
				if(password1[i]==big_chars[j]) {
					if(++big_chars_count>=MIN_COUNT) break;
				}
			}
		}
		
		// numbers
		if(numbers_count<MIN_COUNT) {
			for(j=0;j<sizeof(numbers);++j) {
				if(password1[i]==numbers[j]) {
					if(++numbers_count>=MIN_COUNT) break;
				}
			}
		}
		
		// special_chars
		if(special_chars_count<MIN_COUNT) {
			for(j=0;j<sizeof(special_chars);++j) {
				if(password1[i]==special_chars[j]) {
					if(++special_chars_count>=MIN_COUNT) break;
				}
			}
		}
	}
	
	if(little_chars_count<MIN_COUNT) {
		return PASSWORD_LOWER_CASE;
	}
	
	if(big_chars_count<MIN_COUNT) {
		return PASSWORD_UPPER_CASE;
	}
	
	if(numbers_count<MIN_COUNT) {
		return PASSWORD_NUMBERS;
	}
	
	if(special_chars_count<MIN_COUNT) {
		return PASSWORD_SPECIAL_CHARACTER;
	}
	
	crypto_hash_sha256(hash,password1,password1_len);
	if(byte_equal_notimingattack(hash,crypto_hash_sha256_BYTES,password_hash)) {
		return PASSWORD_NOT_CHANGED;
	}

	if(password1_len!=password2_len || !byte_equal_notimingattack(password1,password1_len,password2)) {
		return PASSWORD_NOT_EQUAL;
	}

	return PASSWORD_OK;
}

static void copyToClipboard(const char *str) {

	char *pchData;
	size_t len = strlen(str);
	HGLOBAL hClipboardData = NULL;

	if(!OpenClipboard(NULL))
		return;
 
	EmptyClipboard();

	hClipboardData = GlobalAlloc(GMEM_DDESHARE, len+1);
	if(hClipboardData==NULL) {
		CloseClipboard();
		return;
	}
	
	pchData = (char*)GlobalLock(hClipboardData);
	byte_copy(pchData,len,str);
	GlobalUnlock(hClipboardData);
	
	SetClipboardData(CF_TEXT, hClipboardData);
	CloseClipboard();
}

static unsigned long RefreshKeyList(HWND window, int box) {
	WIN32_FIND_DATAA ffd;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	char pfad[MAX_PATH];
	size_t len;
	int have_priv, have_pub;
	unsigned long entries = 0;
	unsigned long sel;
	
	sel = SendDlgItemMessageA(window, box, CB_GETCURSEL, 0, 0);

	SendDlgItemMessageA(window, box, CB_RESETCONTENT, 0, 0);

	GetCurrentDirectoryA(MAX_PATH,pfad);
	strncat(pfad,"\\*.key",MAX_PATH);

	have_pub = have_priv = 0;

	hFind = FindFirstFileA(pfad, &ffd);
	if(hFind != INVALID_HANDLE_VALUE) {
		do {
			if(have_priv==0&&strcmp(ffd.cFileName,KEY_PRIV)==0) {
				have_priv = 1;
				continue;
			}
			if(have_pub==0&&strcmp(ffd.cFileName,KEY_PUB)==0) {
				have_pub = 1;
				if(box==INPUT_DLG2_SELECT) {
					SendDlgItemMessageA(window, box, CB_INSERTSTRING,0,(LPARAM)KEY_PUB_TXT);
					if(entries+1>entries) entries++;
				}
				continue;
			}
			
			len = strlen(ffd.cFileName);
			if(len>=5) ffd.cFileName[len-4] = 0;
			SendDlgItemMessageA(window, box, CB_INSERTSTRING,0,(LPARAM)ffd.cFileName);
			if(entries+1>entries) entries++;

		} while (FindNextFileA(hFind, &ffd) != 0);
		FindClose(hFind);
	}
	
	if(box==INPUT_DLG2_SELECT) {
		SendDlgItemMessageA(window, box, CB_INSERTSTRING,0,(LPARAM)NEUER_KEY_TXT);
		if(entries+1>entries) entries++;
	}
	
	entries = SendDlgItemMessageA(window, box, CB_GETCOUNT, 0, 0);
	if(entries>sel) {
		SendDlgItemMessageA(window, box, CB_SETCURSEL, sel, 0);
	} else {
		SendDlgItemMessageA(window, box, CB_SETCURSEL, 0, 0);
	}
	
	return entries;
}

void thread_hash_file(void *param) {

	HWND progress = NULL;
	HWND message_out = NULL;

	DWORD start_time, end_time;
	unsigned long bytes;
	time_t second;
	
	size_t len, readed;
	char file_buf[BUFSIZ];
	unsigned char buf[FILE_BLOCK];
	
	FILE *fd;
	unsigned char hash[crypto_hash_sha256_BYTES];
	
	char message[MAX_PATH];	
	
	thread_status = THREAD_RUN;
	
	if(cryptfile.size>DROP_DIALOG_SIZE) {
		while(!IsWindow(cryptfile.progress_window)) {

			if(thread_status==THREAD_DYING) {
				cryptfile.type = FALSE;
				goto end_hashfile;
			}
			Sleep(100);
		}
		progress = GetDlgItem(cryptfile.progress_window, PROGRESS_DLG3);

		// set defaults
		SetWindowTextA(cryptfile.progress_window, MSG_READ_KEYFILE);
		
		// Keyfile is hidden
		SendDlgItemMessageA(cryptfile.progress_window, STATIC_DLG3_PATH, WM_SETTEXT, 0, (LPARAM)""); 
		SendDlgItemMessageA(cryptfile.progress_window, STATIC_DLG3_SPEED, WM_SETTEXT, 0, (LPARAM)"0.00 MB/s");

		message_out = cryptfile.progress_window;
	} else {
		message_out = cryptfile.window;
	}

	fd = secure_fopen(cryptfile.path,"rb",file_buf,sizeof file_buf);
	if(!fd) {
		MessageBoxA(message_out, MSG_CAN_NOT_READ_KEYFILE, MSG_ERROR, MB_ICONERROR|MB_OK);
		cryptfile.type = FALSE;
		goto end_hashfile;
	}
	
	memset(hash,0,crypto_hash_sha256_BYTES);
	second = time(NULL);
	while((len=fread(buf,1,FILE_BLOCK,fd))>0) {

		if(readed+1>readed) readed++;
		
		crypto_hashblocks_sha256(hash,buf,len);

		if(cryptfile.size>DROP_DIALOG_SIZE) {
		
			if(bytes+len>bytes) bytes += len;
		
			if(readed%20) {
				SendMessage(progress, PBM_SETPOS, (int)(readed*FILE_BLOCK)/(cryptfile.size/100), (LPARAM)0);

				// refresh only every second
				if(time(NULL)>second) {
					end_time = GetTickCount();

					if(TICKS_DIFF(start_time,end_time)>0) {
						snprintf(message,sizeof(message),"%.2f MB/s",((float)bytes/(TICKS_DIFF(start_time,end_time)))/1024);
						SendDlgItemMessageA(cryptfile.progress_window, STATIC_DLG3_SPEED, WM_SETTEXT, 0, (LPARAM)message);
					}
					bytes = 0; 
					start_time = end_time;
					second = time(NULL);
				}
			}
		}
		if(thread_status==THREAD_DYING) {
			cryptfile.type = FALSE;
			goto end_hashfile;
		}
	}
	
	byte_copy(key_file_hash,crypto_hash_sha256_BYTES,hash);
	cryptfile.type = TRUE;

end_hashfile:

	rand_mem(cryptfile.path,MAX_PATH);
	rand_mem(buf,FILE_BLOCK);
	rand_mem(hash,crypto_hash_sha256_BYTES);
	
	if(cryptfile.size>DROP_DIALOG_SIZE) {
		if(IsWindow(cryptfile.progress_window)) {
			PostMessage(cryptfile.progress_window, WM_CLOSE, 0,0);
		}
	}

	secure_fclose(fd,file_buf,sizeof file_buf);

	thread_status = THREAD_OFF;

	 _endthread();
}

void thread_crypt_file(void *param) {

	HWND progress = NULL;
	HWND message_out = NULL;

	char name[MAX_NAME];
	size_t len, path_len, readed;
	char path[MAX_PATH];
	char path_out[MAX_PATH];

	unsigned char sk[crypto_box_SECRETKEYBYTES];
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char k[crypto_box_BEFORENMBYTES];
	unsigned char n[crypto_box_NONCEBYTES];
	
	char key64[KEY64_SIZE];
	FILE *file = NULL;
	FILE *out = NULL;
	char file_buf[BUFSIZ];
	char file_out[BUFSIZ];

	char drive[_MAX_DRIVE];
	char dir[_MAX_DIR];
	char fname[_MAX_FNAME];
	char ext[_MAX_EXT];

	char message[MAX_PATH*2];
	struct stat stbuf;
	
	DWORD start_time, end_time;
	unsigned long bytes;
	time_t second;
	
	int i;
	
	thread_status = THREAD_RUN;
	
	if(cryptfile.size>DROP_DIALOG_SIZE) {
		while(!IsWindow(cryptfile.progress_window)) {

			if(thread_status==THREAD_DYING) {
				goto end_dropfile;
			}
			Sleep(100);
		}
		progress = GetDlgItem(cryptfile.progress_window, PROGRESS_DLG3);

		// set defaults
		SetWindowTextA(cryptfile.progress_window, "");
		SendDlgItemMessageA(cryptfile.progress_window, STATIC_DLG3_PATH, WM_SETTEXT, 0, (LPARAM)"");
		SendDlgItemMessageA(cryptfile.progress_window, STATIC_DLG3_SPEED, WM_SETTEXT, 0, (LPARAM)"0.00 MB/s");

		message_out = cryptfile.progress_window;
	} else {
		message_out = cryptfile.window;
	}

	SendDlgItemMessageA(cryptfile.window, INPUT_DLG1_SELECT, CB_GETLBTEXT,SendDlgItemMessageA(cryptfile.window, INPUT_DLG1_SELECT, CB_GETCURSEL, 0, (LPARAM)0),(LPARAM)name);

	strncpy(path,name,MAX_PATH);

	// insert .key
	len = strlen(path);
	if(len==0) {
		MessageBoxA(message_out, MSG_NO_KEY_SELECTED, MSG_ERROR, MB_ICONERROR|MB_OK);
		goto end_dropfile;
	} else if(len>=4) {
		if(byte_diff(path+len-4,4,".key")!=0) {
			strncat(path,".key",MAX_PATH);
		}
	} else {
		strncat(path,".key",MAX_PATH);
	}
	
	file = secure_fopen(path,"r",file_buf,sizeof file_buf);
	if(file) {
		fgets(key64,KEY64_SIZE,file);
		scan_base64(key64,pk,&len);
		rand_mem(key64,KEY64_SIZE);
		secure_fclose(file,file_buf,sizeof file_buf);
	} else {
		snprintf(message, sizeof(message), MSG_CAN_NOT_LOAD_KEY, path);
		MessageBoxA(message_out, message, MSG_ERROR, MB_ICONERROR|MB_OK);
		goto end_dropfile;
	}

	file = secure_fopen(KEY_PRIV,"r",file_buf,sizeof file_buf);
	if(file) {
	
		fseek(file,strlen(KEY_PRIV_WARNING),SEEK_CUR);
		fgets(key64,KEY64_SIZE,file);
		scan_base64(key64,sk,&len);
		rand_mem(key64,KEY64_SIZE);
		secure_fclose(file,file_buf,sizeof file_buf);
	} else {
		snprintf(message, sizeof(message), MSG_CAN_NOT_LOAD_KEY, KEY_PRIV);
		MessageBoxA(message_out, message, MSG_ERROR, MB_ICONERROR|MB_OK);
		goto end_dropfile;
	}
	
	// decrypt key
	for(i=0;i<crypto_box_SECRETKEYBYTES;++i) {
		sk[i] = sk[i]^password_hash[i]^key_file_hash[i];
	}
	
	strncpy(path,cryptfile.path,MAX_PATH);
	
	if(cryptfile.type==DECRYPT) {

		file = secure_fopen(path,"rb",file_buf,sizeof file_buf);
		if(file) {
			
			_splitpath(path, drive, dir, fname, ext);

			len = fread(n,1,crypto_box_NONCEBYTES,file);
			
			// is filename encrypted?
			if(strlen(fname)>68) {

				stralloc_zero(&sabuf64);
				memset(sabuf64.s,0,crypto_box_BOXZEROBYTES);
				sabuf64.len = crypto_box_BOXZEROBYTES;
				
				scan_base64(fname+1,sabuf64.s+crypto_box_BOXZEROBYTES,&sabuf64.len);

				stralloc_zero(&sabuf);
				if(crypto_box_open(sabuf.s,sabuf64.s,sabuf64.len+crypto_box_BOXZEROBYTES,n,pk,sk)!=0) {
					MessageBoxA(message_out, ERROR_CRYPTO_BOX_OPEN_FILE, MSG_ERROR, MB_ICONERROR|MB_OK);
					goto end_dropfile;
				}
				sabuf.len = sabuf64.len - 16;
				stralloc_0(&sabuf);
				
				strncpy(path_out,drive,MAX_PATH);
				strncat(path_out,dir,MAX_PATH);
				strncat(path_out,sabuf.s+crypto_box_ZEROBYTES,MAX_PATH);
			} else {	
				strncpy(path_out,path,MAX_PATH);
				path_out[strlen(path_out)-6] = 0;
			}

			if(stat(path_out,&stbuf)==0) {
		
				snprintf(message, sizeof(message), MSG_DEST_FILE_EXISTS_OVERWRITE, path_out);
	
				if(MessageBoxA(message_out, message, MSG_DEST_FILE_OVERWRITE, MB_ICONQUESTION|MB_OKCANCEL) != IDOK) {
					goto end_dropfile;
				}
			}
		
			out = secure_fopen(path_out,"wb",file_out, sizeof file_out);
			if(out) {
				snprintf(message, sizeof(message), MSG_FILE_DECRYPT_WITH_KEY, path,name);
		
				if(MessageBoxA(message_out, message, MSG_FILE_DECRYPT, MB_ICONQUESTION|MB_OKCANCEL) == IDOK) {
					
					if(!stralloc_ready(&sabuf,FILE_BLOCK)) {
						MessageBoxA(message_out, MSG_OUT_OF_MEM, MSG_ERROR, MB_ICONERROR|MB_OK);
						goto end_dropfile;
					}
					
					stat(path,&stbuf);
					
					readed = 0;
					if(cryptfile.size>DROP_DIALOG_SIZE) {
						SetWindowTextA(cryptfile.progress_window, MSG_FILE_DECRYPT);
						SendDlgItemMessageA(cryptfile.progress_window, STATIC_DLG3_PATH, WM_SETTEXT, 0, (LPARAM)path);
						SendDlgItemMessageA(cryptfile.progress_window, STATIC_DLG3_SPEED, WM_SETTEXT, 0, (LPARAM)"0.00 MB/s");
						SendMessage(progress, PBM_SETPOS, 0, (LPARAM)0);
						
						start_time = GetTickCount();
						bytes = 0;
					}
						
					EnableWindow(GetDlgItem(cryptfile.window, INPUT_DLG1_SELECT),FALSE);
					EnableWindow(GetDlgItem(cryptfile.window, BUTTON_DLG1_MANAGE_KEYS),FALSE);
					EnableWindow(GetDlgItem(cryptfile.window, BUTTON_DLG1_DELETE),FALSE);
					EnableWindow(GetDlgItem(cryptfile.window, BUTTON_DLG1_COPY),FALSE);
					EnableWindow(GetDlgItem(cryptfile.window, BUTTON_DLG1_CRYPT),FALSE);
					EnableWindow(GetDlgItem(cryptfile.window, INPUT_DLG1_AREA),FALSE);
					DragAcceptFiles(cryptfile.window,FALSE);
					
					crypto_box_beforenm(k,pk,sk);
					
					rand_mem(pk,crypto_box_PUBLICKEYBYTES);
					rand_mem(sk,crypto_box_SECRETKEYBYTES);
					
					stralloc_zero(&sabuf);
					stralloc_zero(&sabuf64);

					second = time(NULL);
					while(!feof(file)) {

						if(cryptfile.size>DROP_DIALOG_SIZE) {
							if(bytes+len>bytes) bytes += len;
						}
					
						// beim ersten Durchgang wurde nonce schon für den Dateinamen gelesen.
						if(readed>0) {
							len=fread(n,1,crypto_box_NONCEBYTES,file);
						}
						if(readed+1>readed) readed++;

						memset(sabuf.s,0,crypto_box_BOXZEROBYTES);
						sabuf.len = crypto_box_BOXZEROBYTES;
						
						len = fread(sabuf.s+crypto_box_BOXZEROBYTES,1,FILE_BLOCK+16,file);
						
						if(crypto_box_open_afternm(sabuf64.s,sabuf.s,len+crypto_box_BOXZEROBYTES,n,k)) {
							MessageBoxA(message_out, ERROR_CRYPTO_BOX_OPEN_FILE, MSG_ERROR, MB_ICONERROR|MB_OK);
							secure_fclose(out,file_out,sizeof file_out);
							DeleteFileA(path_out);
							goto end_dropfile;
						}

						if(fwrite(sabuf64.s+crypto_box_ZEROBYTES,1,len-16,out)!=len-16) {
							MessageBoxA(message_out, MSG_WRITE_ERROR, MSG_ERROR, MB_ICONERROR|MB_OK);							
							secure_fclose(out,file_out,sizeof file_out);
							DeleteFileA(path_out);			
							goto end_dropfile;				
						}

						if(cryptfile.size>DROP_DIALOG_SIZE) {
							if(readed%20) {
								SendMessage(progress, PBM_SETPOS, (int)(readed*FILE_BLOCK)/(stbuf.st_size/100), (LPARAM)0);

								// refresh only every second
								if(time(NULL)>second) {
								
									end_time = GetTickCount();
					
									if(TICKS_DIFF(start_time,end_time)>0) {
										snprintf(message,sizeof(message),"%.2f MB/s",((float)bytes/(TICKS_DIFF(start_time,end_time)))/1024);
										SendDlgItemMessageA(cryptfile.progress_window, STATIC_DLG3_SPEED, WM_SETTEXT, 0, (LPARAM)message);
									}
									bytes = 0; 
									start_time = end_time;
									second = time(NULL);
								}
							}
						}
						if(thread_status==THREAD_DYING) {
							secure_fclose(out,file_out,sizeof file_out);
							DeleteFileA(path_out);
							goto end_dropfile;
						}
					}
					secure_fclose(out,file_out,sizeof file_out);
					secure_fclose(file,file_buf,sizeof file_buf);
				}
			} else {
				snprintf(message, sizeof(message), MSG_CAN_NOT_CREATE_DEST_FILE, path_out);
				MessageBoxA(message_out, message, MSG_ERROR, MB_ICONERROR|MB_OK);
				goto end_dropfile;
			}
		} else {
			snprintf(message, sizeof(message), MSG_CAN_NOT_READ_SRC_FILE, path_out);
			MessageBoxA(message_out, message, MSG_ERROR, MB_ICONERROR|MB_OK);
			goto end_dropfile;
		}
	} else { // encrypt
				
		secure_randombytes(n,crypto_box_NONCEBYTES);
		
		stralloc_zero(&sabuf64);
		memset(sabuf64.s,0,crypto_box_ZEROBYTES);
		sabuf64.len = crypto_box_ZEROBYTES;

		_splitpath(path, drive, dir, fname, ext);

		len = strlen(fname);
		if(len>0) stralloc_catb(&sabuf64,fname,len);
		
		len = strlen(ext);
		if(len>0) stralloc_catb(&sabuf64,ext,len);
		stralloc_0(&sabuf64);
		
		stralloc_zero(&sabuf);
		crypto_box(sabuf.s,sabuf64.s,sabuf64.len+crypto_box_ZEROBYTES,n,pk,sk);
		sabuf.len = sabuf64.len + 16 + crypto_box_BOXZEROBYTES;
		
		stralloc_zero(&sabuf64);
		sabuf64.len = fmt_base64(sabuf64.s,sabuf.s+crypto_box_BOXZEROBYTES,sabuf.len - crypto_box_BOXZEROBYTES);
		stralloc_0(&sabuf64);

		// build path_out
		strncpy(path_out,drive,MAX_PATH);
		strncat(path_out,dir,MAX_PATH);
		
		len = strlen(path_out);
		if(strlen(fname)>0) {
			path_out[len] = fname[0];
		} else if(strlen(ext)>0) {
			path_out[len] = ext[0];
		}
		path_out[len+1] = 0;

		// Pfad zu lang
		if((strlen(drive)+strlen(dir)+strlen(sabuf64.s)+8)<MAX_PATH) {
			strncat(path_out,sabuf64.s,MAX_PATH);				
		} else {
			if(strlen(ext)>0) strncat(path_out,ext,MAX_PATH);
		
			snprintf(message,sizeof(message), MSG_FILENAME_TO_LONG,MAX_PATH,path_out + len);
			MessageBoxA(message_out, message, MSG_PATH_TO_LONG, MB_ICONWARNING|MB_OK);
		}
		strncat(path_out,".fritz",MAX_PATH);

		file = secure_fopen(path,"rb",file_buf,sizeof file_buf);
		if(file) {
			if(stat(path_out,&stbuf)==0) {
		
				snprintf(message, sizeof(message), MSG_DEST_FILE_EXISTS_OVERWRITE, path_out);
	
				if(MessageBoxA(message_out, message, MSG_DEST_FILE_OVERWRITE, MB_ICONQUESTION|MB_OKCANCEL) != IDOK) {
					goto end_dropfile;
				}
			}

			out = secure_fopen(path_out,"wb",file_out,sizeof file_out);
			if(out) {
				snprintf(message, sizeof(message), MSG_FILE_ENCRYPT_WITH_KEY, path, name);
		
				if(MessageBoxA(message_out, message, MSG_FILE_ENCRYPT, MB_ICONQUESTION|MB_OKCANCEL) == IDOK) {
					
					if(!stralloc_ready(&sabuf,FILE_BLOCK)) {
						MessageBoxA(message_out, MSG_OUT_OF_MEM, MSG_ERROR, MB_ICONERROR|MB_OK);
						goto end_dropfile;
					}
					
					stat(path,&stbuf);
					
					crypto_box_beforenm(k,pk,sk);

					rand_mem(pk,crypto_box_PUBLICKEYBYTES);
					rand_mem(sk,crypto_box_SECRETKEYBYTES);

					stralloc_zero(&sabuf);
					stralloc_zero(&sabuf64);
					
					readed = 0;
					if(cryptfile.size>DROP_DIALOG_SIZE) {
						SetWindowTextA(cryptfile.progress_window, MSG_FILE_ENCRYPT);
						SendDlgItemMessageA(cryptfile.progress_window, STATIC_DLG3_PATH, WM_SETTEXT, 0, (LPARAM)path);
						SendDlgItemMessageA(cryptfile.progress_window, STATIC_DLG3_SPEED, WM_SETTEXT, 0, (LPARAM)"0.00 MB/s");
						SendMessage(progress, PBM_SETPOS, 0, (LPARAM)0);
						
						start_time = GetTickCount();
						bytes = 0;
					}

					EnableWindow(GetDlgItem(cryptfile.window, INPUT_DLG1_SELECT),FALSE);
					EnableWindow(GetDlgItem(cryptfile.window, BUTTON_DLG1_MANAGE_KEYS),FALSE);
					EnableWindow(GetDlgItem(cryptfile.window, BUTTON_DLG1_DELETE),FALSE);
					EnableWindow(GetDlgItem(cryptfile.window, BUTTON_DLG1_COPY),FALSE);
					EnableWindow(GetDlgItem(cryptfile.window, BUTTON_DLG1_CRYPT),FALSE);
					EnableWindow(GetDlgItem(cryptfile.window, INPUT_DLG1_AREA),FALSE);
					DragAcceptFiles(cryptfile.window,FALSE);
					
					memset(sabuf.s,0,crypto_box_ZEROBYTES);
					sabuf.len = crypto_box_ZEROBYTES;

					second = time(NULL);
					while((len=fread(sabuf.s+crypto_box_ZEROBYTES,1,FILE_BLOCK,file))>0) {

						if(cryptfile.size>DROP_DIALOG_SIZE) {
							if(bytes+len>bytes) bytes += len;
						}
					
						if(readed>0) {
							secure_randombytes(n,crypto_box_NONCEBYTES);
						}
						if(readed+1>readed) readed++;
					
						crypto_box_afternm(sabuf64.s,sabuf.s,len+crypto_box_ZEROBYTES,n,k);
						
						if(fwrite(n,1,crypto_box_NONCEBYTES,out)!=crypto_box_NONCEBYTES) {
							MessageBoxA(message_out, MSG_WRITE_ERROR, MSG_ERROR, MB_ICONERROR|MB_OK);							
							secure_fclose(out,file_out,sizeof file_out);
							DeleteFileA(path_out);			
							goto end_dropfile;				
						}
						
						if(fwrite(sabuf64.s+crypto_box_BOXZEROBYTES,1,len+16,out)!=len+16) {									
							MessageBoxA(message_out, MSG_WRITE_ERROR, MSG_ERROR, MB_ICONERROR|MB_OK);
							secure_fclose(out,file_out,sizeof file_out);
							DeleteFileA(path_out);
							goto end_dropfile;
						}

						memset(sabuf.s,0,crypto_box_ZEROBYTES);
						sabuf.len = crypto_box_ZEROBYTES;
						
						if(cryptfile.size>DROP_DIALOG_SIZE) {
							if(readed%20) {
								SendMessage(progress, PBM_SETPOS, (int)(readed*FILE_BLOCK)/(stbuf.st_size/100), (LPARAM)0);

								// refresh only every second
								if(time(NULL)>second) {
									end_time = GetTickCount();

									if(TICKS_DIFF(start_time,end_time)>0) {
										snprintf(message,sizeof(message),"%.2f MB/s",((float)bytes/(TICKS_DIFF(start_time,end_time)))/1024);
										SendDlgItemMessageA(cryptfile.progress_window, STATIC_DLG3_SPEED, WM_SETTEXT, 0, (LPARAM)message);
									}
									bytes = 0; 
									start_time = end_time;
									second = time(NULL);
								}
							}
						}
						
						if(thread_status==THREAD_DYING) {
							secure_fclose(out,file_out,sizeof file_out);
							DeleteFileA(path_out);
							goto end_dropfile;
						}
					}
					secure_fclose(out,file_out,sizeof file_out);
					secure_fclose(file,file_buf,sizeof file_buf);

				} else {
					secure_fclose(out,file_out,sizeof file_out);
					DeleteFileA(path_out);
					goto end_dropfile;
				}
			} else {
				snprintf(message, sizeof(message), MSG_CAN_NOT_CREATE_DEST_FILE, path_out);
				MessageBoxA(message_out, message, MSG_ERROR, MB_ICONERROR|MB_OK);
				goto end_dropfile;
			}
		} else {
			snprintf(message,sizeof(message), MSG_CAN_NOT_READ_SRC_FILE, path);
			MessageBoxA(message_out, message, MSG_ERROR, MB_ICONERROR|MB_OK);
			goto end_dropfile;
		}
	}

end_dropfile:

	EnableWindow(GetDlgItem(cryptfile.window, INPUT_DLG1_SELECT),TRUE);
	EnableWindow(GetDlgItem(cryptfile.window, BUTTON_DLG1_MANAGE_KEYS),TRUE);
	EnableWindow(GetDlgItem(cryptfile.window, BUTTON_DLG1_DELETE),TRUE);
	EnableWindow(GetDlgItem(cryptfile.window, BUTTON_DLG1_COPY),TRUE);
	EnableWindow(GetDlgItem(cryptfile.window, BUTTON_DLG1_CRYPT),TRUE);
	EnableWindow(GetDlgItem(cryptfile.window, INPUT_DLG1_AREA),TRUE);
	DragAcceptFiles(cryptfile.window,TRUE);

	if(cryptfile.size>DROP_DIALOG_SIZE) {
		if(IsWindow(cryptfile.progress_window)) {
			PostMessage(cryptfile.progress_window, WM_CLOSE, 0,0);
		}
	}
	
	if(out!=NULL) secure_fclose(out,file_out,sizeof file_out);
	if(file!=NULL) secure_fclose(file,file_buf,sizeof file_buf);
	
	rand_mem(pk,crypto_box_PUBLICKEYBYTES);
	rand_mem(sk,crypto_box_SECRETKEYBYTES);
	rand_mem(k,crypto_box_BEFORENMBYTES);
	rand_mem(n,crypto_box_NONCEBYTES);
	rand_mem(sabuf.s,sabuf.a);
	rand_mem(sabuf64.s,sabuf64.a);

	thread_status = THREAD_OFF;

	 _endthread();
}

void thread_crypt_message(void *param) {

	char path[MAX_PATH];
	size_t len;
	
	FILE *file = NULL;
	char file_buf[BUFSIZ];
	char key64[KEY64_SIZE];
	
	unsigned char sk[crypto_box_SECRETKEYBYTES];
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char n[crypto_box_NONCEBYTES];
	
	char message[MAX_PATH*2];

	int i;
	
	thread_status = THREAD_RUN;
	
	stralloc_0(&sabuf);

	EnableWindow(GetDlgItem(cryptmessage.window, BUTTON_DLG1_CRYPT),FALSE);

	SendDlgItemMessageA(cryptmessage.window, INPUT_DLG1_SELECT, CB_GETLBTEXT,SendDlgItemMessageA(cryptmessage.window, INPUT_DLG1_SELECT, CB_GETCURSEL, 0, (LPARAM)0),(LPARAM)path);
			
	// insert .key
	len = strlen(path);
	if(len>=4) {
		if(byte_diff(path+len-4,4,".key")!=0) {
			strncat(path,".key",MAX_PATH);
		}
	} else {
		strncat(path,".key",MAX_PATH);
	}

	file = secure_fopen(path,"r",file_buf,sizeof file_buf);
	if(file) {
		fgets(key64,KEY64_SIZE,file);
		scan_base64(key64,pk,&len);
		rand_mem(key64,KEY64_SIZE);
		secure_fclose(file,file_buf,sizeof file_buf);
	} else {
		snprintf(message, sizeof(message), MSG_CAN_NOT_LOAD_KEY, path);
		MessageBoxA(cryptmessage.window, message, MSG_ERROR, MB_ICONERROR|MB_OK);
		goto end_crypt;
	}

	file = secure_fopen(KEY_PRIV,"r",file_buf,sizeof file_buf);
	if(file) {
		fseek(file,strlen(KEY_PRIV_WARNING),SEEK_CUR);
		fgets(key64,KEY64_SIZE,file);
		scan_base64(key64,sk,&len);
		rand_mem(key64,KEY64_SIZE);
		secure_fclose(file,file_buf,sizeof file_buf);
	} else {
		snprintf(message, sizeof(message), MSG_CAN_NOT_LOAD_KEY, KEY_PRIV);
		MessageBoxA(cryptmessage.window, message, MSG_ERROR, MB_ICONERROR|MB_OK);
		goto end_crypt;
	}

	// decrypt key
	for(i=0;i<crypto_box_SECRETKEYBYTES;++i) {
		sk[i] = sk[i]^password_hash[i]^key_file_hash[i];
	}

	if(cryptmessage.type==DECRYPT) {
		
		if(sabuf.len<base64_len(crypto_box_NONCEBYTES)+1) goto encrypt;
		
		stralloc_zero(&sabuf64);
		memset(sabuf64.s,0,crypto_box_BOXZEROBYTES);
		sabuf64.len = crypto_box_BOXZEROBYTES;
		
		scan_base64(sabuf.s,sabuf64.s+crypto_box_BOXZEROBYTES,&sabuf64.len);
		
		byte_copy(n,crypto_box_NONCEBYTES,sabuf64.s + (sabuf64.len + crypto_box_BOXZEROBYTES - crypto_box_NONCEBYTES));
		sabuf64.len -= crypto_box_NONCEBYTES;

		stralloc_zero(&sabuf);
		if(crypto_box_open(sabuf.s,sabuf64.s,sabuf64.len+crypto_box_BOXZEROBYTES,n,pk,sk)!=0) {
			MessageBoxA(cryptmessage.window, ERROR_CRYPTO_BOX_OPEN, MSG_ERROR, MB_ICONERROR|MB_OK);
			goto end_crypt;
		}

		stralloc_0(&sabuf);
		SendDlgItemMessageA(cryptmessage.window, INPUT_DLG1_AREA, WM_SETTEXT, 0, (LPARAM)sabuf.s+crypto_box_ZEROBYTES);
		
		SetWindowTextA(GetDlgItem(cryptmessage.window,BUTTON_DLG1_CRYPT),BUTTON_ENCR);
	
	} else { // encrypt
encrypt:
		secure_randombytes(n,crypto_box_NONCEBYTES);

		stralloc_zero(&sabuf64);
		memset(sabuf64.s,0,crypto_box_ZEROBYTES);
		sabuf64.len = crypto_box_ZEROBYTES;
	
		stralloc_catb(&sabuf64,sabuf.s,sabuf.len);
		stralloc_0(&sabuf64);
		
		stralloc_zero(&sabuf);
		if(crypto_box(sabuf.s,sabuf64.s,sabuf64.len+crypto_box_ZEROBYTES,n,pk,sk)!=0) {
			MessageBoxA(cryptmessage.window, ERROR_CRYPTO_BOX, MSG_ERROR, MB_ICONERROR|MB_OK);
			goto end_crypt;
		}
		sabuf.len = sabuf64.len + 16 + crypto_box_BOXZEROBYTES;

		stralloc_catb(&sabuf,n,crypto_box_NONCEBYTES); // nonce

		stralloc_zero(&sabuf64);
		sabuf64.len = fmt_base64(sabuf64.s,sabuf.s+crypto_box_BOXZEROBYTES,sabuf.len - crypto_box_BOXZEROBYTES);
		stralloc_0(&sabuf64);
		
		SendDlgItemMessageA(cryptmessage.window, INPUT_DLG1_AREA, WM_SETTEXT, 0, (LPARAM)sabuf64.s);
		
		SetWindowTextA(GetDlgItem(cryptmessage.window,BUTTON_DLG1_CRYPT),BUTTON_DECR);
	}
end_crypt:

	EnableWindow(GetDlgItem(cryptmessage.window, BUTTON_DLG1_CRYPT),TRUE);
	
	rand_mem(key64,KEY64_SIZE);
	rand_mem(sk,crypto_box_SECRETKEYBYTES);
	rand_mem(pk,crypto_box_PUBLICKEYBYTES);
	rand_mem(sabuf.s,sabuf.a);
	rand_mem(sabuf64.s,sabuf64.a);
	rand_mem(n,crypto_box_NONCEBYTES);

	thread_status = THREAD_OFF;

	 _endthread();
}

INT_PTR CALLBACK DialogCreatePassword(HWND window, UINT uMsg, WPARAM wParam, LPARAM lParam) {

	HWND hwndOwner;
	RECT rc, rcDlg, rcOwner;

	char password1[MAX_PASSWORD+1];
	char password2[MAX_PASSWORD+1];
	
	char old_path[MAX_PATH];
	char path[MAX_PATH];
	unsigned int ret;

	char message[MAX_PATH*2];
	
	OPENFILENAME ofn;
	struct stat stbuf;

	unsigned char n[crypto_stream_xsalsa20_NONCEBYTES];
	FILE *file;
	char file_buf[BUFSIZ];
	char buf[MAX_PATH*2];
	char buf64[MAX_PATH*2];
	size_t len;
	
	int have_keyfile;

	HDC dc;
	RECT r;
	
	switch(uMsg) {
		case WM_INITDIALOG:
			if ((hwndOwner = GetParent(window)) == NULL) {
				hwndOwner = GetDesktopWindow(); 
			}

			GetWindowRect(hwndOwner, &rcOwner); 
			GetWindowRect(window, &rcDlg); 
			CopyRect(&rc, &rcOwner); 

			OffsetRect(&rcDlg, -rcDlg.left, -rcDlg.top); 
			OffsetRect(&rc, -rc.left, -rc.top); 
			OffsetRect(&rc, -rcDlg.right, -rcDlg.bottom); 

			SetWindowPos(window, 
				HWND_TOP, 
				rcOwner.left + (rc.right / 2), 
				rcOwner.top + (rc.bottom / 2), 
				0, 0, 
				SWP_NOSIZE);

			SendMessage(window, WM_SETICON, ICON_SMALL, (LPARAM)hicon);
			
			SendDlgItemMessage(window, INPUT_DLG4_PASSWD1, EM_LIMITTEXT,MAX_PASSWORD,0);
			SendDlgItemMessage(window, INPUT_DLG4_PASSWD2, EM_LIMITTEXT,MAX_PASSWORD,0);
			
			SendDlgItemMessage(window, INPUT_DLG4_PASSWD1, EM_SETPASSWORDCHAR, '*', 0);
			SendDlgItemMessage(window, INPUT_DLG4_PASSWD2, EM_SETPASSWORDCHAR, '*', 0);
			
			SendDlgItemMessageA(window, STATIC_DLG4_STATE, WM_SETTEXT, 0, (LPARAM)"");
			
			SendDlgItemMessageA(window, STATIC_DLG4_PATH, WM_SETTEXT, 0, (LPARAM)KEYFILE_EMPTY_TEXT);
			
			SetWindowTextA(window, MSG_INSERT_NEW_PASSWORD);

			SetWindowTextA(GetDlgItem(window,STATIC_DLG4_TEXT1),TXT_NEW_PASSWORD);
			SetWindowTextA(GetDlgItem(window,STATIC_DLG4_TEXT2),TXT_REPEAT_NEW_PASSWORD);
			SetWindowTextA(GetDlgItem(window,BUTTON_DLG4_OK),TXT_OK);
			SetWindowTextA(GetDlgItem(window,BUTTON_DLG4_ABORT),TXT_ABORT);
			SetWindowTextA(GetDlgItem(window,STATIC_DLG4_TEXT3),TXT_KEYFILE);
			SetWindowTextA(GetDlgItem(window,BUTTON_DLG4_CHANGE),TXT_CHANGE);
			
			EnableWindow(GetDlgItem(window, BUTTON_DLG4_OK),FALSE);

			SetFocus(GetDlgItem(window, INPUT_DLG4_PASSWD1));
		return TRUE;
		case WM_COMMAND:
			switch(LOWORD(wParam)) {
			
				case INPUT_DLG4_PASSWD1:
				case INPUT_DLG4_PASSWD2:
					SendDlgItemMessageA(window, INPUT_DLG4_PASSWD1, WM_GETTEXT, sizeof(password1), (LPARAM)password1);
					SendDlgItemMessageA(window, INPUT_DLG4_PASSWD2, WM_GETTEXT, sizeof(password1), (LPARAM)password2);
					
					ret = check_passwords(password1,password2);
					
					dc = GetDC(window);
					GetClientRect(GetDlgItem(window, STATIC_DLG4_STATE), &r);
					FillRect(dc, &r, (HBRUSH) (COLOR_WINDOW));
					
					SetBkMode(dc, TRANSPARENT);
					if(ret==PASSWORD_OK) {
						SetTextColor(dc, RGB(46,145,10));
						TextOut(dc, 5, 0, password_errors[ret], strlen(password_errors[ret]));
						EnableWindow(GetDlgItem(window, BUTTON_DLG4_OK),TRUE);
					} else {
						SetTextColor(dc, RGB(224,63,18));
						TextOut(dc, 5, 0, password_errors[ret], strlen(password_errors[ret]));
						EnableWindow(GetDlgItem(window, BUTTON_DLG4_OK),FALSE);
					}
					ReleaseDC(window, dc);
				return TRUE;
				case BUTTON_DLG4_OK:

					SendDlgItemMessageA(window, INPUT_DLG4_PASSWD1, WM_GETTEXT, sizeof(password1), (LPARAM)password1);
					len = strlen(password1);
					crypto_hash_sha256(password_hash,password1,len);
					rand_mem(password1,MAX_PASSWORD);
					rand_mem(password2,MAX_PASSWORD);
					
					memset(path,0,MAX_PATH);
					SendDlgItemMessageA(window, STATIC_DLG4_PATH, WM_GETTEXT, MAX_PATH, (LPARAM)path);

					secure_randombytes(n,crypto_stream_xsalsa20_NONCEBYTES);

					len = strlen(path);
					if(byte_diff(path,strlen(KEYFILE_EMPTY_TEXT),KEYFILE_EMPTY_TEXT)==0) {
						have_keyfile = 0;
					} else {
						have_keyfile = 1;
					}
					
					// encrypt everytime MAX_PATH bytes in path with password_hash
					crypto_stream_xsalsa20_xor(buf,path,MAX_PATH,n,password_hash);
					
					byte_copy(buf + MAX_PATH,crypto_stream_xsalsa20_NONCEBYTES,n);
					rand_mem(n,crypto_stream_xsalsa20_NONCEBYTES);

					file = secure_fopen(KEYFILE_PATH_STORE,"w",file_buf,sizeof file_buf);
					if(file) {
						buf64[fmt_base64(buf64,buf,MAX_PATH+crypto_stream_xsalsa20_NONCEBYTES)]=0;
						fputs(buf64,file);
						secure_fclose(file,file_buf,sizeof file_buf);
						rand_mem(buf64,sizeof(buf64));
					}
					rand_mem(buf,sizeof(buf));
					
					// plaintext: password_hash, path

					if(have_keyfile) {
						// read and store file hash in extra thread
						if(stat(path,&stbuf)==0) {

							cryptfile.type = FALSE; // this is a return code
							cryptfile.size = stbuf.st_size;
							cryptfile.window = window;
							cryptfile.progress_window = NULL;
							strncpy(cryptfile.path,path,MAX_PATH);
					
							_beginthread(thread_hash_file, 0, 0);
						
							if(stbuf.st_size>DROP_DIALOG_SIZE) {
								DialogBoxA(NULL, MAKEINTRESOURCE(DIALOG_PROGRESS_FILE), window, DialogProgressFile);
							}
							
							while(thread_status!=THREAD_OFF) Sleep(100);
						}
						rand_mem(path,sizeof(path));
					} else {
						memset(key_file_hash,0,crypto_hash_sha256_BYTES);
					}
					
					if(have_keyfile) {
						if(cryptfile.type==FALSE) {
							EndDialog(window,0);
						}
					}
					EndDialog(window,1);

					return TRUE;
				case BUTTON_DLG4_CHANGE:
				
					GetCurrentDirectoryA(MAX_PATH,old_path);
					
					memset(&ofn,0,sizeof(ofn));
					ofn.lStructSize = sizeof(ofn);
					ofn.hwndOwner = window;
					ofn.lpstrFile = path;
					ofn.lpstrFile[0] = '\0';
					ofn.nMaxFile = MAX_PATH;
					ofn.Flags = OFN_FILEMUSTEXIST;
					
					if(GetOpenFileName(&ofn)==TRUE) {
						SendDlgItemMessageA(window, STATIC_DLG4_PATH, WM_SETTEXT, 0, (LPARAM)ofn.lpstrFile);
					}
					SetCurrentDirectoryA(old_path);
				return TRUE;
				case BUTTON_DLG4_HELP1:
					snprintf(message, sizeof(message), MSG_PASSWORD_RULES, MIN_PASSWORD_LEN,MIN_COUNT);
				
					MessageBoxA(NULL, message, MSG_NEW_PASSWORD, MB_ICONINFORMATION|MB_OK);
				return TRUE;
				case BUTTON_DLG4_HELP2:
				
					MessageBoxA(NULL, MSG_KEYFILE, MSG_KEYFILE_TITLE, MB_ICONINFORMATION|MB_OK);
				return TRUE;
				case BUTTON_DLG4_ABORT:
					EndDialog(window,0);
				return TRUE;
			}
		break;
		case WM_CLOSE:
			EndDialog(window,0);
		return TRUE;
	}
	return FALSE;
}

INT_PTR CALLBACK DialogManageKeys(HWND window, UINT uMsg, WPARAM wParam, LPARAM lParam) {

	HWND hwndOwner;
	RECT rc, rcDlg, rcOwner;

	struct stat stbuf;
	char name[MAX_NAME];
	char message[MAX_NAME*2];
	char path[MAX_NAME];
	char key[crypto_box_SECRETKEYBYTES];
	char key64[KEY64_SIZE];
	size_t len;
	FILE *file = NULL;
	char file_buf[BUFSIZ];

	unsigned char sk[crypto_box_SECRETKEYBYTES];
	int i;

	HFONT hfont;
	
	switch(uMsg) {
		case WM_INITDIALOG:
			if ((hwndOwner = GetParent(window)) == NULL) {
				hwndOwner = GetDesktopWindow(); 
			}

			GetWindowRect(hwndOwner, &rcOwner); 
			GetWindowRect(window, &rcDlg); 
			CopyRect(&rc, &rcOwner); 

			OffsetRect(&rcDlg, -rcDlg.left, -rcDlg.top); 
			OffsetRect(&rc, -rc.left, -rc.top); 
			OffsetRect(&rc, -rcDlg.right, -rcDlg.bottom); 

			SetWindowPos(window, 
				HWND_TOP, 
				rcOwner.left + (rc.right / 2), 
				rcOwner.top + (rc.bottom / 2), 
				0, 0, 
				SWP_NOSIZE);

			SetWindowTextA(window, DIALOG_MANAGE_KEYS_TITLE);
			SetWindowTextA(GetDlgItem(window,BUTTON_DLG2_COPY),TXT_COPY);
			SetWindowTextA(GetDlgItem(window,BUTTON_DLG2_CHANGE),TXT_CHANGE_PASSWORD_KEYFILE);
			SetWindowTextA(GetDlgItem(window,BUTTON_DLG2_DELETE),TXT_DELETE);
			SetWindowTextA(GetDlgItem(window,BUTTON_DLG2_SAVE),TXT_SAVE);
			SetWindowTextA(GetDlgItem(window,BUTTON_DLG2_ABORT),TXT_ABORT);
			SetWindowTextA(GetDlgItem(window,IDC_GRP1),TXT_NAME);
			SetWindowTextA(GetDlgItem(window,IDC_GRP2),TXT_KEYS);
			
			SendMessage(window, WM_SETICON, ICON_SMALL, (LPARAM)hicon);
			
			SendDlgItemMessage(window, INPUT_DLG2_TEXT_NAME, EM_LIMITTEXT,MAX_NAME,0);
			SendDlgItemMessage(window, INPUT_DLG2_TEXT_KEY, EM_LIMITTEXT,KEY64_SIZE,0);

			// courier font is easier to read
			hfont = CreateFont(15, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,FF_DONTCARE, "Courier New");
			SendMessage(GetDlgItem(window, INPUT_DLG2_TEXT_KEY), WM_SETFONT,(WPARAM)hfont, TRUE);
			
			RefreshKeyList(window,INPUT_DLG2_SELECT);
					 
			PostMessage(window, WM_COMMAND, (CBN_SELCHANGE << 16) | (INPUT_DLG2_SELECT & 0xffff),0);
			
			SetFocus(GetDlgItem(window, INPUT_DLG2_TEXT_NAME));
		return TRUE;
		case WM_COMMAND:
			switch(LOWORD(wParam)) {
				case INPUT_DLG2_TEXT_NAME:
					SendDlgItemMessageA(window, INPUT_DLG2_SELECT, CB_GETLBTEXT,SendDlgItemMessageA(window, INPUT_DLG2_SELECT, CB_GETCURSEL, 0, (LPARAM)0),(LPARAM)name);
					if(strcmp(name,NEUER_KEY_TXT)==0) {
						len = SendDlgItemMessageA(window, INPUT_DLG2_TEXT_NAME, WM_GETTEXTLENGTH, 0, 0);
						if(len>0) {
							EnableWindow(GetDlgItem(window, BUTTON_DLG2_SAVE),TRUE);
						} else {
							EnableWindow(GetDlgItem(window, BUTTON_DLG2_SAVE),FALSE);
						}
					}
				return TRUE;
				case BUTTON_DLG2_ABORT:
				case IDCANCEL:
					EndDialog(window,0);
					return TRUE;
				case BUTTON_DLG2_CHANGE: // change Password
				
					file = secure_fopen(KEY_PRIV,"r",file_buf,sizeof file_buf);
					if(file) {
						fseek(file,strlen(KEY_PRIV_WARNING),SEEK_CUR);
						fgets(key64,KEY64_SIZE,file);
						scan_base64(key64,sk,&len);
						rand_mem(key64,KEY64_SIZE);
						secure_fclose(file,file_buf,sizeof file_buf);
					} else {
						snprintf(message, sizeof(message), MSG_CAN_NOT_LOAD_KEY, KEY_PRIV);
						MessageBoxA(NULL, message, MSG_ERROR, MB_ICONERROR|MB_OK);
						return TRUE;
					}
					
					// decrypt key
					for(i=0;i<crypto_box_SECRETKEYBYTES;++i) {
						sk[i] = sk[i]^password_hash[i]^key_file_hash[i];
					}
		
					// set new hashes
					if(DialogBoxA(NULL, MAKEINTRESOURCE(DIALOG_CREATE_PASSWORD), window, DialogCreatePassword)==0) {
						rand_mem(sk,crypto_box_SECRETKEYBYTES);
						return TRUE;
					}
				
					// encrypt key
					for(i=0;i<crypto_box_SECRETKEYBYTES;++i) {
						sk[i] = sk[i]^password_hash[i]^key_file_hash[i];
					}

					file = secure_fopen(KEY_PRIV,"w",file_buf,sizeof file_buf);
					if(file) {
						key64[fmt_base64(key64,sk,crypto_box_SECRETKEYBYTES)]=0;
						fputs(KEY_PRIV_WARNING,file);
						fputs(key64,file);
						rand_mem(key64,KEY64_SIZE);
						secure_fclose(file,file_buf,sizeof file_buf);
					}
					rand_mem(sk,crypto_box_SECRETKEYBYTES);
					
					for(i=crypto_hash_sha256_BYTES-1;i>0;i--) {
						if(key_file_hash[i]!=0) break;
					}
					if(i==0) {
						MessageBoxA(NULL, MSG_PASSWORD_CHANGED_NO_KEYFILE, MSG_NEW_PASSWORD, MB_ICONINFORMATION|MB_OK);
					} else {
						MessageBoxA(NULL, MSG_PASSWORD_CHANGED_KEYFILE, MSG_NEW_PASSWORD_KEYFILE, MB_ICONINFORMATION|MB_OK);
					}
				return TRUE;
				case BUTTON_DLG2_DELETE:
					SendDlgItemMessageA(window, INPUT_DLG2_TEXT_NAME, WM_GETTEXT, sizeof(name), (LPARAM)name);
					
					strncpy(path,name,MAX_NAME);
					
					// insert .key
					len = strlen(path);
					if(len>=4) {
						if(byte_diff(path+len-4,4,".key")!=0) {
							strncat(path,".key",MAX_NAME);
						}
					} else {
						strncat(path,".key",MAX_NAME);
					}

					snprintf(message,sizeof(message), MSG_REMOVE_KEY_FROM, name);
					if(MessageBoxA(window, message, MSG_REMOVE_KEY, MB_ICONQUESTION | MB_YESNO) == IDYES) {

						rand_mem(key64,KEY64_SIZE);
						file = secure_fopen(path,"w",file_buf,sizeof file_buf);
						if(file) {
							fwrite(key64,KEY64_SIZE,1,file);
							secure_fclose(file,file_buf,sizeof file_buf);
						}
					
						if(DeleteFileA(path)==0) {
							MessageBoxA(window, MSG_REMOVE_KEY_ERROR, MSG_ERROR, MB_ICONERROR);
							return TRUE;
						}
						EndDialog(window,0);		
						return TRUE;
					}		
					return TRUE;
				case BUTTON_DLG2_COPY:
				
					SendDlgItemMessageA(window, INPUT_DLG2_SELECT, CB_GETLBTEXT,SendDlgItemMessageA(window, INPUT_DLG2_SELECT, CB_GETCURSEL, 0, (LPARAM)0),(LPARAM)name);
						
					if(strcmp(name,NEUER_KEY_TXT)==0) {
					
						secure_randombytes(key,crypto_box_PUBLICKEYBYTES);
						key64[fmt_base64(key64,key,crypto_box_PUBLICKEYBYTES)]=0;
						SendDlgItemMessageA(window, INPUT_DLG2_TEXT_KEY, WM_SETTEXT, 0, (LPARAM)key64);
						
						// mark random keys with '#'
						SendDlgItemMessageA(window, INPUT_DLG2_TEXT_NAME, WM_GETTEXT, sizeof(name) - 1, (LPARAM)name + 1);
						if(name[1]!='#') {
							name[0] = '#';
							SendDlgItemMessageA(window, INPUT_DLG2_TEXT_NAME, WM_SETTEXT, 0, (LPARAM)name);
						}
					
					} else {
						SendDlgItemMessageA(window, INPUT_DLG2_TEXT_KEY, WM_GETTEXT, sizeof(key64), (LPARAM)key64);
						copyToClipboard(key64);
						rand_mem(key64,KEY64_SIZE);
						
						SendDlgItemMessageA(window, INPUT_DLG2_TEXT_NAME, WM_GETTEXT, sizeof(name), (LPARAM)name);
						if(name[0]=='#') {
							MessageBoxA(NULL, MSG_RANDOM_KEY_COPIED, MSG_RANDOM_KEY, MB_ICONWARNING|MB_OK);
						}						
					}
					return TRUE;
				case INPUT_DLG2_SELECT:
					if(HIWORD(wParam)==CBN_SELCHANGE) {
						SendDlgItemMessageA(window, INPUT_DLG2_SELECT, CB_GETLBTEXT,SendDlgItemMessageA(window, INPUT_DLG2_SELECT, CB_GETCURSEL, 0, (LPARAM)0),(LPARAM)name);
						
						if(strcmp(name,NEUER_KEY_TXT)==0) {
							EnableWindow(GetDlgItem(window, BUTTON_DLG2_SAVE),TRUE);
							EnableWindow(GetDlgItem(window, BUTTON_DLG2_DELETE),FALSE);
							EnableWindow(GetDlgItem(window, INPUT_DLG2_TEXT_NAME),TRUE);
							
							SendDlgItemMessageA(window, INPUT_DLG2_TEXT_NAME, WM_SETTEXT, 0, (LPARAM)NULL);
							SendDlgItemMessageA(window, INPUT_DLG2_TEXT_KEY, WM_SETTEXT, 0, (LPARAM)NULL);
							SendDlgItemMessageA(window, BUTTON_DLG2_COPY, WM_SETTEXT, 0, (LPARAM)MSG_CREATE);
							return TRUE;
						} else {
							SendDlgItemMessageA(window, BUTTON_DLG2_COPY, WM_SETTEXT, 0, (LPARAM)MSG_COPY);
						}
						
						if(strcmp(name,KEY_PUB_TXT)==0) {
							EnableWindow(GetDlgItem(window, BUTTON_DLG2_SAVE),FALSE);
							EnableWindow(GetDlgItem(window, BUTTON_DLG2_DELETE),FALSE);
							EnableWindow(GetDlgItem(window, INPUT_DLG2_TEXT_NAME),FALSE);
							
							strncpy(path,KEY_PUB,MAX_NAME);
						} else {
							EnableWindow(GetDlgItem(window, BUTTON_DLG2_SAVE),TRUE);
							EnableWindow(GetDlgItem(window, BUTTON_DLG2_DELETE),TRUE);
							EnableWindow(GetDlgItem(window, INPUT_DLG2_TEXT_NAME),TRUE);
							
							strncpy(path,name,MAX_NAME);
							
							// insert .key
							len = strlen(path);
							if(len>=4) {
								if(byte_diff(path+len-4,4,".key")!=0) {
									strncat(path,".key",MAX_NAME);
								}
							} else {
								strncat(path,".key",MAX_NAME);
							}
						}
							
						file = secure_fopen(path,"r",file_buf,sizeof file_buf);
						if(file) {
							fgets(key64,KEY64_SIZE,file);
							secure_fclose(file,file_buf,sizeof file_buf);

							SendDlgItemMessageA(window, INPUT_DLG2_TEXT_NAME, WM_SETTEXT, 0, (LPARAM)&name);
							SendDlgItemMessageA(window, INPUT_DLG2_TEXT_KEY, WM_SETTEXT, 0, (LPARAM)&key64);
						}
						rand_mem(key64,KEY64_SIZE);
						return TRUE;
					}
					return TRUE;

				case BUTTON_DLG2_SAVE:
				
					SendDlgItemMessageA(window, INPUT_DLG2_TEXT_NAME, WM_GETTEXT, MAX_NAME, (LPARAM)name);

					// insert .key
					len = strlen(name);
					if(len>=4) {
						if(byte_diff(name+len-4,4,".key")!=0) {
							strncat(name,".key",MAX_NAME);
						}
					} else {
						strncat(name,".key",MAX_NAME);
					}
				
					if(stat(name,&stbuf)==0) {
						if(MessageBoxA(window, MSG_KEY_EXISTS, MSG_OVERWRITE, MB_ICONQUESTION|MB_YESNO) == IDNO) {
							EndDialog(window,0);
							return FALSE;
						}
					}
					
					SendDlgItemMessageA(window, INPUT_DLG2_TEXT_KEY, WM_GETTEXT, sizeof(key64), (LPARAM)key64);
					if(!isBase64(key64,BASE64_NORMAL)) {
						MessageBoxA(window, MSG_KEY_CORRUPT, MSG_ERROR, MB_ICONERROR|MB_OK);
						rand_mem(key64,KEY64_SIZE);
						EndDialog(window,0);
						return FALSE;
					}
					
					scan_base64(key64,key,&len);
					if(len!=crypto_box_PUBLICKEYBYTES) {
						MessageBoxA(window, MSG_KEY_CORRUPT, MSG_ERROR, MB_ICONERROR|MB_OK);
						rand_mem(key64,KEY64_SIZE);
						rand_mem(key,sizeof(key));
						EndDialog(window,0);
						return FALSE;
					}
					
					file = secure_fopen(name,"w",file_buf,sizeof file_buf);
					if(!file) {
						MessageBoxA(window, MSG_KEY_NAME_CORRUPT, MSG_ERROR, MB_ICONERROR|MB_OK);
						rand_mem(key64,KEY64_SIZE);
						rand_mem(key,sizeof(key));
						EndDialog(window,0);
						return FALSE;
					}

					fputs(key64,file);
					secure_fclose(file,file_buf,sizeof file_buf);

					rand_mem(key64,KEY64_SIZE);
					rand_mem(key,sizeof(key));					
					EndDialog(window,0);
					return TRUE;
			}
		break;
		case WM_CLOSE:
			EndDialog(window,0);
		return TRUE;
	}
	return FALSE;
}

INT_PTR CALLBACK DialogProgressFile(HWND window, UINT uMsg, WPARAM wParam, LPARAM lParam) {

	HWND hwndOwner;
	RECT rc, rcDlg, rcOwner;

	switch(uMsg) {
		case WM_INITDIALOG:
			if ((hwndOwner = GetParent(window)) == NULL) {
				hwndOwner = GetDesktopWindow(); 
			}

			GetWindowRect(hwndOwner, &rcOwner); 
			GetWindowRect(window, &rcDlg); 
			CopyRect(&rc, &rcOwner); 

			OffsetRect(&rcDlg, -rcDlg.left, -rcDlg.top); 
			OffsetRect(&rc, -rc.left, -rc.top); 
			OffsetRect(&rc, -rcDlg.right, -rcDlg.bottom); 

			SetWindowPos(window, 
				HWND_TOP, 
				rcOwner.left + (rc.right / 2), 
				rcOwner.top + (rc.bottom / 2), 
				0, 0, 
				SWP_NOSIZE);

			cryptfile.progress_window = window;
			
			SetWindowTextA(GetDlgItem(window,BUTTON_DLG3_ABORT),TXT_ABORT);
			
			SendMessage(window, WM_SETICON, ICON_SMALL, (LPARAM)hicon);
		return TRUE;
		case WM_COMMAND:
			switch(LOWORD(wParam)) {
				case BUTTON_DLG3_ABORT:
				
					if(thread_status==THREAD_RUN) {
						thread_status = THREAD_DYING;
					}
					EndDialog(window,0);
					return TRUE;
				case BUTTON_DLG2_ABORT:
					EndDialog(window,0);
					return TRUE;
			}
		case WM_CLOSE:
		
			if(thread_status==THREAD_RUN) {
				thread_status = THREAD_DYING;
			}
			EndDialog(window,0);
		return TRUE;
	}
	return FALSE;
}

INT_PTR CALLBACK DialogMain(HWND window, UINT uMsg, WPARAM wParam, LPARAM lParam) {

	HWND hwndOwner,hwndLink;
	RECT rc, rcDlg, rcOwner;

	size_t len, path_len;
	struct stat stbuf;

	HDROP query = (HDROP) wParam;

	switch(uMsg) {
		case WM_INITDIALOG:
			if((hwndOwner = GetParent(window)) == NULL) {
				hwndOwner = GetDesktopWindow(); 
			}

			GetWindowRect(hwndOwner, &rcOwner); 
			GetWindowRect(window, &rcDlg); 
			CopyRect(&rc, &rcOwner); 

			OffsetRect(&rcDlg, -rcDlg.left, -rcDlg.top); 
			OffsetRect(&rc, -rc.left, -rc.top); 
			OffsetRect(&rc, -rcDlg.right, -rcDlg.bottom); 

			SetWindowPos(window, 
				HWND_TOP, 
				rcOwner.left + (rc.right / 2), 
				rcOwner.top + (rc.bottom / 2), 
				0, 0, 
				SWP_NOSIZE);

			SetWindowTextA(window, DIALOG_TITLE);
				
			SendMessage(window, WM_SETICON, ICON_SMALL, (LPARAM)hicon);

			SendDlgItemMessage(window,INPUT_DLG1_AREA, EM_LIMITTEXT,MAX_INPUT_BASE64,0);

			if(RefreshKeyList(window,INPUT_DLG1_SELECT)>0) {
				EnableWindow(GetDlgItem(window, INPUT_DLG1_SELECT),TRUE);
				DragAcceptFiles(window,TRUE);
			} else {
				EnableWindow(GetDlgItem(window, INPUT_DLG1_SELECT),FALSE);
				DragAcceptFiles(window,FALSE);
			}
			
			SetWindowTextA(GetDlgItem(window,BUTTON_DLG1_MANAGE_KEYS),TXT_MANAGE);
			SetWindowTextA(GetDlgItem(window,BUTTON_DLG1_CRYPT),TXT_ENCRYPT);
			SetWindowTextA(GetDlgItem(window,BUTTON_DLG1_DELETE),TXT_DELETE);
			SetWindowTextA(GetDlgItem(window,BUTTON_DLG1_COPY),TXT_COPY);
			SetWindowTextA(GetDlgItem(window,IDC_GRP),TXT_KEYRING);
			SetWindowTextA(GetDlgItem(window,STATIC_DLG1_TEXT),TXT_MORE_INFOS);
			
			// mingw can not compile SysLink-Objects
			hwndLink = CreateWindowExA(0, WC_LINK, "<A HREF=\""URL"\">njör.de</A>", WS_CHILD | WS_VISIBLE | WS_TABSTOP,235,280,71,18, window, NULL, GetModuleHandle(NULL) , NULL);
			
			EnableWindow(GetDlgItem(window, BUTTON_DLG1_CRYPT),FALSE);
			SetFocus(GetDlgItem(window, INPUT_DLG1_AREA));

		return TRUE;
		case WM_DROPFILES:

			if(thread_status==THREAD_RUN) {
				thread_status = THREAD_DYING;
				while(thread_status!=THREAD_OFF) Sleep(100);
			}
		
			cryptfile.window = window;
	
			query = (HDROP) wParam;
			DragQueryFileA(query,0,cryptfile.path,MAX_PATH);
			DragFinish(query);
			
			if(stat(cryptfile.path,&stbuf)==0) {
				if(!(stbuf.st_mode & _S_IFREG)) {
					MessageBoxA(window, MSG_ERROR_ONLY_FILE, MSG_ERROR, MB_ICONERROR|MB_OK);
					return TRUE;
				}
			} else return TRUE;
			
			cryptfile.size = stbuf.st_size;
			
			path_len = strlen(cryptfile.path);
			if(path_len>=5&&byte_diff(cryptfile.path+path_len-6,6,".fritz")==0) {
				cryptfile.type = DECRYPT;
			} else {
				cryptfile.type = ENCRYPT;
			}
			
			cryptfile.progress_window = NULL;
			
			_beginthread(thread_crypt_file, 0, 0);
			
			if(stbuf.st_size>DROP_DIALOG_SIZE) {
				DialogBoxA(NULL, MAKEINTRESOURCE(DIALOG_PROGRESS_FILE), window, DialogProgressFile);
			}
			
			return TRUE;
		case WM_NOTIFY:
			switch(((LPNMHDR)lParam)->code) {
				case NM_CLICK:
				case NM_RETURN:
					ShellExecuteA(NULL, "open", URL, NULL, NULL, SW_SHOW);
				break;
			}
		return TRUE;

		case WM_COMMAND:
			switch(LOWORD(wParam)) {
				case IDCANCEL:
					SendMessage(window, WM_CLOSE, 0, 0);
					return TRUE;

				case BUTTON_DLG1_DELETE:
					SendDlgItemMessageA(window, INPUT_DLG1_AREA, WM_SETTEXT, 0, (LPARAM)"");
					SetFocus(GetDlgItem(window, INPUT_DLG1_AREA));
					return TRUE;
				case BUTTON_DLG1_COPY:
				
					len = SendDlgItemMessageA(window, INPUT_DLG1_AREA, WM_GETTEXTLENGTH, 0, 0);
					
					stralloc_zero(&sabuf);
					if(stralloc_ready(&sabuf,len)) {
						SendDlgItemMessageA(window, INPUT_DLG1_AREA, WM_GETTEXT, sabuf.a, (LPARAM)sabuf.s);
						sabuf.len = len;
					}
					stralloc_0(&sabuf);
					
					copyToClipboard(sabuf.s);
					return TRUE;

				case BUTTON_DLG1_MANAGE_KEYS:
					DialogBoxA(NULL, MAKEINTRESOURCE(DIALOG_MANAGE_KEYS), window, DialogManageKeys);
					if(RefreshKeyList(window,INPUT_DLG1_SELECT)>0) {
						EnableWindow(GetDlgItem(window, INPUT_DLG1_SELECT),TRUE);
						DragAcceptFiles(window,TRUE);
					} else {
						EnableWindow(GetDlgItem(window, INPUT_DLG1_SELECT),FALSE);
						DragAcceptFiles(window,FALSE);
					}
					return TRUE;

				case INPUT_DLG1_AREA:
			
	
					len = SendDlgItemMessageA(window, INPUT_DLG1_AREA, WM_GETTEXTLENGTH, 0, 0);

					if(len==0) {
						EnableWindow(GetDlgItem(window, BUTTON_DLG1_CRYPT),FALSE);
					} else {
						if(IsWindowEnabled(GetDlgItem(window, INPUT_DLG1_SELECT))) {
							EnableWindow(GetDlgItem(window, BUTTON_DLG1_CRYPT),TRUE);
						}
					}

					if(len<base64_len(crypto_box_NONCEBYTES)+1) {
						SetWindowTextA(GetDlgItem(window,BUTTON_DLG1_CRYPT),BUTTON_ENCR);
						return TRUE;
					}

					stralloc_zero(&sabuf);
					if(stralloc_ready(&sabuf,len)) {
						SendDlgItemMessageA(window, INPUT_DLG1_AREA, WM_GETTEXT, sabuf.a, (LPARAM)sabuf.s);
						sabuf.len = len;					
					}
					stralloc_0(&sabuf);
				
					if(isBase64(sabuf.s,BASE64_IGNORE_WHITESPACE)) { // decrypt
						SetWindowTextA(GetDlgItem(window,BUTTON_DLG1_CRYPT),BUTTON_DECR);
					} else { // encrypt
						SetWindowTextA(GetDlgItem(window,BUTTON_DLG1_CRYPT),BUTTON_ENCR);
					}

					return TRUE;

				case BUTTON_DLG1_CRYPT:

					if(thread_status==THREAD_RUN) {
						thread_status = THREAD_DYING;
						while(thread_status!=THREAD_OFF) Sleep(100);
					}
					
					cryptmessage.window = window;
					
					stralloc_zero(&sabuf);
					len = SendDlgItemMessageA(window, INPUT_DLG1_AREA, WM_GETTEXTLENGTH, 0, 0);
					if(len==0) return TRUE;

					if(stralloc_ready(&sabuf,len)) {
						SendDlgItemMessageA(window, INPUT_DLG1_AREA, WM_GETTEXT, sabuf.a, (LPARAM)sabuf.s);
						sabuf.len = len;
					}
					stralloc_0(&sabuf);
					
					if(len>base64_len(crypto_box_NONCEBYTES)+1 && isBase64(sabuf.s,BASE64_IGNORE_WHITESPACE)) {
						
						// crypted text
						stralloc_remove_whitespaces(&sabuf);
						
						cryptmessage.type = DECRYPT;
					} else {
					
						// shorten cleartext
						if(len>=MAX_INPUT) {
							sabuf.len = MAX_INPUT;
							stralloc_0(&sabuf);
							MessageBoxA(NULL, MSG_MESSAGE_TO_LONG, MSG_MESSAGE_TO_LONG_TITLE, MB_ICONWARNING|MB_OK);
						}
						cryptmessage.type = ENCRYPT;
					}
					
					_beginthread(thread_crypt_message, 0, 0);
					return TRUE;
			}
		break;	
		case WM_CLOSE:
			DestroyWindow(window);
			return TRUE;
		case WM_DESTROY:
			PostQuitMessage(0);
			return TRUE;
	}
	return FALSE;
}

INT_PTR CALLBACK DialogGetPassword(HWND window, UINT uMsg, WPARAM wParam, LPARAM lParam) {

	HWND hwndOwner;
	RECT rc, rcDlg, rcOwner;

	char password[MAX_PASSWORD+1];
	size_t len;

	char path[MAX_PATH];
	unsigned char n[crypto_stream_xsalsa20_NONCEBYTES];

	FILE *file;
	char file_buf[BUFSIZ];
	char buf[MAX_PATH*2];
	char buf64[MAX_PATH*2];
	
	int have_keyfile;

	struct stat stbuf;
	
	switch(uMsg) {
		case WM_INITDIALOG:
			if ((hwndOwner = GetParent(window)) == NULL) {
				hwndOwner = GetDesktopWindow(); 
			}

			GetWindowRect(hwndOwner, &rcOwner); 
			GetWindowRect(window, &rcDlg); 
			CopyRect(&rc, &rcOwner); 

			OffsetRect(&rcDlg, -rcDlg.left, -rcDlg.top); 
			OffsetRect(&rc, -rc.left, -rc.top); 
			OffsetRect(&rc, -rcDlg.right, -rcDlg.bottom); 

			SetWindowPos(window, 
				HWND_TOP, 
				rcOwner.left + (rc.right / 2), 
				rcOwner.top + (rc.bottom / 2), 
				0, 0, 
				SWP_NOSIZE);
			
			SetWindowTextA(GetDlgItem(window,STATIC_DLG5_TEXT),TXT_PASSWORD_FOR_PRIVATE_KEY);
			SetWindowTextA(GetDlgItem(window,BUTTON_DLG5_OK),TXT_OK);
			SetWindowTextA(GetDlgItem(window,BUTTON_DLG5_ABORT),TXT_ABORT);
			
			SendMessage(window, WM_SETICON, ICON_SMALL, (LPARAM)hicon);
			
			SendDlgItemMessage(window,INPUT_DLG5_PASSWD,EM_LIMITTEXT,MAX_PASSWORD,0);
			SendDlgItemMessage(window, INPUT_DLG5_PASSWD, EM_SETPASSWORDCHAR, '*', 0);

			EnableWindow(GetDlgItem(window, BUTTON_DLG5_OK),FALSE);

			SetFocus(GetDlgItem(window, INPUT_DLG5_PASSWD));
			
			SetWindowTextA(window, MSG_INSERT_PASSWORD);

		return TRUE;
		case WM_COMMAND:
			switch(LOWORD(wParam)) {
				case INPUT_DLG5_PASSWD:
				
					len = SendDlgItemMessageA(window, INPUT_DLG5_PASSWD, WM_GETTEXTLENGTH, 0, 0);
					if(len<MIN_PASSWORD_LEN) {
						EnableWindow(GetDlgItem(window, BUTTON_DLG5_OK),FALSE);
					} else {
						EnableWindow(GetDlgItem(window, BUTTON_DLG5_OK),TRUE);
					}
					
				return TRUE;
				case BUTTON_DLG5_ABORT:
					EndDialog(window,0);
					return TRUE;
	
				case IDOK:
				case BUTTON_DLG5_OK:
					SendDlgItemMessageA(window, INPUT_DLG5_PASSWD, WM_GETTEXT, MAX_PASSWORD, (LPARAM)password);
					
					len = strlen(password);
					crypto_hash_sha256(password_hash,password,len);
					rand_mem(password,MAX_PASSWORD);
					len = 0;
					
					file = secure_fopen(KEYFILE_PATH_STORE,"r",file_buf,sizeof file_buf);
					if(file) {
						fgets(buf64,sizeof(buf64),file);
						scan_base64(buf64,buf,&len);
						rand_mem(buf64,sizeof(buf64));
						secure_fclose(file,file_buf,sizeof file_buf);
					} else {
						MessageBoxA(NULL, MSG_KEYFILE_CAN_NOT_OPEN, MSG_ERROR, MB_ICONERROR|MB_OK);
						goto end_getpassword;
					}

					if(len>=MAX_PATH+crypto_stream_xsalsa20_NONCEBYTES) {
						byte_copy(n,crypto_stream_xsalsa20_NONCEBYTES,buf+MAX_PATH);
					} else {
						MessageBoxA(NULL, MSG_KEYFILE_ERROR, MSG_ERROR, MB_ICONERROR|MB_OK);
						goto end_getpassword;
					}
					
					// decrypt MAX_PATH bytes in path with password_hash -> hidden path len
					crypto_stream_xsalsa20_xor(path,buf,MAX_PATH,n,password_hash);

					if(byte_diff(path,strlen(KEYFILE_EMPTY_TEXT),KEYFILE_EMPTY_TEXT)==0) {
					
						// no keyfile
						EndDialog(window,1);
						return TRUE;

					} else {
					
						if(stat(path,&stbuf)==0) {

							cryptfile.type = FALSE; // this is a return code
							cryptfile.size = stbuf.st_size;
							cryptfile.window = window;
							cryptfile.progress_window = NULL;
							strncpy(cryptfile.path,path,MAX_PATH);
					
							_beginthread(thread_hash_file, 0, 0);
						
							if(stbuf.st_size>DROP_DIALOG_SIZE) {
								DialogBoxA(NULL, MAKEINTRESOURCE(DIALOG_PROGRESS_FILE), window, DialogProgressFile);
							}
						
							while(thread_status!=THREAD_OFF) Sleep(100);
						
							EndDialog(window,1);
							return TRUE;
						
						} else {
							
							MessageBoxA(NULL, MSG_WRONG_PASSWORD, MSG_ERROR, MB_ICONERROR|MB_OK);
							SendDlgItemMessageA(window, INPUT_DLG5_PASSWD, WM_SETTEXT, 0, (LPARAM)"");
							SetFocus(GetDlgItem(window, INPUT_DLG5_PASSWD));

							return TRUE;
						}
					}
end_getpassword:
					EndDialog(window,0);
					return TRUE;
			}
		case WM_CLOSE:
			EndDialog(window,0);
		return TRUE;
	}
	return FALSE;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE h0, LPSTR lpCmdLine, int nCmdShow) {

	HWND window = NULL;
	MSG msg;
	MEMORYSTATUS memstat;

	unsigned char sk[crypto_box_SECRETKEYBYTES];
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char key64[KEY64_SIZE];
	
	FILE *priv, *pub;
	char file_priv[BUFSIZ];
	char file_pub[BUFSIZ];
	
	size_t len;
	int i;
	struct stat st_priv, st_pub;
	char message[MAX_PATH];
	
	priv = pub = NULL;
	
	hicon = (HICON) LoadImage(hInst, MAKEINTRESOURCE(ICON_KEY), IMAGE_ICON,16,16,LR_DEFAULTSIZE); 
	
	thread_status = THREAD_OFF;
	
	stralloc_init(&sabuf);
	stralloc_init(&sabuf64);
	
	memstat.dwLength = sizeof (memstat);
	GlobalMemoryStatus(&memstat);
	
	srand((unsigned int)GetTickCount()^time(NULL)
		^memstat.dwMemoryLoad
		^memstat.dwTotalPhys
		^memstat.dwAvailPhys
		^memstat.dwTotalPageFile
		^memstat.dwAvailPageFile
		^memstat.dwTotalVirtual
		^memstat.dwAvailVirtual);
	
	CryptAcquireContext(&hCryptProv,NULL,NULL,PROV_RSA_FULL,0);

#ifdef WITH_LIBSODIUM
	sodium_init();
#endif
	
	if(!stralloc_ready(&sabuf,base64_len(MAX_INPUT)+4)||
		!stralloc_ready(&sabuf64,base64_len(MAX_INPUT)+4)) {
		MessageBoxA(NULL, MSG_OUT_OF_MEM_CAN_NOT_START, MSG_ERROR, MB_ICONERROR|MB_OK);
		goto err;
	}
	
	if(test_crypto_stream_xsalsa20_xor()==0||
		test_crypto_hash_sha256()==0||
		test_crypto_hashblocks_sha256()==0||
		test_crypto_box_static()==0||
		test_crypto_box_beforenm_and_afternm()==0) {
		MessageBoxA(NULL, MSG_CRYPTO_TEST_ERROR, MSG_ERROR, MB_ICONERROR|MB_OK);
		goto err;
	}
	
	if(stat(KEY_PUB,&st_pub)<0||stat(KEY_PRIV,&st_priv)<0) {

create_new_keys:
		if(MessageBoxA(NULL, MSG_KEYS_NOT_FOUND, MSG_KEYS_NOT_FOUND_TITLE, MB_ICONWARNING|MB_OKCANCEL) == IDCANCEL) {
			goto err;
		}
		
		memset(key_file_hash,0,crypto_hash_sha256_BYTES);
		memset(password_hash,0,crypto_hash_sha256_BYTES);
		if(DialogBoxA(NULL, MAKEINTRESOURCE(DIALOG_CREATE_PASSWORD), NULL, DialogCreatePassword)==0) {
			goto err;
		}
		
		crypto_box_keypair(pk,sk);

		// encrypt secret key
		for(i=0;i<crypto_box_SECRETKEYBYTES;++i) {
			sk[i] = sk[i]^password_hash[i]^key_file_hash[i];
		}
	
		pub = secure_fopen(KEY_PUB,"w",file_pub,sizeof file_pub);
		if(pub) {
			key64[fmt_base64(key64,pk,crypto_box_PUBLICKEYBYTES)]=0;
			fputs(key64,pub);
			rand_mem(key64,KEY64_SIZE);
			secure_fclose(pub,file_pub,sizeof file_pub);
		}
		rand_mem(pk,crypto_box_PUBLICKEYBYTES);

		priv = secure_fopen(KEY_PRIV,"w",file_priv,sizeof file_priv);
		if(priv) {
			key64[fmt_base64(key64,sk,crypto_box_SECRETKEYBYTES)]=0;
			fputs(KEY_PRIV_WARNING,priv);
			fputs(key64,priv);
			rand_mem(key64,KEY64_SIZE);
			secure_fclose(priv,file_priv,sizeof file_priv);
		}
		rand_mem(sk,crypto_box_SECRETKEYBYTES);
	} else {

		memset(key_file_hash,0,crypto_hash_sha256_BYTES);
		memset(password_hash,0,crypto_hash_sha256_BYTES);

		// get password
		if(DialogBoxA(NULL, MAKEINTRESOURCE(DIALOG_GET_PASSWORD), NULL, DialogGetPassword)==0) {
			goto err;
		}
		
		if(stat(KEYFILE_PATH_STORE,&st_pub)==0) {
	
			// last password reset > 100 days -> must change
			if(time(NULL)>(60*60*24*100)+st_pub.st_mtime) {

				if(MessageBoxA(NULL, MSG_PASSWORD_TO_OLD, MSG_PASSWORD_TO_OLD_TITLE, MB_ICONWARNING|MB_OKCANCEL) == IDCANCEL) {
					goto err;
				}			

				priv = secure_fopen(KEY_PRIV,"r",file_priv,sizeof file_priv);
				if(priv) {
					fseek(priv,strlen(KEY_PRIV_WARNING),SEEK_CUR);
					fgets(key64,KEY64_SIZE,priv);
					scan_base64(key64,sk,&len);
					rand_mem(key64,KEY64_SIZE);
					secure_fclose(priv,file_priv,sizeof file_priv);
				} else {
					snprintf(message, sizeof(message), MSG_CAN_NOT_LOAD_KEY, KEY_PRIV);
					MessageBoxA(NULL, message, MSG_ERROR, MB_ICONERROR|MB_OK);
					goto err;
				}
				
				// decrypt key
				for(i=0;i<crypto_box_SECRETKEYBYTES;++i) {
					sk[i] = sk[i]^password_hash[i]^key_file_hash[i];
				}
	
				// set new hashes
				if(DialogBoxA(NULL, MAKEINTRESOURCE(DIALOG_CREATE_PASSWORD), window, DialogCreatePassword)==0) {
					rand_mem(sk,crypto_box_SECRETKEYBYTES);
					goto err;
				}
			
				// encrypt key
				for(i=0;i<crypto_box_SECRETKEYBYTES;++i) {
					sk[i] = sk[i]^password_hash[i]^key_file_hash[i];
				}

				priv = secure_fopen(KEY_PRIV,"w",file_priv,sizeof file_priv);
				if(priv) {
					key64[fmt_base64(key64,sk,crypto_box_SECRETKEYBYTES)]=0;
					fputs(KEY_PRIV_WARNING,priv);
					fputs(key64,priv);
					rand_mem(key64,KEY64_SIZE);
					secure_fclose(priv,file_priv,sizeof file_priv);
				}
				rand_mem(sk,crypto_box_SECRETKEYBYTES);
				
				for(i=crypto_hash_sha256_BYTES-1;i>0;i--) {
					if(key_file_hash[i]!=0) break;
				}
				if(i==0) {
					MessageBoxA(NULL, MSG_PASSWORD_CHANGED_NO_KEYFILE, MSG_NEW_PASSWORD, MB_ICONINFORMATION|MB_OK);
				} else {
					MessageBoxA(NULL, MSG_PASSWORD_CHANGED_KEYFILE, MSG_NEW_PASSWORD_KEYFILE, MB_ICONINFORMATION|MB_OK);
				}
			}
		} else {
			goto create_new_keys;
		}
	}
		
	window = CreateDialogParam(hInst, MAKEINTRESOURCE(DIALOG_MAIN), 0, DialogMain, 0);
	if(window == NULL) goto err;
	ShowWindow(window, nCmdShow);
	UpdateWindow(window);

	while(GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg); 
		DispatchMessage(&msg); 
	}
err:

	rand_mem(key_file_hash,crypto_hash_sha256_BYTES);
	rand_mem(password_hash,crypto_hash_sha256_BYTES);

	rand_mem(sabuf.s,sabuf.a);
	rand_mem(sabuf64.s,sabuf64.a);
	
	stralloc_free(&sabuf);
	stralloc_free(&sabuf64);

	CryptReleaseContext(hCryptProv, 0);
	
	return 0;
}
