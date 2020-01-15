/**
 * os_wrapper.h
 *
 *  Created on: دسامبر ۲۴, ۲۰۱۱
 *      Author: Hedayat Vatankhah <hedayat.fwd@gmail.com>.
 */

#ifndef OS_WRAPPER_H_
#define OS_WRAPPER_H_

#include <stddef.h>

#ifdef __linux__
#define _GNU_SOURCE
#include <semaphore.h>
#include <pthread.h>
#include <wtypes.h>
#include <stdio.h>
#include <errno.h>
#else // windows headers
#include <WTypes.h>
#include <Windows.h>
#endif

#ifdef __linux__
#ifdef _DEBUG
#define FILE_WRITE_DATA 1
#define FILE_SHARE_WRITE 1
#define OPEN_ALWAYS 1
#define FILE_ATTRIBUTE_NORMAL 1
#define FILE_END SEEK_END
#endif

#define INFINITE -1

#define _T(A) (A)
#define _U(S) (S)
#define unicode_sstr strstr
#define SEMAPHORE_ALL_ACCESS 1
#define EVENT_ALL_ACCESS 1
#define WAIT_TIMEOUT ETIMEDOUT
#define WAIT_OBJECT_0 0
typedef struct SemaphoreData
{
	int named;
	char cName[512];
	sem_t *semaphore;
}*Semaphore;
typedef struct EventData
{
	int			named;
	char		cName[512];
	char		filePath[512];
	Semaphore	sem;
	Semaphore	unlockSem;
	int 		fd;
}*Event;
typedef pthread_t *Thread;
typedef pthread_mutex_t *Mutex;
typedef void *ThreadResult;
typedef char unicode_char;
typedef void* HANDLE;
typedef char WCHAR;
typedef void* PSECURITY_ATTRIBUTES;
#else // windows types

#define _U(S) (L##S)
#define unicode_sstr wcsstr

typedef HANDLE Semaphore;
typedef HANDLE Thread;
typedef HANDLE Mutex;
typedef HANDLE Event;
typedef DWORD ThreadResult;
typedef wchar_t unicode_char;

#endif

#define INVALID_SEMAPHORE	NULL
#define INVALID_EVENT		NULL
#define INVALID_MUTEX		NULL
#define INVALID_THREAD		NULL

typedef ThreadResult (CALLBACK *ThreadFunction)(void *);

/* Semaphore functions */
Semaphore GetSemaphore(PSECURITY_ATTRIBUTES pSecAttr, DWORD dwDesiredAccess, int initial_value,
		const WCHAR *name);
int LockSemaphore(Semaphore sem, int milli_seconds_timeout);
int UnlockSemaphore(Semaphore sem);
void CloseSemaphore(Semaphore *semptr);

/* Event functions */
Event GetEvent(DWORD dwDesiredAccess, const WCHAR *name, BOOL manualReset, BOOL initialState, BOOL setACL);
int LockEvent(Event evn, int milli_seconds_timeout);
int UnlockEvent(Event evn);
void CloseEvent(Event *evn);

/* Mutex functions */
Mutex InitMutex();
int LockMutex(Mutex mutex, int milli_seconds_timeout);
int UnlockMutex(Mutex mutex);
void DestroyMutex(Mutex *mutex);

/* Thread functions */
Thread StartThread(ThreadFunction threadfn, void *param, DWORD *id);
int JoinThread(Thread thread, int milli_seconds_timeout);
void FreeThread(Thread *thread);
void CancelThreadIO(Thread *thread);

/* Atomic Operations */
long AtomicIncrement(long *valptr);
long AtomicDecrement(long *valptr);
long AtomicExchange(long *valptr, long new_val);
long AtomicCompareExchange(size_t *valptr, long compare_val, size_t new_val);

/* Filesystem Functions */
int GetFileExtension(const unicode_char *filepath, unicode_char *ext,
		int extsize);

/* CloseFile is equal to CloseHandle in windows .*/
void CloseFile(HANDLE hFile);
#ifdef __linux__

#define _wcsicmp _tcsicmp
#define strcpy_s _tcscpy_s
#define wcscpy_s _tcscpy_s
#define GetCurrentProcessId getpid
#define GetCurrentThreadId getpid //TODO Fix it by calling gettid or syscall(SYS_gettid)
#define GetTickCount _l_GetTickCount
#define SetFilePointer _l_SetFilePointer
#define CreateFile _l_CreateFile
#define WriteFile _l_WriteFile

void QueryPerformanceCounter(int64_t *counter);
void _tcscpy_s(char *dest, int num, const char * src);
int _tcsicmp(const char *first, const char *second);
int _wfopen_s(FILE **file_ptr, unicode_char *filename, const char *mode);
unsigned long _l_GetTickCount();
void _l_SetFilePointer(HANDLE hFile, long lDistanceToMove, long* lpDistanceToMoveHigh, DWORD dwMoveMethod);
int _l_CreateFile(char* lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, DWORD lpSecurityAttributes,
		DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
void _l_WriteFile(HANDLE hFile, char* buffer, int bufferLength, char* lpWriteBuffer, int* lpWriteBufferLength);

#endif

#endif /* OS_WRAPPER_H_ */
