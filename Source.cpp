#include <windows.h>
#include <cstdio>

#define MAGIC_SPOOF_RETADDR_NUMBER 0xDEADBEEF00000001

#define SPOOFER_NOINLINE __declspec( noinline )
#define SPOOFER_INLINE __forceinline

#define CONSOLE_PAUSE( ) \
system( "pause" )

#define CONSOLE_LOG( Fmt, ... ) \
printf( "[!] " __FUNCTION__ ": " Fmt "\n", ##__VA_ARGS__ )

namespace ReturnSpoofer
{
	extern "C" 
		ULONG_PTR SpoofCall(
			IN ... );

	extern "C"
		VOID InitSpoofCall(
			IN LPVOID Function,
			IN LPVOID FakeRet );

	template< typename _RET_TYPE_,
		typename... _VA_ARGS_ >
		SPOOFER_NOINLINE
		_RET_TYPE_ WINAPI DoSpoofCall(
			IN LPVOID Function,
			IN LPVOID FakeRet,
			IN OUT _VA_ARGS_... Args OPTIONAL )
		noexcept
	{
		InitSpoofCall( Function, FakeRet );

		return ( ( _RET_TYPE_( * )( IN OUT ... OPTIONAL ) )SpoofCall )
			( Args... );
	}
}

LONG WINAPI VectoredHandler( IN LPEXCEPTION_POINTERS ExceptionPointers )
{
	const PCONTEXT				ContextRecord = ExceptionPointers->ContextRecord;
	const LPEXCEPTION_RECORD	ExceptionRecord = ExceptionPointers->ExceptionRecord;

	//
	// Hit a privileged instruction
	//
	if ( ExceptionRecord->ExceptionCode == STATUS_PRIVILEGED_INSTRUCTION )
	{
		//
		// Did the exception deliberately occur inside our SpoofCall ASM proc?
		//
		if ( ContextRecord->Rax == MAGIC_SPOOF_RETADDR_NUMBER )
		{
			ContextRecord->Rbx = *(ULONG_PTR*)( ContextRecord->Rsp );

			*(ULONG64*)( ContextRecord->Rsp ) = ContextRecord->Rdi;

			CONSOLE_LOG( "Old return address: %p", ContextRecord->Rbx );
			CONSOLE_LOG( "New return address: %p", ContextRecord->Rdi );

			ContextRecord->Rip = ContextRecord->Rsi;
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	//
	// Hit a interrupt 3 instruction ( CC )
	//
	if ( ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT )
	{
		if ( ExceptionRecord->ExceptionAddress == (LPVOID)ContextRecord->Rdi )
		{
			CONSOLE_LOG( "Returning back to %p...", ContextRecord->Rbx );

			ContextRecord->Rip = ContextRecord->Rbx;
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

LONG main( VOID )
{
	//
	// Add a vectored handler ( Of course you can also use KiUserExceptionDispatcher )
	//
	LPVOID ExceptionHandler =
		AddVectoredExceptionHandler( TRUE, VectoredHandler );

	DWORD Result =
		ReturnSpoofer::DoSpoofCall<DWORD>( MessageBoxA, (PBYTE)(MessageBoxA)-1,
			NULL, "Hello World", "Spoofed call", NULL );

	//
	// Log to prove both execution flow lands here and the value returned properly
	//
	CONSOLE_LOG( "MessageBoxA Result: %i", Result );

	//
	// Remove the vectored handler
	//
	RemoveVectoredExceptionHandler( ExceptionHandler );

	CONSOLE_PAUSE( );

	return NULL;
}
