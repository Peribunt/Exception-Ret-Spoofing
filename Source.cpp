#include <windows.h>
#include <cstdio>

#define MAGIC_SPOOF_RETADDR_NUMBER 0xDEADBEEF00000001

#define CONSOLE_LOG( Fmt, ... ) \
printf( "[!] " __FUNCTION__ ": " Fmt "\n", ##__VA_ARGS__ )

namespace ReturnSpoofer
{
	LPVOID FunctionToCall;
	LPVOID FakeReturnAddress;
	LPVOID ReturnAddressBackup;
	
	__forceinline
	VOID WINAPI SetupSpoofCall(
		IN LPVOID Function,
		IN LPVOID FakeRet ) 
		noexcept
	{
		FunctionToCall = Function;
		FakeReturnAddress = FakeRet;
	}

	extern "C"
	ULONG_PTR SpoofCall(
		IN ... );
	
	template< typename _RET_TYPE_, 
	typename... _VA_ARGS_ >
	__forceinline
	_RET_TYPE_ WINAPI DoSpoofCall(
		IN LPVOID Function,
		IN LPVOID FakeRet,
		IN OUT _VA_ARGS_... Args OPTIONAL )
		noexcept
	{
		FunctionToCall = Function;
		FakeReturnAddress = FakeRet;
		
		( ( _RET_TYPE_( * )( IN OUT ... OPTIONAL ) )&SpoofCall )
			( Args... );
	}
}

LONG WINAPI VectoredHandler( IN LPEXCEPTION_POINTERS ExceptionPointers )
{
	const PCONTEXT				ContextRecord   = ExceptionPointers->ContextRecord;
	const LPEXCEPTION_RECORD	ExceptionRecord = ExceptionPointers->ExceptionRecord;

	//
	// Hit an access violation
	//
	if ( ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION )
	{
		//
		// Did the exception deliberately occur inside our SpoofCall ASM proc?
		//
		if ( ContextRecord->Rax == MAGIC_SPOOF_RETADDR_NUMBER )
		{
			ReturnSpoofer::ReturnAddressBackup = *(LPVOID*)( ContextRecord->Rsp );

			*( LPVOID* )( ContextRecord->Rsp ) = ReturnSpoofer::FakeReturnAddress;

			CONSOLE_LOG( "Old return address: %p", ReturnSpoofer::ReturnAddressBackup );
			CONSOLE_LOG( "New return address: %p", ReturnSpoofer::FakeReturnAddress );

			ContextRecord->Rip = (ULONG64)ReturnSpoofer::FunctionToCall;
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	//
	// Hit a trap instruction
	//
	if ( ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT )
	{
		if ( ExceptionRecord->ExceptionAddress == ReturnSpoofer::FakeReturnAddress )
		{
			CONSOLE_LOG( "Returning back to %p...", ReturnSpoofer::ReturnAddressBackup );

			ContextRecord->Rip = (ULONG64)ReturnSpoofer::ReturnAddressBackup;
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

	//
	// Set up the spoof call for MessageBoxA
	// Make the return address a 0xCC anywhere in the executable region of the module I suppose
	//
	ReturnSpoofer::SetupSpoofCall( 
		MessageBoxA, ( LPVOID )( ( ULONG64 )MessageBoxA - 1 ) );

	//
	// Call the MessageBoxA function with a spoofed return address
	//
	DWORD Result = 
		ReturnSpoofer::SpoofCall( NULL, "Hello World", "Spoofed call", NULL );

	//
	// Log to prove both execution flow lands here and the value returned properly
	//
	CONSOLE_LOG( "MessageBoxA Result: %i", Result );

	//
	// Remove the vectored handler
	//
	RemoveVectoredExceptionHandler( ExceptionHandler );

	system( "pause" );

	return NULL;
}
