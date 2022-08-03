#pragma once

#include <Windows.h>
#include <cstdio>

#define CONSOLE_LOG( Message, ... ) \
printf( "[!] " __FUNCTION__ ": " Message "\n", ##__VA_ARGS__ )

#define CONSOLE_PAUSE( ) \
system( "pause" )

#define SPOOFER_MAGIC		0xDEADC0DE00000001
#define SPOOFER_AS_CODE		__declspec( allocate( ".text" ) )
#define SPOOFER_INLINE		__forceinline
#define SPOOFER_NOINLINE	__declspec( noinline )

#pragma code_seg( push, ".text" )
SPOOFER_AS_CODE BYTE SpoofCall_Shellcode[ 24 ] = 
{
	//
	// Spoof call preparation 
	//
	0x66, 0x4C, 0x0F, 0x6E, 0xF9,			//movq xmm15, rcx
	0x66, 0x4C, 0x0F, 0x3A, 0x22, 0xFA, 0x01,	//pinsrq xmm15, rdx, 1
	0xC3,

	//
	// Spoof call execution
	//
	0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xDE, 0xC0, 0xAD, 0xDE, 	//mov rax, SPOOFER_MAGIC_NUMBER
	0xFB								//sti
};
#pragma code_seg( pop )

#pragma optimize( "", off )
template< typename _RET_TYPE_, 
	typename... _VA_ARGS_ >
SPOOFER_NOINLINE
_RET_TYPE_
DoSpoofCall( 
	IN LPVOID FunctionToCall, 
	IN LPVOID FakeRetAddr,
	IN OUT _VA_ARGS_... Args OPTIONAL
	)
{
	//
	// Prepare the spoof call
	// Moves the function to call into XMM15.Low and the fake ret into XMM15.High
	//
	( ( VOID( * )( IN LPVOID, IN LPVOID ) )&SpoofCall_Shellcode[ NULL ] )
		( FunctionToCall, FakeRetAddr );

	//
	// Start the spoof call by deliberately causing an exception
	//
	return ( ( _RET_TYPE_( * )( IN OUT ... OPTIONAL ) )&SpoofCall_Shellcode[ 13 ] )
		( Args... );
}
#pragma optimize( "", on )

LONG 
WINAPI 
VectoredHandler( 
	IN LPEXCEPTION_POINTERS ExceptionPointers 
	)
{
	CONST LPEXCEPTION_RECORD ExceptionRecord 
		= ExceptionPointers->ExceptionRecord;

	CONST LPCONTEXT			 ContextRecord	 
		= ExceptionPointers->ContextRecord;

	//
	// Hit a privileged instruction
	//
	if ( ExceptionRecord->ExceptionCode == STATUS_PRIVILEGED_INSTRUCTION )
	{
		if ( ContextRecord->Rax == SPOOFER_MAGIC )
		{
			//
			// Swapping XMM15.High with the real return address 
			//
			ContextRecord->Xmm15.High = InterlockedExchange64(
				( LONG64* )ContextRecord->Rsp, ContextRecord->Xmm15.High );

			//
			// Setting the instruction pointer to the function we want to call and spoof
			//
			ContextRecord->Rip = ContextRecord->Xmm15.Low;

			//
			// Save the fake return address to efficiently check return exception
			//
			ContextRecord->Xmm15.Low = *( ULONG64* )( ContextRecord->Rsp );

			CONSOLE_LOG( "Old return address: %p", ContextRecord->Xmm15.High );
			CONSOLE_LOG( "New return address: %p", ContextRecord->Xmm15.Low );

			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	//
	// Exception occured on our return address
	//
	if ( ExceptionRecord->ExceptionAddress == ( LPVOID )( ContextRecord->Xmm15.Low ) )
	{
		//
		// Set the instruction pointer to the original return address
		//
		ContextRecord->Rip = ContextRecord->Xmm15.High;

		CONSOLE_LOG( "Returning back to %p...", ContextRecord->Xmm15.High );

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

LONG 
main( 
	VOID
	)
{
	//
	// Add a vectored handler ( Of course you can also use KiUserExceptionDispatcher directly )
	//
	LPVOID VEH = AddVectoredExceptionHandler( TRUE, VectoredHandler );

	//
	// Spoof call MessageBoxA
	//
	DWORD Result = DoSpoofCall<DWORD>( MessageBoxA, ( PBYTE )( MessageBoxA )-1, 
		NULL, "Hello World", "Spoofed call", NULL );

	//
	// Log to prove both execution flow lands here and the value returned properly
	//
	CONSOLE_LOG( "MessageBoxA Result: %i", Result );

	//
	// Remove the vectored handler
	//
	RemoveVectoredExceptionHandler( VEH );

	CONSOLE_PAUSE( );
}
