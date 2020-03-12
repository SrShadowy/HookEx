#include <iostream>
#include <Windows.h>

bool hook_x32(const HANDLE p_handle, const DWORD address_hook, const int nop)
{
	if (!p_handle || p_handle == INVALID_HANDLE_VALUE)
	{
		std::cout << "[ERROR]\tHandle invalid\n";
		return false;
	}
	/*Byte function*/
	byte function[] = { 0xC7, 0x04, 0xBD, 0xE8, 0x2A, 0x56, 0x00, 0x05, 0x00, 0x00, 0x00, 0xE9, 0xFF, 0xFF, 0xFF, 0xFF };
	/*Address of hook function*/
	auto address = reinterpret_cast<unsigned long>( VirtualAllocEx(p_handle, nullptr, 2048, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
	/*Address of back to original function*/
	const auto address_back = address_hook - address - sizeof(function) + nop;
	std::cout << "\n[JMP_ADDRESS]\t | 0x" << std::hex << address << std::endl;

	/*create the jmp`s*/
	byte jmp[5];
	jmp[0] = 0xE9;
	byte x = 0x90;
	const auto ad_function = address;
	address = address - address_hook -5;
	std::cout << "[BACK_ADDRESS]\t | 0x" << std::hex << address_back << std::endl;
	std::cout << "[OFFSET]\t | 0x" << std::hex << address << std::endl;
	*reinterpret_cast<long unsigned*>((&function[sizeof(function) - 4])) = address_back;
	*reinterpret_cast<long unsigned*>(&jmp[1]) = address;


	//Executions and write on extern process

	long unsigned old_proc;
	if (!VirtualProtectEx(p_handle, reinterpret_cast<LPVOID>(address_hook), nop, (0x0020), &old_proc))
		std::cout << "\n[OPC]\tI not can change the proc\n";

		
	for (auto i = 0; i < nop; ++i)
	{ 
		if (!WriteProcessMemory(p_handle, reinterpret_cast<LPVOID>(address_hook + i), &x, sizeof(x), nullptr))
		{ 
			std::cout << "\n[ERROR]\tNot nop`s\n";
			return false;
		}
	}

	if (!WriteProcessMemory(p_handle, reinterpret_cast<void*>(ad_function), function, sizeof(function), nullptr))
	{
		std::cout << "\n[ERROR]\tNot write on process function\n";
		return false;
	}
	
	if (!WriteProcessMemory(p_handle, reinterpret_cast<void*>(address_hook), jmp, sizeof(jmp), nullptr))
	{
		std::cout << "\n[ERROR]\tNot write the hook\n";
		return false;
	}

	if (!VirtualProtectEx(p_handle, reinterpret_cast<void*>(address_hook), nop, old_proc, nullptr))
		std::cout << "\n[OPC]\tI not can restoration proc\n";


	return true;
}

int main()
{
	unsigned long pid = 0;
	std::cout << "Welcome!\n";
	/******************[optional]********************
	 *	Get handle_window of process with name window
	 */
	const auto window_game = FindWindowA(nullptr, "Nice Game Console");
	/*Get ID_Process*/
	const auto thread_id = GetWindowThreadProcessId(window_game, &pid);

	//CHECK!
	if (pid)
		std::cout << "Gotcha!! find process!: " << pid << std::endl;

	std::cout << "Thread ID: " << thread_id << std::endl;

	/*Open The handle of process*/
	const auto p_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

	/*
	 ********************HOW USE*************************
	 *need handle with ( WRITE & EXECUTION )
	 *The address of function to be used as a hook
	 *And the size of instruction
	 ***************************************************
	 */
	
	if (hook_x32(p_handle, 0x00445DDD, 7))
		std::cout << "\Gotcha!! HOOK\n";
	else
		std::cout << "\nNot hook\n";

	/*End*/
	std::cout << "Press any ENTER or close the window\n";
	std::cin.get();
	return 0;
}