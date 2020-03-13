#include <iostream>
#include <Windows.h>

byte function[] = { 0xC7, 0x04, 0xBD, 0xE8, 0x2A, 0x56, 0x00, 0x05, 0x00, 0x00, 0x00, 0xE9, 0xFF, 0xFF, 0xFF, 0xFF };


bool hook_x86(const HANDLE p_handle, const DWORD address_hook, const int nop, byte* function)
{
	if (!p_handle || p_handle == INVALID_HANDLE_VALUE)
	{
		std::cout << "[ERROR]\tHandle invalid\n";
		return false;
	}
	/*Byte function*/
	
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

bool hook_x64(const HANDLE p_handle, const intptr_t address_hook, const int nop)
{
	if (!p_handle || p_handle == INVALID_HANDLE_VALUE)
	{
		std::cout << "[ERROR]\tHandle invalid\n";
		return false;
	}
	/*Byte function*/
	byte function[] = { 0x50, 0x48, 0x8D, 0x04, 0x8F, 0x81, 0x78, 0x14, 0xFF, 0xFF, 0x00, 0x00, 0x0F, 0x84, 0x03, 0x00, 0x00, 0x00, 0x89, 0x34, 0x8F,
		0x44, 0x0F, 0xB7, 0x57, 0x52, 0x58, 0x4C, 0x01, 0xD0, 0x3B, 0x2C, 0x87,
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x36, 0x84, 0x46, 0xF7, 0x7F, 0x00, 0x00 };
	/*Address of hook function*/
	const auto address = reinterpret_cast<intptr_t>(VirtualAllocEx(p_handle, nullptr, 2048, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
	/*Address of back to original function*/

	std::cout << "\n[JMP_ADDRESS]\t | 0x" << std::hex << address << std::endl;

	/*create the jmp`s*/
	byte jmp[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	byte x = 0x90;
	std::cout << "[BACK_ADDRESS]\t | 0x" << std::hex << address_hook << std::endl;
	*reinterpret_cast<intptr_t*>((&function[sizeof(function) - 8])) = address_hook;
	*reinterpret_cast<intptr_t*>(&jmp[6]) = (address + 14);


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

	if (!WriteProcessMemory(p_handle, reinterpret_cast<void*>(address), function, sizeof(function), nullptr))
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
	const auto window_game = FindWindowA(nullptr, "Trine 3: The Artifacts of Power");
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
	
	if (hook_x64(p_handle, 0x7FF746843604, 8))
		std::cout << "\Gotcha!! HOOK\n";
	else
		std::cout << "\nNot hook\n";

	/*End*/
	CloseHandle(p_handle);
	std::cout << "Press any ENTER or close the window\n";
	std::cin.get();
	return 0;
}