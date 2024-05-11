using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);



    static void Main(string[] args)
    {
        Console.Title = GenerateRandomString(8); // Set the console window title to a random string to avoid detection

        Console.WriteLine("Enter the full path of the DLL:");
        string dllPath = Console.ReadLine();

        if (!File.Exists(dllPath))
        {
            Console.WriteLine("DLL not found at the specified path.");
            return;
        }

        string processName = "Target.exe"; // Whatever the name of the process you are trying to inject into is

        int processId = GetProcessIdByName(processName);
        if (processId == 0)
        {
            Console.WriteLine("Process not found.");
            return;
        }

        IntPtr processHandle = OpenProcess(0x001F0FFF, false, processId); // All possible access rights
        if (processHandle == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open process.");
            return;
        }

        byte[] dllBytes = File.ReadAllBytes(dllPath);

        IntPtr allocatedMemory = VirtualAllocEx(processHandle, IntPtr.Zero, (uint)dllBytes.Length, 0x1000, 0x40); // Allocation type: MEM_COMMIT (0x1000), Protection: PAGE_EXECUTE_READWRITE (0x40)
        if (allocatedMemory == IntPtr.Zero)
        {
            Console.WriteLine("Failed to allocate memory in target process.");
            return;
        }

        int bytesWritten;
        if (!WriteProcessMemory(processHandle, allocatedMemory, dllBytes, (uint)dllBytes.Length, out bytesWritten) || bytesWritten != dllBytes.Length)
        {
            Console.WriteLine("Failed to write DLL bytes to target process memory.");
            return;
        }

        IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
        if (loadLibraryAddr == IntPtr.Zero)
        {
            Console.WriteLine("Failed to get address of LoadLibraryA function.");
            return;
        }

        IntPtr remoteThread = CreateRemoteThread(processHandle, IntPtr.Zero, 0, loadLibraryAddr, allocatedMemory, 0, IntPtr.Zero);
        if (remoteThread == IntPtr.Zero)
        {
            Console.WriteLine("Failed to create remote thread in target process.");
            return;
        }

        Console.WriteLine("DLL injected successfully.");
    }

    static int GetProcessIdByName(string processName)
    {
        Process[] processes = Process.GetProcessesByName(processName);
        if (processes.Length > 0)
            return processes[0].Id;
        else
            return 0;
    }

    static string GenerateRandomString(int length)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+=-<>";
        var random = new Random();
        return new string(Enumerable.Repeat(chars, length)
          .Select(s => s[random.Next(s.Length)]).ToArray());
    }
}
