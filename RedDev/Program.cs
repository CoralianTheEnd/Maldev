using RedDev.Shellcode;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RedDev
{
    internal class Program
    {
        // # Managed delegate for our shell code function
        private delegate IntPtr Delegate_PEBShellCode();

        // # Our shellcode to execute
        private static byte[] Shellcode_ReadFSWord30 = new byte[]
        {
            0x64, 0xA1, 0x30, 0x00, 0x00, 0x00,         // mov eax, dword ptr fs:[30]
            0xC3                                        // ret
        };

        static void Main(string[] args)
        {
            // # Cast our newly stage shellcode to a managed delegate
            Delegate_PEBShellCode GetPebAddress =
                (Delegate_PEBShellCode)SharpStager.StageShellcode<Delegate_PEBShellCode>(Shellcode_ReadFSWord30);

            // # Execute our new function
            IntPtr pebAddress = GetPebAddress();

            Console.WriteLine("PEB is located at: 0x{0:X8}", pebAddress);

            Console.ReadKey();
        }
    }
}
