using System;
using System.Runtime.InteropServices;
using System.Text;

namespace DarpaInjector.UI
{
    public static class InjectorBinding
    {
        private const string DllName = "DarpaInjector.Core.dll";

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool InjectRemote(int pid, string dllPath, int method);
        
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool EnablePrivileges();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int GetDebugLog(StringBuilder buffer, int size);
    }
}
