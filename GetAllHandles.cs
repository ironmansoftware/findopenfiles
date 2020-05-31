// Get all system open handles method - uses NTQuerySystemInformation and NTQueryObject
//https://gist.github.com/i-e-b/2290426
//https://stackoverflow.com/a/13735033/2999220


using System;
using System.Collections.Generic;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace GetAllHandles
{
    public static class HandleUtil
    {
        public enum HandleType
        {
            Unknown,
            Other,
            File, Directory, SymbolicLink, Key,
            Process, Thread, Job, Session, WindowStation,
            Timer, Desktop, Semaphore, Token,
            Mutant, Section, Event, KeyedEvent, IoCompletion, IoCompletionReserve,
            TpWorkerFactory, AlpcPort, WmiGuid, UserApcReserve,
        }

        public enum NT_STATUS
        {
            STATUS_SUCCESS = 0x00000000,
            STATUS_BUFFER_OVERFLOW = unchecked((int)0x80000005L),
            STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004L)
        }

        public enum SYSTEM_INFORMATION_CLASS
        {
            SystemBasicInformation = 0,
            SystemPerformanceInformation = 2,
            SystemTimeOfDayInformation = 3,
            SystemProcessInformation = 5,
            SystemProcessorPerformanceInformation = 8,
            SystemHandleInformation = 16,
            SystemInterruptInformation = 23,
            SystemExceptionInformation = 33,
            SystemRegistryQuotaInformation = 37,
            SystemLookasideInformation = 45
        }

        public enum OBJECT_INFORMATION_CLASS
        {
            ObjectBasicInformation = 0,
            ObjectNameInformation = 1,
            ObjectTypeInformation = 2,
            ObjectAllTypesInformation = 3,
            ObjectHandleInformation = 4
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SystemHandleEntry
        {
            public int OwnerProcessId;
            public byte ObjectTypeNumber;
            public byte Flags;
            public ushort Handle;
            public IntPtr Object;
            public int GrantedAccess;
        }

        [DllImport("ntdll.dll")]
        internal static extern NT_STATUS NtQuerySystemInformation(
            [In] SYSTEM_INFORMATION_CLASS SystemInformationClass,
            [In] IntPtr SystemInformation,
            [In] int SystemInformationLength,
            [Out] out int ReturnLength);

        [DllImport("ntdll.dll")]
        internal static extern NT_STATUS NtQueryObject(
            [In] IntPtr Handle,
            [In] OBJECT_INFORMATION_CLASS ObjectInformationClass,
            [In] IntPtr ObjectInformation,
            [In] int ObjectInformationLength,
            [Out] out int ReturnLength);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            [In] int dwDesiredAccess,
            [In, MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            [In] int dwProcessId);

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(
            [In] IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateHandle(
            [In] IntPtr hSourceProcessHandle,
            [In] IntPtr hSourceHandle,
            [In] IntPtr hTargetProcessHandle,
            [Out] out IntPtr lpTargetHandle,
            [In] int dwDesiredAccess,
            [In, MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            [In] int dwOptions);

        public class HandleInfo
        {
            public int ProcessId { get; private set; }
            public ushort Handle { get; private set; }
            public int GrantedAccess { get; private set; }
            public byte RawType { get; private set; }

            public HandleInfo(int processId, ushort handle, int grantedAccess, byte rawType)
            {
                ProcessId = processId;
                Handle = handle;
                GrantedAccess = grantedAccess;
                RawType = rawType;
            }

            private static Dictionary<byte, string> _rawTypeMap = new Dictionary<byte, string>();

            private string _name, _typeStr;
            private HandleType _type;

            public string Name { get { if (_name == null) initTypeAndName(); return _name; } }
            public string TypeString { get { if (_typeStr == null) initType(); return _typeStr; } }
            public HandleType Type { get { if (_typeStr == null) initType(); return _type; } }

            private void initType()
            {
                if (_rawTypeMap.ContainsKey(RawType))
                {
                    _typeStr = _rawTypeMap[RawType];
                    _type = HandleTypeFromString(_typeStr);
                }
                else
                    initTypeAndName();
            }

            bool _typeAndNameAttempted = false;

            private void initTypeAndName()
            {
                if (_typeAndNameAttempted)
                    return;
                _typeAndNameAttempted = true;

                IntPtr sourceProcessHandle = IntPtr.Zero;
                IntPtr handleDuplicate = IntPtr.Zero;
                try
                {
                    sourceProcessHandle = OpenProcess(0x40 /* dup_handle */, true, ProcessId);

                    // To read info about a handle owned by another process we must duplicate it into ours
                    // For simplicity, current process handles will also get duplicated; remember that process handles cannot be compared for equality
                    if (!DuplicateHandle(sourceProcessHandle, (IntPtr)Handle, GetCurrentProcess(), out handleDuplicate, 0, false, 2 /* same_access */))
                        return;

                    // Query the object type
                    if (_rawTypeMap.ContainsKey(RawType))
                        _typeStr = _rawTypeMap[RawType];
                    else
                    {
                        int length;
                        NtQueryObject(handleDuplicate, OBJECT_INFORMATION_CLASS.ObjectTypeInformation, IntPtr.Zero, 0, out length);
                        IntPtr ptr = IntPtr.Zero;
                        try
                        {
                            ptr = Marshal.AllocHGlobal(length);
                            if (NtQueryObject(handleDuplicate, OBJECT_INFORMATION_CLASS.ObjectTypeInformation, ptr, length, out length) != NT_STATUS.STATUS_SUCCESS)
                                return;
                            _typeStr = Marshal.PtrToStringUni((IntPtr)((int)ptr + 0x58 + 2 * IntPtr.Size));
                            _rawTypeMap[RawType] = _typeStr;
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(ptr);
                        }
                    }
                    _type = HandleTypeFromString(_typeStr);

                    // Query the object name
                    if (_typeStr != null && GrantedAccess != 0x0012019f && GrantedAccess != 0x00120189 && GrantedAccess != 0x120089) // don't query some objects that could get stuck
                    {
                        int length;
                        NtQueryObject(handleDuplicate, OBJECT_INFORMATION_CLASS.ObjectNameInformation, IntPtr.Zero, 0, out length);
                        IntPtr ptr = IntPtr.Zero;
                        try
                        {
                            ptr = Marshal.AllocHGlobal(length);
                            if (NtQueryObject(handleDuplicate, OBJECT_INFORMATION_CLASS.ObjectNameInformation, ptr, length, out length) != NT_STATUS.STATUS_SUCCESS)
                                return;
                            _name = Marshal.PtrToStringUni((IntPtr)((int)ptr + 2 * IntPtr.Size));
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(ptr);
                        }
                    }
                }
                finally
                {
                    CloseHandle(sourceProcessHandle);
                    if (handleDuplicate != IntPtr.Zero)
                        CloseHandle(handleDuplicate);
                }
            }

            public static HandleType HandleTypeFromString(string typeStr)
            {
                switch (typeStr)
                {
                    case null:
                        return HandleType.Unknown;
                    case "File":
                        return HandleType.File;
                    case "IoCompletion":
                        return HandleType.IoCompletion;
                    case "TpWorkerFactory":
                        return HandleType.TpWorkerFactory;
                    case "ALPC Port":
                        return HandleType.AlpcPort;
                    case "Event":
                        return HandleType.Event;
                    case "Section":
                        return HandleType.Section;
                    case "Directory":
                        return HandleType.Directory;
                    case "KeyedEvent":
                        return HandleType.KeyedEvent;
                    case "Process":
                        return HandleType.Process;
                    case "Key":
                        return HandleType.Key;
                    case "SymbolicLink":
                        return HandleType.SymbolicLink;
                    case "Thread":
                        return HandleType.Thread;
                    case "Mutant":
                        return HandleType.Mutant;
                    case "WindowStation":
                        return HandleType.WindowStation;
                    case "Timer":
                        return HandleType.Timer;
                    case "Semaphore":
                        return HandleType.Semaphore;
                    case "Desktop":
                        return HandleType.Desktop;
                    case "Token":
                        return HandleType.Token;
                    case "Job":
                        return HandleType.Job;
                    case "Session":
                        return HandleType.Session;
                    case "IoCompletionReserve":
                        return HandleType.IoCompletionReserve;
                    case "WmiGuid":
                        return HandleType.WmiGuid;
                    case "UserApcReserve":
                        return HandleType.UserApcReserve;
                    default:
                        return HandleType.Other;
                }
            }
        }

        public static IEnumerable<HandleInfo> GetHandles()
        {
            // Attempt to retrieve the handle information
            int length = 0x10000;
            IntPtr ptr = IntPtr.Zero;
            try
            {
                while (true)
                {
                    ptr = Marshal.AllocHGlobal(length);
                    int wantedLength;
                    var result = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemHandleInformation, ptr, length, out wantedLength);
                    if (result == NT_STATUS.STATUS_INFO_LENGTH_MISMATCH)
                    {
                        length = Math.Max(length, wantedLength);
                        Marshal.FreeHGlobal(ptr);
                        ptr = IntPtr.Zero;
                    }
                    else if (result == NT_STATUS.STATUS_SUCCESS)
                        break;
                    else
                        throw new Exception("Failed to retrieve system handle information.");
                }

                int handleCount = IntPtr.Size == 4 ? Marshal.ReadInt32(ptr) : (int)Marshal.ReadInt64(ptr);
                int offset = IntPtr.Size;
                int size = Marshal.SizeOf(typeof(SystemHandleEntry));
                for (int i = 0; i < handleCount; i++)
                {
                    var struc = (SystemHandleEntry)Marshal.PtrToStructure((IntPtr)((int)ptr + offset), typeof(SystemHandleEntry));

                    // see https://gist.github.com/i-e-b/2290426#gistcomment-3234676
                    if (!(struc.GrantedAccess == 0x001a019f && struc.Flags == 2))
                        yield return new HandleInfo(struc.OwnerProcessId, struc.Handle, struc.GrantedAccess, struc.ObjectTypeNumber);
                    offset += size;
                }
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    Marshal.FreeHGlobal(ptr);
            }
        }
    }
}