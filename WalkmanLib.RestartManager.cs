// RestartManager method
//https://stackoverflow.com/a/3504251/2999220
//https://stackoverflow.com/a/20623311/2999220
//https://stackoverflow.com/a/20623302/2999220
//https://gist.github.com/mlaily/9423f1855bb176d52a327f5874915a97
//https://docs.microsoft.com/en-us/archive/msdn-magazine/2007/april/net-matters-restart-manager-and-generic-method-compilation
//https://devblogs.microsoft.com/oldnewthing/?p=8283


using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.ComponentModel;

namespace WalkmanLib
{
    public static class RestartManager
    {
        const int CCH_RM_MAX_APP_NAME = 255;
        const int CCH_RM_MAX_SVC_NAME = 63;
        const int ERROR_MORE_DATA = 234;

        //https://docs.microsoft.com/en-us/windows/win32/api/restartmanager/ns-restartmanager-rm_process_info
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct ProcessInfo
        {
            public UniqueProcess Process;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
            public string AppName;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
            public string ServiceShortName;

            public AppType ApplicationType;
            public uint AppStatus;
            public uint TSSessionId;
            [MarshalAs(UnmanagedType.Bool)]
            public bool Restartable;
        }

        //https://docs.microsoft.com/en-us/windows/win32/api/restartmanager/ns-restartmanager-rm_unique_process
        [StructLayout(LayoutKind.Sequential)]
        public struct UniqueProcess
        {
            public uint ProcessID;
            System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
        }

        //https://docs.microsoft.com/en-us/windows/win32/api/restartmanager/ne-restartmanager-rm_app_type
        // values: https://github.com/microsoft/msbuild/blob/2791d9d93e88325011eb6907579d6fdac0b1b62e/src/Tasks/LockCheck.cs#L101
        public enum AppType
        {
            RmUnknownApp = 0,
            RmMainWindow = 1,
            RmOtherWindow = 2,
            RmService = 3,
            RmExplorer = 4,
            RmConsole = 5,
            RmCritical = 1000
        }

        //https://docs.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmregisterresources
        [DllImport("rstrtmgr.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern int RmRegisterResources(uint pSessionHandle,
                                              uint nFiles,
                                              string[] rgsFilenames,
                                              uint nApplications,
                                              [In] UniqueProcess[] rgApplications,
                                              uint nServices,
                                              string[] rgsServiceNames);

        //https://docs.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmstartsession
        [DllImport("rstrtmgr.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern int RmStartSession(out uint pSessionHandle,
                                         int dwSessionFlags,
                                         string strSessionKey);

        //https://docs.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmendsession
        [DllImport("rstrtmgr.dll", SetLastError = true)]
        static extern int RmEndSession(uint pSessionHandle);

        //https://docs.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmgetlist
        [DllImport("rstrtmgr.dll", SetLastError = true)]
        static extern int RmGetList(uint dwSessionHandle,
                                    out uint pnProcInfoNeeded,
                                    ref uint pnProcInfo,
                                    [In, Out] ProcessInfo[] rgAffectedApps,
                                    ref uint lpdwRebootReasons);

        public static ProcessInfo[] GetLockingProcessInfos(string path)
        {
            uint handle;
            if (RmStartSession(out handle, 0, Guid.NewGuid().ToString()) != 0)
                throw new Exception("Could not begin session. Unable to determine file lockers.", new Win32Exception());

            try
            {
                uint ArrayLengthNeeded = 0,
                     ArrayLength = 0,
                     lpdwRebootReasons = 0; //RmRebootReasonNone;

                string[] resources = { path }; // Just checking on one resource.

                if (RmRegisterResources(handle, (uint)resources.Length, resources, 0, null, 0, null) != 0)
                    throw new Exception("Could not register resource.", new Win32Exception());

                switch (RmGetList(handle, out ArrayLengthNeeded, ref ArrayLength, null, ref lpdwRebootReasons))
                {
                    case ERROR_MORE_DATA:
                        ProcessInfo[] processInfos = new ProcessInfo[ArrayLengthNeeded];
                        ArrayLength = ArrayLengthNeeded;

                        if (RmGetList(handle, out ArrayLengthNeeded, ref ArrayLength, processInfos, ref lpdwRebootReasons) != 0)
                            throw new Exception("Could not list processes locking resource.", new Win32Exception());

                        return processInfos;
                    case 0:
                        return new ProcessInfo[0];
                    default:
                        throw new Exception("Could not list processes locking resource. Failed to get size of result.", new Win32Exception());
                }
            }
            finally
            {
                RmEndSession(handle);
            }
        }

        public static List<Process> GetLockingProcesses(string path)
        {
            List<Process> processes = new List<Process>();
            foreach (ProcessInfo pI in GetLockingProcessInfos(path))
            {
                try
                {
                    Process process = Process.GetProcessById((int)pI.Process.ProcessID);
                    processes.Add(process);
                }
                catch (ArgumentException) { }
            }
            return processes;
        }
    }
}
