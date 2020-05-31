using System.Diagnostics;
using System.Linq;
using System.Management.Automation;

namespace FindOpenFiles
{
    [Cmdlet(VerbsCommon.Find, "OpenFile", DefaultParameterSetName = AllParameterSet)]
    public class FindOpenFileCommand : PSCmdlet
    {
        private const string AllParameterSet = "All";
        private const string FileParameterSet = "File";
        private const string ProcessParameterSet = "Process";

        [Parameter(ParameterSetName = AllParameterSet)]
        public SwitchParameter System { get; set; }
        [Parameter(ParameterSetName = FileParameterSet, Mandatory = true, ValueFromPipeline = true)]
        public string FilePath { get; set; }
        [Parameter(ParameterSetName = ProcessParameterSet, Mandatory = true, ValueFromPipeline = true)]
        public Process Process { get; set; }

        protected override void ProcessRecord()
        {
            if (ParameterSetName == AllParameterSet)
            {
                if (System)
                {
                    WriteObject(WalkmanLib.GetFileLocks.GetAllHandles.GetSystemHandles(), true);
                }
                else
                {
                    WriteObject(WalkmanLib.GetFileLocks.GetAllHandles.GetFileHandles(), true);
                }
            }
            else if (ParameterSetName == FileParameterSet)
            {
                FilePath = GetUnresolvedProviderPathFromPSPath(FilePath);

                WriteObject(WalkmanLib.RestartManager.GetLockingProcesses(FilePath), true);   
            }
            else if (ParameterSetName == ProcessParameterSet)
            {
                WriteObject(WalkmanLib.GetFileLocks.GetAllHandles.GetFileHandles().Where(m => m.ProcessId == Process.Id), true);
            }            
        }
    }
}