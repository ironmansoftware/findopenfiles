# Find-OpenFile by [Ironman Software](https://ironmansoftware.com)

A PowerShell module for finding open files. 

----

## Installation 

```
Install-Module FindOpenFile
```

## Usage

Find all files in use. 

```
PS C:\Users\adamr> Find-OpenFile

ProcessId     : 7936
Handle        : 64
GrantedAccess : 1048608
RawType       : 37
Flags         : 0
Name          : \Device\HarddiskVolume3\Windows\System32\DriverStore\FileRepository\FN8DAD~1.INF\driver
TypeString    : File
Type          : File

ProcessId     : 7936
Handle        : 112
GrantedAccess : 1048608
RawType       : 37
Flags         : 0
Name          : \Device\HarddiskVolume3\Windows\WinSxS\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.190
                41.1_none_b555e41d4684ddec
TypeString    : File
Type          : File

```

Find open files based on process

```
PS C:\Users\adamr> Get-Process pwsh | Find-OpenFile

ProcessId     : 22160
Handle        : 64
GrantedAccess : 1048608
RawType       : 37
Flags         : 0
Name          : \Device\HarddiskVolume3\Windows\SysWOW64
TypeString    : File
Type          : File

ProcessId     : 22160
Handle        : 964
GrantedAccess : 1048577
RawType       : 37
Flags         : 0
Name          : \Device\HarddiskVolume3\Windows\System32\en-US\winnlsres.dll.mui
TypeString    : File
Type          : File
```

Find process locking a file 

```
PS C:\Users\adamr> Find-OpenFile -FilePath C:\Windows\System32\en-US\KernelBase.dll.mui

 NPM(K)    PM(M)      WS(M)     CPU(s)      Id  SI ProcessName
 ------    -----      -----     ------      --  -- -----------
    115   226.44     176.13       0.00    1940   1 dwm
     11     2.63      10.35       0.00    7792   1 DAX3API
     26    11.29      37.09      35.92    5568   1 sihost
    154   168.61     203.50     652.52    8340   1 explorer
     27    12.43       8.03      66.62    9952   1 SettingSyncHost
     36    40.49      90.16      19.86    9480   1 StartMenuExperienceHost
     18     6.96      27.73      10.08    9712   1 RuntimeBroker
    140   157.37      97.46      93.78   10356   1 SearchApp
     36    44.05      50.38      33.58   10520   1 RuntimeBroker
    103   212.27      52.13      79.25   11236   1 SkypeApp
     29    10.79       6.42      35.92    8748   1 PowerToys
     27    14.69      48.04       3.91   11624   1 LockApp
```

Find processes accessing a folder or files within it

```
PS C:\Users\adamr> Find-OpenFile -FilePath C:\Test

 NPM(K)    PM(M)      WS(M)     CPU(s)      Id  SI ProcessName
 ------    -----      -----     ------      --  -- -----------
     56    50.62      74.23      10.42   15136   1 notepad
```

## Source

- C# Code Forked from [this repository](https://github.com/Walkman100/FileLocks)
