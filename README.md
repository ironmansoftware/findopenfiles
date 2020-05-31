# Find-OpenFile

A PowerShell module for finding open files. 

----

## Installation 

```
Install-Module FindOpenFile
```

## Usage

Find all files in use. 

```
Find-OpenFile
```

Find open files based on process

```
Get-Process -Name pwsh | Find-OpenFile 
```

Find process locking a file 

```
Find-OpenFile -FilePath .\test.txt
```

## Source

- C# Code Forked from [this repository](https://github.com/Walkman100/FileLocks)
