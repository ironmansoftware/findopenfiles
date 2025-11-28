param(
    [Parameter()]
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug'
)

BeforeAll {
    # Import the module from the specified build configuration directory
    $modulePath = Join-Path $PSScriptRoot "..\bin\$Configuration\netstandard2.0\FindOpenFile.psd1"
    
    if (-not (Test-Path $modulePath)) {
        throw "Module not found at $modulePath. Please build the project in $Configuration configuration first."
    }
    
    Import-Module $modulePath -Force
}

Describe 'Find-OpenFile Module' {
    Context 'Module Import' {
        It 'Should import the module successfully' {
            $module = Get-Module -Name FindOpenFile
            $module | Should -Not -BeNull
        }
        
        It 'Should export the Find-OpenFile cmdlet' {
            $command = Get-Command -Name Find-OpenFile -ErrorAction SilentlyContinue
            $command | Should -Not -BeNull
        }
        
        It 'Should have correct module version' {
            $module = Get-Module -Name FindOpenFile
            $module.Version.ToString() | Should -Match '^\d+\.\d+\.\d+$'
        }
    }
    
    Context 'Find-OpenFile Cmdlet Structure' {
        It 'Should have correct parameter sets' {
            $command = Get-Command -Name Find-OpenFile
            $parameterSets = $command.ParameterSets.Name
            $parameterSets | Should -Contain 'All'
            $parameterSets | Should -Contain 'File'
            $parameterSets | Should -Contain 'Process'
        }
        
        It 'Should have FilePath parameter' {
            $command = Get-Command -Name Find-OpenFile
            $command.Parameters.ContainsKey('FilePath') | Should -Be $true
        }
        
        It 'Should have Process parameter' {
            $command = Get-Command -Name Find-OpenFile
            $command.Parameters.ContainsKey('Process') | Should -Be $true
        }
        
        It 'Should have System parameter' {
            $command = Get-Command -Name Find-OpenFile
            $command.Parameters.ContainsKey('System') | Should -Be $true
        }
    }
    
    Context 'Find-OpenFile - All Parameter Set' {
        It 'Should return file handles when called without parameters' {
            $result = Find-OpenFile
            $result | Should -Not -BeNull
            $result.Count | Should -BeGreaterThan 0
        }
        
        It 'Should return objects with expected properties' {
            $result = Find-OpenFile | Select-Object -First 1
            $result.PSObject.Properties.Name | Should -Contain 'ProcessId'
            $result.PSObject.Properties.Name | Should -Contain 'Handle'
            $result.PSObject.Properties.Name | Should -Contain 'Name'
            $result.PSObject.Properties.Name | Should -Contain 'Type'
        }
        
        It 'Should return system handles when -System switch is used' {
            $result = Find-OpenFile -System
            $result | Should -Not -BeNull
            $result.Count | Should -BeGreaterThan 0
        }
        
        It 'Should return more handles with -System than without' {
            $normalHandles = @(Find-OpenFile)
            $systemHandles = @(Find-OpenFile -System)
            $systemHandles.Count | Should -BeGreaterOrEqual $normalHandles.Count
        }
    }
    
    Context 'Find-OpenFile - Process Parameter Set' {
        It 'Should accept Process object from pipeline' {
            $currentProcess = Get-Process -Id $PID
            $result = $currentProcess | Find-OpenFile
            $result | Should -Not -BeNull
        }
        
        It 'Should return handles for the specified process' {
            $currentProcess = Get-Process -Id $PID
            $result = Find-OpenFile -Process $currentProcess
            $result | Should -Not -BeNull
            
            # All results should be from the specified process
            $result | ForEach-Object {
                $_.ProcessId | Should -Be $currentProcess.Id
            }
        }
        
        It 'Should work with Get-Process pipeline' {
            $result = Get-Process -Id $PID | Find-OpenFile
            $result | Should -Not -BeNull
        }
    }
    
    Context 'Find-OpenFile - FilePath Parameter Set' {
        BeforeAll {
            # Create a temporary file that we can lock
            $script:testFile = Join-Path $TestDrive 'testfile.txt'
            'Test content' | Out-File -FilePath $script:testFile -Force
        }
        
        It 'Should accept FilePath parameter' {
            # Lock the file by opening it
            $fileStream = [System.IO.File]::Open($script:testFile, 'Open', 'Read', 'None')
            
            try {
                $result = Find-OpenFile -FilePath $script:testFile
                $result | Should -Not -BeNull
                $result.Count | Should -BeGreaterThan 0
            }
            finally {
                $fileStream.Close()
                $fileStream.Dispose()
            }
        }
        
        It 'Should accept FilePath from pipeline' {
            # Lock the file by opening it
            $fileStream = [System.IO.File]::Open($script:testFile, 'Open', 'Read', 'None')
            
            try {
                $result = $script:testFile | Find-OpenFile
                $result | Should -Not -BeNull
            }
            finally {
                $fileStream.Close()
                $fileStream.Dispose()
            }
        }
        
        It 'Should return Process objects for locked files' {
            # Lock the file by opening it
            $fileStream = [System.IO.File]::Open($script:testFile, 'Open', 'Read', 'None')
            
            try {
                $result = Find-OpenFile -FilePath $script:testFile
                $result | Should -Not -BeNull
                
                # Result should contain process information
                $result | ForEach-Object {
                    $_ | Should -BeOfType [System.Diagnostics.Process]
                }
                
                # One of the processes should be the current process
                $result.Id | Should -Contain $PID
            }
            finally {
                $fileStream.Close()
                $fileStream.Dispose()
            }
        }
        
        It 'Should handle non-existent file paths gracefully' {
            $nonExistentFile = Join-Path $TestDrive 'nonexistent.txt'
            { Find-OpenFile -FilePath $nonExistentFile } | Should -Not -Throw
        }
    }
    
    Context 'Platform Support' {
        It 'Should only work on Windows' {
            if ($IsLinux -or $IsMacOS) {
                { Find-OpenFile } | Should -Throw "*only supported on Windows*"
            }
            else {
                { Find-OpenFile } | Should -Not -Throw
            }
        }
    }
    
    Context 'Output Validation' {
        It 'Should return enumerable results' {
            $result = Find-OpenFile
            $result | Should -Not -BeNull
            $result.GetType().IsArray | Should -Be $true
        }
        
        It 'Should have valid ProcessId values' {
            $result = Find-OpenFile | Select-Object -First 5
            $result | ForEach-Object {
                $_.ProcessId | Should -BeOfType [System.Int32]
                $_.ProcessId | Should -BeGreaterThan 0
            }
        }
        
        It 'Should have valid Handle values' {
            $result = Find-OpenFile | Select-Object -First 5
            $result | ForEach-Object {
                $_.Handle | Should -Not -BeNullOrEmpty
            }
        }
    }
    
    Context 'Real-world Scenarios' {
        It 'Should find PowerShell process files' {
            $pwshProcesses = Get-Process pwsh -ErrorAction SilentlyContinue
            if ($pwshProcesses) {
                $result = $pwshProcesses | Select-Object -First 1 | Find-OpenFile
                $result | Should -Not -BeNull
                $result.Count | Should -BeGreaterThan 0
            }
            else {
                Set-ItResult -Skipped -Because "No PowerShell processes found"
            }
        }
        
        It 'Should handle system files without throwing errors or return valid results' {
            # Create a test file in a location we control
            $testSystemFile = Join-Path $TestDrive 'systemtest.log'
            'Test log content' | Out-File -FilePath $testSystemFile -Force
            
            # Lock the file and verify we can find the lock
            $fileStream = [System.IO.File]::Open($testSystemFile, 'Open', 'ReadWrite', 'None')
            
            try {
                $result = Find-OpenFile -FilePath $testSystemFile
                # Should either succeed with results or complete without error
                $result | Should -Not -BeNull
                $result.Count | Should -BeGreaterThan 0
                $result.Id | Should -Contain $PID
            }
            finally {
                $fileStream.Close()
                $fileStream.Dispose()
            }
        }
    }
}

AfterAll {
    # Clean up - remove the module
    Remove-Module FindOpenFile -Force -ErrorAction SilentlyContinue
}
