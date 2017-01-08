<#	
	.NOTES
	===========================================================================
	 Created on:   	Apr 2016
	 Created by:   	Dmitriy Kagarlickij
	 Contact: 	    dmitriy@kagarlickij.com
     Description:   http://kagarlickij.com/download-restore-ms-sql-database-backup/
	===========================================================================
	.DESCRIPTION
		This script should be executing with Administrator-level permissions
#>

#Requires -RunAsAdministrator

# Set variables
$Hostname = hostname
$errorsCounter = 0

$WorkDir = "C:\myDBtmp"
$LogSource = "DB restore script"
$LogFile = "$WorkDir\logs\mainLog.txt"
$WorkDisk = "DeviceID='C:'"
$WorkDiskFreeSpaceDesired = "10"

$EmailFrom = "monitor@kagarlickij.com"
$EmailServer = "smtp.gmail.com"
$EmailServerPort = "587"
$EmailPass = Get-Content C:\myDBtmp\MailboxSecurePass.txt | ConvertTo-SecureString
$EmailCred = New-Object -TypeName System.Management.Automation.PSCredential -argumentlist $EmailFrom, $EmailPass

$RemoteHostAddr = "10.211.55.8"
$RemoteHostUser = "sftp-user"
$RemoteHostPswd = Get-Content C:\myDBtmp\SFTPpwd.txt | ConvertTo-SecureString
$RemoteArcheiveName = "myDBarcheive.7z"

$OldBackupFileName = "myDBOld.bak"
$TargetDatabaseName = "myDB"
$MainTable = "dbo.Main_File"
$TargetServerName = "ws2016tp4"

Set-Alias sz "$env:ProgramFiles\7-Zip\7z.exe"
$7zOutDir = "-o$WorkDir"
$7zPswd = "-pPassword"

$PermGroup = "WS2016TP4\dk"
$PermLevel = "db_datareader"

function addLogEntry ($Message, $EntryType) {
    # Write to console
    Write-Host "[$(Get-Date -UFormat "%b-%d %H:%M:%S %Z")] $Message"
    
    # Write to text log
    Add-Content -Value "[$(Get-Date -UFormat "%b-%d %H:%M:%S %Z")] $Message" -Path $LogFile -Encoding ASCII
    
    # Write to eventlog
    Write-EventLog -LogName Application -Source $LogSource -EntryType $EntryType -EventId 1 -Message $Message
}

function sendEmail ($Result) {
    # Add records to logs
    $Message = "sendEmail function has been started"
    $EntryType = "Information"
    addLogEntry $Message $EntryType

    # Set EmailTo
    if ($Result -eq 'SUCCESS') {
        $EmailTo = "dmitriy@kagarlickij.com"
    } else {
        $EmailTo = "dmitriy@kagarlickij.com", "Dmytro_Kaharlytskyi@epam.com"
    }

    # Set EmailSubject
    $EmailSubject = "$Result : $TargetDatabaseName restore $(Get-Date -UFormat "%b-%d %H:%M:%S %Z")"

    # Send email
    Send-MailMessage -From $EmailFrom -To $EmailTo -Subject $EmailSubject -Body $(Get-Content -Path $LogFile | Out-String) `
    -SmtpServer $EmailServer -Port $EmailServerPort -UseSsl -Credential $EmailCred
}

function endMain {
    # Calculate function execution time
    $functionExecutionTime = ([math]::truncate( ((Get-Date) - $functionStartTime).TotalMinutes ))
    
    # Add records to logs
    $Message = "DB restore script has been finished with status: ERROR because of last function. Previous functions have been executed in $functionExecutionTime min"
    $EntryType = "Error"
    addLogEntry $Message $EntryType

    # End script execution
    $Result = "ERROR"
    sendEmail $Result
    exit
}

function addLogEntrys {
    # Create directory with logs if it's not present
    if ((Test-Path -Path $WorkDir\logs) -ne 'True') {
        New-Item -Type Directory -Path $WorkDir -Name logs
    }

    # Remove old mainLog if it's present
    if ((Test-Path -Path $LogFile) -eq 'True') {
        Remove-Item -Path $LogFile
    }
        
    # Create source in the Application log if it's not present 
    if ([system.diagnostics.eventlog]::SourceExists($LogSource) -ne 'True') {
        New-EventLog -LogName Application -Source $LogSource
        if ([system.diagnostics.eventlog]::SourceExists($LogSource) -ne 'True') {
            $Message = "Source in the Application log has been created with error"
            $EntryType = "Error"
        } else {
            $Message = "Source in the Application log has been created successfully"
            $EntryType = "Information"
        }
    } else {
        $Message = "Source in the Application log has been already present"
        $EntryType = "Information"        
    }

    # Add records to logs
    addLogEntry $Message $EntryType

    # Add records to logs (echo script start)
    $Message = "DB restore script has been started on server $Hostname. Restoring $TargetDatabaseName database."
    $EntryType = "Information"
    addLogEntry $Message $EntryType
}

function clean {
    # Fix function start time
    $functionStartTime = (Get-Date)

    # Add records to logs
    $Message = "clean function has been started"
    $EntryType = "Information"
    addLogEntry $Message $EntryType

    # Delete remote archeive (7zip file)    
    if ((Test-Path -Path $WorkDir\$RemoteArcheiveName) -eq 'True') {
        Remove-Item $WorkDir\$RemoteArcheiveName -Force
    }
    if(-not $?) {
        $errorsCounter++
        $Message = "Remote archeive file has been deleted with error"
        $EntryType = "Error"
        addLogEntry $Message $EntryType
    }
    
    # Delete backup files (.bak)
    Remove-Item $WorkDir\*.bak -Force
    if(-not $?) {
        $errorsCounter++
        $Message = "Backup files have been deleted with error"
        $EntryType = "Error"
        addLogEntry $Message $EntryType
    }  
    
    # Calculate function execution time
    $functionExecutionTime = ([math]::truncate( ((Get-Date) - $functionStartTime).TotalSeconds ))

    # Check function results
    if ( $errorsCounter -gt 0 ) {        
        $Message = "clean function has been finished with status: ERROR in $functionExecutionTime sec"
        $EntryType = "Error"
        addLogEntry $Message $EntryType
        
        endMain
    }
    else {    
        $Message = "clean function has been finished with status: SUCCESS in $functionExecutionTime sec"
        $EntryType = "Information"
        addLogEntry $Message $EntryType   
        
    }
}

function checkDiskSpace {
    # Fix function start time
    $functionStartTime = (Get-Date)

    # Add records to logs
    $Message = "checkDiskSpace function has been started"
    $EntryType = "Information"
    addLogEntry $Message $EntryType

    # Check free disk space
    $WorkDiskFreeSpace = $(Get-WMIObject Win32_LogicalDisk -ComputerName $TargetServerName -Filter $WorkDisk | ForEach-Object {[math]::truncate($_.freespace / 1GB)})
    if ($WorkDiskFreeSpace -le $WorkDiskFreeSpaceDesired) {
        $errorsCounter++
    }

    # Calculate function execution time
    $functionExecutionTime = ([math]::truncate( ((Get-Date) - $functionStartTime).TotalSeconds ))

    # Check function results
    if ( $errorsCounter -gt 0 ) {        
        $Message = "checkDiskSpace function has been finished with status: ERROR in $functionExecutionTime sec"
        $EntryType = "Error"
        addLogEntry $Message $EntryType
        
        endMain
    }
    else {
        $Message = "checkDiskSpace function has been finished with status: SUCCESS in $functionExecutionTime sec"
        $EntryType = "Information"
        addLogEntry $Message $EntryType    
    }
}

function importModules {
    # Fix function start time
    $functionStartTime = (Get-Date)

    # Add records to logs
    $Message = "importModules function has been started"
    $EntryType = "Information"
    addLogEntry $Message $EntryType

    # Import SQLPS Module 
    Import-Module -Name "sqlps" -DisableNameChecking -WarningAction SilentlyContinue
    if(-not $?) {
        $errorsCounter++
        $Message = "Module sqlps has been imported with error"
        $EntryType = "Error"
        addLogEntry $Message $EntryType

    }
    
    # Import Open Source SSH PowerShell Module
    Import-Module -Name "Posh-SSH"
    if(-not $?) {
        $errorsCounter++
        $Message = "Module Posh-SSH has been imported with error"
        $EntryType = "Error"
        addLogEntry $Message $EntryType
    }

    # Check 7-zip
    Test-Path -Path "$env:ProgramFiles\7-Zip\7z.exe"
    if(-not $?) {
        $errorsCounter++
        $Message = "7-Zip has been checked with error"
        $EntryType = "Error"
        addLogEntry $Message $EntryType
    }

    # Calculate function execution time
    $functionExecutionTime = ([math]::truncate( ((Get-Date) - $functionStartTime).TotalSeconds ))

    # Check function results
    if ( $errorsCounter -gt 0 ) {        
        $Message = "importModules function has been finished with status: ERROR in $functionExecutionTime sec"
        $EntryType = "Error"
        addLogEntry $Message $EntryType
        
        endMain
    }
    else {    
        $Message = "importModules function has been finished with status: SUCCESS in $functionExecutionTime sec"
        $EntryType = "Information"
        addLogEntry $Message $EntryType   
        
    }
}

function getNewBackup {
    # Fix function start time
    $functionStartTime = (Get-Date)

    # Add records to logs
    $Message = "getNewBackup function has been started"
    $EntryType = "Information"
    addLogEntry $Message $EntryType

    # Download backup file from SFTP
    $SFTPCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $RemoteHostUser, $RemoteHostPswd
    $SFTPSession = New-SFTPSession -ComputerName $RemoteHostAddr -Credential $SFTPCredentials -AcceptKey
    Get-SFTPFile -SFTPSession $SFTPSession -RemoteFile $RemoteArcheiveName -LocalPath $WorkDir

    # Unzip backup file
    sz x $WorkDir\$RemoteArcheiveName $7zOutDir $7zPswd

    # Determine backup file names
    Set-Variable -Name NewBackupFileName -Value $(Get-ChildItem -Path $WorkDir | Where-Object {$_.Name -like "$TargetDatabaseName*"}).Name -Scope Global
   
    # Check downloaded backup file
    Set-Location SQLSERVER:\SQL\$TargetServerName\DEFAULT\Databases
    Invoke-Sqlcmd "RESTORE VERIFYONLY FROM DISK = '$WorkDir\$NewBackupFileName'"
    
    if(-not $?) {
        $errorsCounter++
        $Message = "New Backup File has been checked with error"
        $EntryType = "Error"
        addLogEntry $Message $EntryType
    }    

    # Calculate function execution time
    $functionExecutionTime = ([math]::truncate( ((Get-Date) - $functionStartTime).TotalSeconds ))

    # Check function results
    if ( $errorsCounter -gt 0 ) {        
        $Message = "getNewBackup function has been finished with status: ERROR in $functionExecutionTime sec"
        $EntryType = "Error"
        addLogEntry $Message $EntryType
        
        endMain
    }
    else {    
        $Message = "getNewBackup function has been finished with status: SUCCESS in $functionExecutionTime sec"
        $EntryType = "Information"
        addLogEntry $Message $EntryType   
        
    }
}

function backupOldDatabase {
    # Fix function start time
    $functionStartTime = (Get-Date)

    # Add records to logs
    $Message = "backupOldDatabase function has been started"
    $EntryType = "Information"
    addLogEntry $Message $EntryType

    # Calculate old records quantity in the table
    Set-Location SQLSERVER:\SQL\$TargetServerName\DEFAULT\Databases\$TargetDatabaseName
    Set-Variable -Name MainFileCountOld -Value $(Invoke-Sqlcmd "SELECT * FROM $MainTable;" | Measure-Object).Count -Scope Global

    # Backup old database
    Backup-SqlDatabase -ServerInstance $TargetServerName -Database $TargetDatabaseName -BackupFile $WorkDir\$OldBackupFileName -CompressionOption On

    # Check old database backup
    Set-Location SQLSERVER:\SQL\$TargetServerName\DEFAULT\Databases\$TargetDatabaseName
    Invoke-Sqlcmd "RESTORE VERIFYONLY FROM DISK = '$WorkDir\$OldBackupFileName'"
    
        if(-not $?) {
        $errorsCounter++
        $Message = "New Backup File has been checked with error"
        $EntryType = "Error"
        addLogEntry $Message $EntryType
    }    

    # Calculate function execution time
    $functionExecutionTime = ([math]::truncate( ((Get-Date) - $functionStartTime).TotalSeconds ))

    # Check function results
    if ( $errorsCounter -gt 0 ) {        
        $Message = "backupOldDatabase function has been finished with status: ERROR in $functionExecutionTime sec"
        $EntryType = "Error"
        addLogEntry $Message $EntryType
        
        endMain
    }
    else {    
        $Message = "backupOldDatabase function has been finished with status: SUCCESS in $functionExecutionTime sec"
        $EntryType = "Information"
        addLogEntry $Message $EntryType
    }
}

function restoreDatabase ($BackupFileName) {
    # Fix function start time
    $functionStartTime = (Get-Date)

    # Determine database to restore
    if ($BackupFileName -eq $NewBackupFileName) {
        Set-Variable -Name db -Value "New" -Scope Global
    } elseif ($BackupFileName -eq $OldBackupFileName) {
        Set-Variable -Name db -Value "Old" -Scope Global
    } else {
        $Message = "Request for restore unknown database. Script has been stopped."
        $EntryType = "Error"
        addLogEntry $Message $EntryType
        endMain
    }

    # Add records to logs
    $Message = "restoreDatabase function has been started. Restoring $db database."
    $EntryType = "Information"
    addLogEntry $Message $EntryType
        
    # Set database offline
    Set-Location SQLSERVER:\SQL\$TargetServerName\DEFAULT\Databases\$TargetDatabaseName
    Invoke-Sqlcmd "ALTER DATABASE $TargetDatabaseName SET OFFLINE WITH ROLLBACK IMMEDIATE"

    # Restore backup to TargetServer/TargetDatabase
    Restore-SqlDatabase -ServerInstance $TargetServerName -Database $TargetDatabaseName -BackupFile $WorkDir\$BackupFileName -ReplaceDatabase 

    # Set database online
    Set-Location SQLSERVER:\SQL\$TargetServerName\DEFAULT\Databases\$TargetDatabaseName
    Invoke-Sqlcmd "ALTER DATABASE $TargetDatabaseName SET ONLINE"

    # Add permissions to DB
    Invoke-Sqlcmd "USE $TargetDatabaseName CREATE USER [$PermGroup5] FOR LOGIN [$PermGroup5] EXEC sp_addrolemember N'$PermLevel', N'$PermGroup'"

    # Check restored database
    Set-Location SQLSERVER:\SQL\$TargetServerName\DEFAULT\Databases\$TargetDatabaseName
    Invoke-Sqlcmd "SELECT * FROM $MainTable;" | Measure-Object

    if(-not $?) {
        $errorsCounter++
    }
    
    # Calculate function execution time
    $functionExecutionTime = ([math]::truncate( ((Get-Date) - $functionStartTime).TotalSeconds ))

    # Check function results
    if ( $errorsCounter -gt 0 ) {        
        $Message = "restoreDatabase function ($db database restore) has been finished with status: ERROR in $functionExecutionTime sec"
        $EntryType = "Error"
        addLogEntry $Message $EntryType
        
        endMain
    }
    else {    
        $Message = "restoreDatabase function ($db database restore) has been finished with status: SUCCESS in $functionExecutionTime sec"
        $EntryType = "Information"
        addLogEntry $Message $EntryType
    }
}

function deployNewDatabase {
    # Fix function start time
    $functionStartTime = (Get-Date)

    # Add records to logs
    $Message = "deployNewDatabase function has been started"
    $EntryType = "Information"
    addLogEntry $Message $EntryType
       
    # Restore new database   
    restoreDatabase $NewBackupFileName
    
    # Calculate new records quantity in the table
    Set-Location SQLSERVER:\SQL\$TargetServerName\DEFAULT\Databases\$TargetDatabaseName
    Set-Variable -Name MainFileCountNew -Value $(Invoke-Sqlcmd "SELECT * FROM $MainTable;" | Measure-Object).Count -Scope Global

    # Compare records quantity in the table
    if ($MainFileCountOld -gt $MainFileCountNew) {
        $Message = "New Backup File has less records than Old. Old database restore has been initiated."
        $EntryType = "Warning"
        addLogEntry $Message $EntryType
        
        # Restore old database 
        restoreDatabase $OldBackupFileName
    } else {
        $Message = "New Backup File has more records than Old"
        $EntryType = "Information"
        addLogEntry $Message $EntryType
    }

    # Calculate function execution time
    $functionExecutionTime = ([math]::truncate( ((Get-Date) - $functionStartTime).TotalSeconds ))

    # Add records to logs  
    $Message = "deployNewDatabase function has been finished in $functionExecutionTime sec"
    $EntryType = "Information"
    addLogEntry $Message $EntryType

}

function main {
    # Fix function start time
    $functionStartTime = (Get-Date)

    addLogEntrys
    clean
    checkDiskSpace
    importModules
    getNewBackup
    backupOldDatabase
    deployNewDatabase
    clean

    # Calculate function execution time
    $functionExecutionTime = ([math]::truncate( ((Get-Date) - $functionStartTime).TotalMinutes ))

    # Add records to logs
    $Message = "DB restore script has been finished with status: SUCCESS. $db version of database $TargetDatabaseName was restored. All functions have been executed in $functionExecutionTime min"
    $EntryType = "Information"
    addLogEntry $Message $EntryType
  
    # End script execution
    $Result = "SUCCESS"
    sendEmail $Result
    
    # Clean for local run
    Set-Location -Path "C:\"
    Remove-Variable -Name * -ErrorAction SilentlyContinue
}

# Execute main function
main


# SIG # Begin signature block
# MIITvgYJKoZIhvcNAQcCoIITrzCCE6sCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUCF2s6OllFgsduIPdP5pIp2L0
# ZEGggg5PMIIEFDCCAvygAwIBAgILBAAAAAABL07hUtcwDQYJKoZIhvcNAQEFBQAw
# VzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNV
# BAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0xMTA0
# MTMxMDAwMDBaFw0yODAxMjgxMjAwMDBaMFIxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSgwJgYDVQQDEx9HbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBDQSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlO9l
# +LVXn6BTDTQG6wkft0cYasvwW+T/J6U00feJGr+esc0SQW5m1IGghYtkWkYvmaCN
# d7HivFzdItdqZ9C76Mp03otPDbBS5ZBb60cO8eefnAuQZT4XljBFcm05oRc2yrmg
# jBtPCBn2gTGtYRakYua0QJ7D/PuV9vu1LpWBmODvxevYAll4d/eq41JrUJEpxfz3
# zZNl0mBhIvIG+zLdFlH6Dv2KMPAXCae78wSuq5DnbN96qfTvxGInX2+ZbTh0qhGL
# 2t/HFEzphbLswn1KJo/nVrqm4M+SU4B09APsaLJgvIQgAIMboe60dAXBKY5i0Eex
# +vBTzBj5Ljv5cH60JQIDAQABo4HlMIHiMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMB
# Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBRG2D7/3OO+/4Pm9IWbsN1q1hSpwTBHBgNV
# HSAEQDA+MDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFs
# c2lnbi5jb20vcmVwb3NpdG9yeS8wMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLm5ldC9yb290LmNybDAfBgNVHSMEGDAWgBRge2YaRQ2XyolQ
# L30EzTSo//z9SzANBgkqhkiG9w0BAQUFAAOCAQEATl5WkB5GtNlJMfO7FzkoG8IW
# 3f1B3AkFBJtvsqKa1pkuQJkAVbXqP6UgdtOGNNQXzFU6x4Lu76i6vNgGnxVQ380W
# e1I6AtcZGv2v8Hhc4EvFGN86JB7arLipWAQCBzDbsBJe/jG+8ARI9PBw+DpeVoPP
# PfsNvPTF7ZedudTbpSeE4zibi6c1hkQgpDttpGoLoYP9KOva7yj2zIhd+wo7AKvg
# IeviLzVsD440RZfroveZMzV+y5qKu0VN5z+fwtmK+mWybsd+Zf/okuEsMaL3sCc2
# SI8mbzvuTXYfecPlf5Y1vC0OzAGwjn//UYCAp5LUs0RGZIyHTxZjBzFLY7Df8zCC
# BJ8wggOHoAMCAQICEhEhBqCB0z/YeuWCTMFrUglOAzANBgkqhkiG9w0BAQUFADBS
# MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UE
# AxMfR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBHMjAeFw0xNTAyMDMwMDAw
# MDBaFw0yNjAzMDMwMDAwMDBaMGAxCzAJBgNVBAYTAlNHMR8wHQYDVQQKExZHTU8g
# R2xvYmFsU2lnbiBQdGUgTHRkMTAwLgYDVQQDEydHbG9iYWxTaWduIFRTQSBmb3Ig
# TVMgQXV0aGVudGljb2RlIC0gRzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
# AoIBAQCwF66i07YEMFYeWA+x7VWk1lTL2PZzOuxdXqsl/Tal+oTDYUDFRrVZUjtC
# oi5fE2IQqVvmc9aSJbF9I+MGs4c6DkPw1wCJU6IRMVIobl1AcjzyCXenSZKX1GyQ
# oHan/bjcs53yB2AsT1iYAGvTFVTg+t3/gCxfGKaY/9Sr7KFFWbIub2Jd4NkZrItX
# nKgmK9kXpRDSRwgacCwzi39ogCq1oV1r3Y0CAikDqnw3u7spTj1Tk7Om+o/SWJMV
# TLktq4CjoyX7r/cIZLB6RA9cENdfYTeqTmvT0lMlnYJz+iz5crCpGTkqUPqp0Dw6
# yuhb7/VfUfT5CtmXNd5qheYjBEKvAgMBAAGjggFfMIIBWzAOBgNVHQ8BAf8EBAMC
# B4AwTAYDVR0gBEUwQzBBBgkrBgEEAaAyAR4wNDAyBggrBgEFBQcCARYmaHR0cHM6
# Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wCQYDVR0TBAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDBCBgNVHR8EOzA5MDegNaAzhjFodHRwOi8vY3Js
# Lmdsb2JhbHNpZ24uY29tL2dzL2dzdGltZXN0YW1waW5nZzIuY3JsMFQGCCsGAQUF
# BwEBBEgwRjBEBggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNv
# bS9jYWNlcnQvZ3N0aW1lc3RhbXBpbmdnMi5jcnQwHQYDVR0OBBYEFNSihEo4Whh/
# uk8wUL2d1XqH1gn3MB8GA1UdIwQYMBaAFEbYPv/c477/g+b0hZuw3WrWFKnBMA0G
# CSqGSIb3DQEBBQUAA4IBAQCAMtwHjRygnJ08Kug9IYtZoU1+zETOA75+qrzE5ntz
# u0vxiNqQTnU3KDhjudcrD1SpVs53OZcwc82b2dkFRRyNpLgDXU/ZHC6Y4OmI5uzX
# BX5WKnv3FlujrY+XJRKEG7JcY0oK0u8QVEeChDVpKJwM5B8UFiT6ddx0cm5OyuNq
# Q6/PfTZI0b3pBpEsL6bIcf3PvdidIZj8r9veIoyvp/N3753co3BLRBrweIUe8qWM
# ObXciBw37a0U9QcLJr2+bQJesbiwWGyFOg32/1onDMXeU+dUPFZMyU5MMPbyXPsa
# jMKCvq1ZkfYbTVV7z1sB3P16028jXDJHmwHzwVEURoqbMIIFkDCCBHigAwIBAgIQ
# QXaXpC9uno+9UjU6oprWsjANBgkqhkiG9w0BAQsFADB9MQswCQYDVQQGEwJHQjEb
# MBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRow
# GAYDVQQKExFDT01PRE8gQ0EgTGltaXRlZDEjMCEGA1UEAxMaQ09NT0RPIFJTQSBD
# b2RlIFNpZ25pbmcgQ0EwHhcNMTUwNjIyMDAwMDAwWhcNMTYwNjE2MjM1OTU5WjCB
# 1jELMAkGA1UEBhMCQ1kxDTALBgNVBBEMBDIxMTIxCjAIBgNVBAgMAS0xEDAOBgNV
# BAcMB05pY29zaWExEjAQBgNVBAkMCTV0aCBGbG9vcjEsMCoGA1UECQwjVHJlcHBp
# ZGVzIFRvd2VyLCA5IEthZmthc291IFN0cmVldCwxJDAiBgNVBAoMG0xFQURDQVBJ
# VEFMIE1BUktFVFMgTElNSVRFRDEMMAoGA1UECwwDRGV2MSQwIgYDVQQDDBtMRUFE
# Q0FQSVRBTCBNQVJLRVRTIExJTUlURUQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
# ggEKAoIBAQC2/fKSGaIyR5wa0cmCcXJofszXk+auXtEnbnDSgmSrlEluqAehzkuS
# j42uEMBrrKfR9O1AW1vG9nMEsKEpOifnhkEfFPko69k8IGjFV3biklrvuBSb2b+2
# CijlJTRMKIKsazATp5fFjCIpZ6Xvpt6m+kOu+394b+ig8qOAv9T1q7vhKjEO7zmj
# qkXN9U1emat8vYyoGyPqiux69n6lLzPPd8XD/yR/bH1/OuJIKNx58VcsIYVpy0ki
# F3YsoBTo4/xjpgx792hu9QneXroQq8pPbZEzgeT5SLcxMwi0qzQSsYkGguI9LeuZ
# d6qZI/BoLUydA2rMk39jR3V+0tNGjztDAgMBAAGjggGwMIIBrDAfBgNVHSMEGDAW
# gBQpkWD/ik366/mmarjP+eZLvUnOEjAdBgNVHQ4EFgQUKEW1o+pUvBTUoQIm+qpH
# +iZG2zQwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYI
# KwYBBQUHAwMwEQYJYIZIAYb4QgEBBAQDAgQQMEYGA1UdIAQ/MD0wOwYMKwYBBAGy
# MQECAQMCMCswKQYIKwYBBQUHAgEWHWh0dHBzOi8vc2VjdXJlLmNvbW9kby5uZXQv
# Q1BTMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0NP
# TU9ET1JTQUNvZGVTaWduaW5nQ0EuY3JsMHQGCCsGAQUFBwEBBGgwZjA+BggrBgEF
# BQcwAoYyaHR0cDovL2NydC5jb21vZG9jYS5jb20vQ09NT0RPUlNBQ29kZVNpZ25p
# bmdDQS5jcnQwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTAh
# BgNVHREEGjAYgRZhZG1pbkBvcHRpb25zY2xpY2suY29tMA0GCSqGSIb3DQEBCwUA
# A4IBAQCI6dmaN3fsZlWXq+if67EZvHUYQCq3AomBwYrv+rQhMore24NJwWQLwUyy
# ZMFuX9ezd1XU/iASFG5q1/xGLykklTBSe2r4J2sG2nj2q4YUGa0Tel1wMmTJWz1A
# ubcr8OJ8HRpb2MY0jERm/zf2txFN3gf7H5CAU0YCaklvieDs8DEAJCZy9Ryi4JIR
# td+jKnn9Z59FgfFdE0ESlqKoTrqnf9i2RplrLIBLQwT92KtTYbZGiYmNXk6a4fR5
# HuwHsqXYHAoucP7fPKrYJRVHjwgNKb+i99QKcbnh6iEMnlhqcTnmWGaNlJ0CJD+t
# altnQtzrpskFXmeSYi9YguFxVRakMYIE2TCCBNUCAQEwgZEwfTELMAkGA1UEBhMC
# R0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9y
# ZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxIzAhBgNVBAMTGkNPTU9ETyBS
# U0EgQ29kZSBTaWduaW5nIENBAhBBdpekL26ej71SNTqimtayMAkGBSsOAwIaBQCg
# eDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEE
# AYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJ
# BDEWBBQH+HwpnpKjOyxYFDlCmxIuO8IsnjANBgkqhkiG9w0BAQEFAASCAQCMOEST
# j5fe380vHtYMN/XJH70M397P/Uujig7+kH82Gz8LkNGdL+OyyGz9z5qhyuQxwF8I
# E/4/1G9i6VhhWCZD+jWS5OEp6Oz0E8RSk/yBUYViDVfTLLhpxyy/zK5kQ8UW7J45
# iMf0t3ZEkVVX0wjNkCtvrplynht+z/1Cd2GDch9qHiAeOxXPopPNnfLT2CrXaO7I
# IQwQuFQHjO51rQeFg6qevTSuhxyOp8MZh7BRKfYFWZC+JfSE3oedd2vrd0O6I4fw
# nOn7Sb1Cwy0bA12sIioViFC5Wpq1hoLquw9kd7TVNGsjqmACb02nBNpvj6fQlJoK
# Vdqm5PG2nHmi3dqPoYICojCCAp4GCSqGSIb3DQEJBjGCAo8wggKLAgEBMGgwUjEL
# MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKDAmBgNVBAMT
# H0dsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gRzICEhEhBqCB0z/YeuWCTMFr
# UglOAzAJBgUrDgMCGgUAoIH9MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTE2MDMzMDA5NDcwMFowIwYJKoZIhvcNAQkEMRYEFC9QU2Ol
# M9s42mqJeRZndWAIicFWMIGdBgsqhkiG9w0BCRACDDGBjTCBijCBhzCBhAQUs2MI
# tNTN7U/PvWa5Vfrjv7EsKeYwbDBWpFQwUjELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExKDAmBgNVBAMTH0dsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gRzICEhEhBqCB0z/YeuWCTMFrUglOAzANBgkqhkiG9w0BAQEFAASC
# AQAfFxol1RWq9TkttkrNrFviJ+0ldwih26WiThZ41Nw3GT7XUFVR+TdfsXCXXmdK
# 72XoHnA3s+3gp7ef4nonCj+tkFtZzT5cGJAzNOZaGZigBFV6kHCMQUUz15mEFMAJ
# nnNkY7MKuxrQ49UqiIM8ISLIJKuJSsyBnhF9T91fBV61tN8NDPlJW2oo2rzqLtr6
# 4a4yC55rJdDWMPnoWqYasuF5/nTSzyiUaK4YjMA/63VcqohgG1+4Rr8Q2kUC7ZY8
# bI/xzvL+m64P3QDTIC+TQU1RBh4L3nzjdV4T2cKo+v6i06+q/dQrT/+HpUtGoHze
# GlstW3sZSuANdfvXljJG5iNi
# SIG # End signature block