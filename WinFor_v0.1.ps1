function isadmin
{
    # Check if Elevated
    $isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    return $isAdmin
}


function dependencychecks
{
    <#
        .DESCRIPTION
        Checks for System Role, Powershell Version, Proxy active/not active, Elevated or non elevated Session.
        Creates the Log directories or checks if they are already available.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    #Privilege Escalation Phase
         [int]$systemRoleID = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole



         $systemRoles = @{
                              0         =    " Standalone Workstation    " ;
                              1         =    " Member Workstation        " ;
                              2         =    " Standalone Server         " ;
                              3         =    " Member Server             " ;
                              4         =    " Backup  Domain Controller " ;
                              5         =    " Primary Domain Controller "       
         }

        #Proxy Detect #1
        proxydetect
        
        $PSVersion=$PSVersionTable.PSVersion.Major
        $currentPath = (Get-Item -Path ".\" -Verbose).FullName
        Write-Host 'Current Path is: '$currentPath''
        
        Write-Host "[?] Checking for administrative privileges ..`n" -ForegroundColor black -BackgroundColor white  ; sleep 1
        
        $isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if(!$isAdmin){
                
                Write-Warning  "[-] Some of the operations need administrative privileges.`n"
                
                Write-Warning  "[*] Please run the script using an administrative account if you have one.`n"
                
                Read-Host "Type any key to continue .."
        }
        
        write-host "[?] Checking for Default PowerShell version ..`n" -ForegroundColor black -BackgroundColor white  ; sleep 1
        
        if($PSVersion -lt 2){
           
                Write-Warning  "[!] You have PowerShell v1.0.`n"
            
                Write-Warning  "[!] This script only supports Powershell verion 2 or above.`n"
            
                read-host "Type any key to continue .."
            
                exit  
        }
        
        write-host "       [+] ----->  PowerShell v$PSVersion`n" ; sleep 1
        
        write-host "[?] Detecting system role ..`n" -ForegroundColor black -BackgroundColor white ; sleep 1
        
        $systemRoleID = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole
        
        if($systemRoleID -ne 1){
        
                "       [-] This script needs access to the domain. It can only be run on a domain member machine.`n"
               
                Read-Host "Type any key to continue .."
                   
        }
        
        write-host "       [+] ----->",$systemRoles[[int]$systemRoleID],"`n" ; sleep 1
}


dependencychecks
if (isadmin)
{
    Write-Host -ForegroundColor Green "Elevated PowerShell session detected. Continuing."

    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    #Loki Start
    Invoke-WebRequest -Uri 'https://github.com/SecureThisShit/Creds/blob/master/loki.exe?raw=true' -Outfile $currentPath\loki.exe
    Invoke-WebRequest -Uri 'https://github.com/SecureThisShit/Creds/blob/master/loki.zip?raw=true' -Outfile $currentPath\loki.zip
    Unzip "$currentPath\loki.zip" "$currentPath\"
    Write-Host -ForegroundColor Yellow 'Checking, loki download was successfull:'
    if (Test-Path $currentPath\loki.exe)
    {
        Write-Host -ForegroundColor Yellow 'Good... Starting Loki!'
        invoke-expression 'cmd /c start powershell -Command {.\loki.exe}'
        Write-Host -ForegroundColor Yellow 'Results will be saved to '$currentPath\Forensics\Loki_Results.txt'!'
    }
    else {Write-Host -ForegroundColor Red 'Zip File could not be unpacked...'}


    $PSrecon = Read-Host -Prompt 'Do you want to gather local computer Informations with PSRecon? (yes/no)'
    if ($PSrecon -eq "yes" -or $PSrecon -eq "y" -or $PSrecon -eq "Yes" -or $PSrecon -eq "Y")
    {
        Write-Host -ForegroundColor Yellow 'Starting PsRecon:'
        Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/gfoss/PSRecon/master/psrecon.ps1' -Outfile $currentPath\LocalRecon\Psrecon.ps1
        .\Psrecon.ps1
    }

    #ThreadHunting Functions
    Invoke-WebRequest -Uri 'https://github.com/DLACERT/ThreatHunting/archive/master.zip' -Outfile $currentPath\ThreadHunting.zip
    Unzip "$currentPath\ThreadHunting.zip" "$currentPath\Forensics\"
    Write-Host -ForegroundColor Yellow 'Checking, if folder was unzipped successfully:'
    if (Test-Path $currentPath\Forensics\ThreatHunting-master\ThreatHunting.psm1)
    {
        Write-Host -ForegroundColor Yellow 'Good...'
        Get-ChildItem *.ps* -Recurse | Unblock-File
        Import-Module $currentPath\Forensics\ThreadHunting-master\ThreatHunting.psm1
        Write-Host -ForegroundColor Yellow 'ThreadHunting Functions imported...'

        #TODO
    }
    else {Write-Host -ForegroundColor Red 'Zip File could not be unpacked...'}

}
else{Write-Host -ForegroundColor Red 'You need to be admin for WinFor'}
