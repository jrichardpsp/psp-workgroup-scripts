#Transcript Logging
$tmpName = "Migration_Kickoff_Log"
$tmpPath = "C:\Temp\" + $tmpName + ".log"
Start-Transcript -Append -Path $tmpPath

# Constants

# Base Path - Where the CSV, PSP Installer, etc will be located
$basePath = "C:\Temp"

# Name of the CSV file being used as a database.
$csvName = "mig_db.csv"
# Domain name of the "fake" domain where the object is stored
$DomainName = "fake.lan"
# Runbook ID from the PSP Database (Links to the specific Runbook for this job)
$RunbookGUIDs=@("BC481FD8-894C-4E2F-8B4B-08DD8B8E2DE8")
# Name of Migration Agent Service
$serviceName = "PowerSyncPro Migration Agent"

# PSP Migration Agent Name
# This will be merged with $basePath above.
$pspmig_loc = "PSPMigrationAgentInstaller.msi"

# PSP Server Location
# URL to the PSP Agent Endpoint
$psp_server = "https://psp.company.com/Agent"
# PSP PSK
$psp_psk = "<PSK from PSP Server>"

# Begin Script

# Set the CSV path variable assuming the file is in the same directory as the script
$CsvPath = Join-Path -Path $basePath -ChildPath $csvName

# Check if the CSV file exists
if (-not (Test-Path $CsvPath)) {
    Write-Error "The specified CSV file does not exist: $CsvPath"
    exit 1
}

# Import the CSV file
try {
    $csvData = Import-Csv -Path $CsvPath -ErrorAction Stop
    # Verify required headers exist
    $requiredHeaders = @("computer_name", "local_username", "target_entraid")
    $csvHeaders = $csvData[0].PSObject.Properties.Name
    $missingHeaders = $requiredHeaders | Where-Object { $_ -notin $csvHeaders }
    if ($missingHeaders) {
        Write-Error "CSV is missing required headers: $($missingHeaders -join ', '). Expected: $($requiredHeaders -join ', ')"
        exit 1
    }
} catch {
    Write-Error "Failed to import CSV: $_"
    exit 1
}

# Get the current hostname of the machine
$currentHostname = $env:COMPUTERNAME
Write-Host "Current hostname: $currentHostname"

# Look up the current hostname in the CSV with case-insensitive comparison
$matchingRow = $csvData | Where-Object { $_.computer_name -ieq $currentHostname }

# Check if the hostname was found
if (-not $matchingRow) {
    Write-Error "The current hostname '$currentHostname' was not found in the CSV file '$CsvPath'. Aborting."
    exit 1
}

# Set variables from the matching row
$LocalUserName = $matchingRow.local_username
$EntraUserObjectID = $matchingRow.target_entraid

# Output the variables for confirmation
Write-Host "Local Username:" $LocalUserName
Write-Host "Target Entra ID:" $EntraUserObjectID

# -----------------------
# Begin Migration Process
# -----------------------

#Grab PowerSyncPro Migration Agent if it doesn't exist
$service = Get-Service | Where-Object { $_.Name -eq $serviceName }
if ($service) {
    Write-Host "Service '$serviceName' exists and its status is: $($service.Status)"
} else {
    Write-Host "Service '$serviceName' does not exist."
    Write-Host "PowerSync Pro was not found on this system... Installing..."

    $pspPath = Join-Path -Path $basePath -ChildPath $pspmig_loc

    # Install PSP Migration Agent
    # Install Arguments
    $PSPArguments = @(
        "/i", $pspPath,
        "PSK=$psp_psk",
        "URL=$psp_server",
        "/qn",
        "/l*v", "C:\Temp\PSPAgent_Install.log"
    )

    Write-Host "Installing PSP Migration Agent..."
    $pspInstallStatus = (Start-Process -FilePath msiexec.exe -ArgumentList $PSPArguments -Wait -Passthru).ExitCode
    Write-Host "PSP Migration Agent Exited with Status" $pspInstallStatus

    #Sleep and check again...
    Write-Host "Sleeping 15 seconds for PSP Migration Agent to Startup..."
    Start-Sleep -Seconds 15
    $service2 = Get-Service | Where-Object { $_.Name -eq $serviceName }
    if ($service2) {
    Write-Host "Service '$serviceName' exists and its status is: $($service2.Status)"
    }
    else {
        Write-Host "'$serviceName' still doesn't exist after installation... Please verify installation and try script again..."
        Exit
    }
}

Write-Host "PSP is installed and running, lets get started..."

# Obtain the local hostname of this system
$ComputerName = $currentHostname
Write-Host "Running on" $ComputerName "..."

# Obtain from the local system...
# SID of the Local Workgroup User
$SearchSID = Get-WmiObject win32_useraccount | Where Name -match $LocalUserName
$LocalSiD = $SearchSID.SID
Write-Host "Current SID of" $LocalUserName "is" $LocalSiD

# Object ID of the target user in Azure AD - converted to a SID below
$ObjectID = $EntraUserObjectID

function Convert-AzureAdObjectIdToSid {
    param (
        [Parameter(Mandatory = $true)]
        [String]$ObjectId
    )

    # Parse the Object ID into a GUID and convert it to a byte array
    $guidBytes = [Guid]::Parse($ObjectId).ToByteArray()

    # Initialize an array to hold the UInt32 values
    $uintArray = New-Object 'UInt32[]' 4

    # Copy the byte array into the UInt32 array
    [Buffer]::BlockCopy($guidBytes, 0, $uintArray, 0, 16)

    # Construct the SID string
    $sid = "S-1-12-1-$($uintArray[0])-$($uintArray[1])-$($uintArray[2])-$($uintArray[3])"

    return $sid
}

$targetsid = Convert-AzureAdObjectIdToSid -ObjectId $ObjectID
Write-Host $ObjectID "converts to" $targetsid

# Creating the Translation File
$TranslationTableString = '{"' + $Localsid + '":"' + $targetsid +'"}'
$TranslationTableString | Out-File -FilePath "TranslationTable.json" -Encoding UTF8
Write-Host "Translation table created... -- " $TranslationTableString
Write-Host "Kicking off Migration..."


# Run Script from PSP / Declaration Software
$FileName = "TranslationTable.json"
$regKey = "HKLM:\SOFTWARE\Declaration Software\Migration Agent"
$maDataDirectory = "C:\ProgramData\Declaration Software\Migration Agent"
$serviceName = "PowerSyncPro Migration Agent"
$runbooksFileName = "Runbooks.json"
$asciiLogo = 

"________                .__                       __  .__               
\______ \   ____   ____ |  | _____ ____________ _/  |_|__| ____   ____  
 |    |  \_/ __ \_/ ___\|  | \__  \\_  __ \__  \\   __\  |/  _ \ /    \ 
 |_____\  \  ___/\  \___|  |__/ __ \|  | \// __ \|  | |  (  <_> )   |  \
/_______  /\___  >\___  >____(____  /__|  (____  /__| |__|\____/|___|  /
        \/     \/     \/          \/           \/                    \/ 
  _________       _____  __                                             
 /   _____/ _____/ ____\/  |___  _  _______ _______   ____              
 \_____  \ /  _ \   __\\   __\ \/ \/ /\__  \\_  __ \_/ __ \             
 /        (  <_> )  |   |  |  \     /  / __ \|  | \/\  ___/             
/_______  /\____/|__|   |__|   \/\_/  (____  /__|    \___  >            
        \/                                 \/            \/             
"

Write-Host $asciiLogo
Write-Host "Workgroup Workstation Migration"

Start-Sleep 4

if((Test-Path $FileName)){

    Write-Host "Stopping Service $serviceName"

    Stop-Service -name $serviceName

    Write-Host "Setting Registry Entries"

    # Set the values for Domain and ComputerName in the registry
    Set-ItemProperty -Path $regKey -Name "DomainName" -Value $DomainName
    Set-ItemProperty -Path $regKey -Name "ComputerName" -Value $ComputerName
    
    Write-Output "ComputerName and DomainName have been saved to the registry under $regKey"
    
    # Processing GUIDs
    Write-Output "Processing RunbookGUIDs:"
    foreach ($guid in $RunbookGUIDs) {
        $translationTableTargetFolder = Join-Path -Path $maDataDirectory -ChildPath $guid
        
        if( -not (Test-Path $translationTableTargetFolder)){
            New-Item -Path $translationTableTargetFolder -ItemType "Directory" | Out-Null
        }

        Write-Host "Copying SID Translation Table $FileName to $translationTableTargetFolder"

        Copy-Item $FileName $translationTableTargetFolder  | Out-Null
    }

    $runbookFilePath = Join-Path -Path $maDataDirectory -ChildPath $runbooksFileName
    
    Write-Host "Removing $runbookFilePath"

    Remove-Item $runbookFilePath -ErrorAction SilentlyContinue  | Out-Null

    Write-Host "Restarting Service $serviceName"

    Restart-Service -name $serviceName
}
else{
    Write-Host "$FileName not found, script cannot continue"
}