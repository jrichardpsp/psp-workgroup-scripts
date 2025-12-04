<#
.SYNOPSIS
    Automates a full workstation migration from a local workgroup user profile
    to a target directory user (Entra ID / AD) using the PowerSyncPro API.

.DESCRIPTION
    This script performs an end-to-end automated workstation migration using
    PowerSyncPro's API and Migration Agent. It validates and maps the local
    user to a target UPN, looks up the corresponding target SID, and builds a
    translation table for the PSP Migration Agent.

    The workflow:
      • Connects to the PSP server using saved auth credentials.
      • Looks up Runbooks, Batches, Directory IDs, and the target SID.
      • Creates the workstation's computer object in a "dummy" AD domain via
        raw LDAP (no RSAT required).
      • Triggers a PSP directory sync and verifies the new computer appears.
      • Assigns the machine to the correct PSP batch.
      • Installs .NET 8 and the PSP Migration Agent if not already present.
      • Configures the agent for workgroup migration, including registry values
        and per-runbook translation tables.
      • Restarts the PSP Migration Agent so the migration is ready to begin.

    This is intended for M&A "war room" migrations, workgroup onboarding,
    remote acquisitions, or lab/demo environments where machines cannot be
    domain-joined prior to migration.

.PARAMETER TargetUPN
    The target directory user principal name (user@domain.com)
    that this workstation should be migrated to.

.PARAMETER LocalUsername
    The local workgroup username to migrate. If omitted, the script will list
    local users and prompt for selection.

.NOTES
    Requires API access to the PSP server, local admin rights, and connectivity
    to the dummy AD domain controller for LDAP object creation.
    Use in controlled/internal environments only.

    Date            December/2025
    Disclaimer:     This script is provided 'AS IS'. No warrantee is provided either expressed or implied. Declaration Software Ltd cannot be held responsible for any misuse of the script.
    Version: beta 0.1
    Updated: Initial Public Release.
    Copyright (c) 2025 Declaration Software
#>

param(
    [string]$TargetUPN,
    [string]$LocalUsername
)

# =====================================================================
# Global Configuration (Edit These for Your Environment)
# =====================================================================

# --------------------------- Logging ---------------------------------
# Log file name and directory used for transcript and operational logs.
$logName = "Workgroup_Migration_Log.log"
$logDir  = "C:\Temp"


# ---------------------- PowerSyncPro API Access -----------------------
# Module containing PSP API helper functions.
$apiModule = ".\PowerSyncPro-WebAPI.psm1"

# URL of the PowerSyncPro server.
$baseURL = "https://psp1.jrr.me"

# Credentials used to authenticate to the PSP API.
# Required roles: Agent Admin, Agent Viewer, Sync Operator (or Global Admin).
$pspUser = "scriptapi"
$pspPass = "gi@ntPark90"


# --------------------- PSP Runbook / Batch Info ----------------------
# Names of the Runbook and Batch that define the migration workflow.
$runBookName = "Workgroup API Migration"
$batchName   = "Workgroup API Migration"


# --------------------- PSP Agent Installation -------------------------
# Download location for the self-contained PSP Migration Agent MSI
# (served by your PSP instance).
$pspmig_loc      = $baseURL + "/downloads/self-contained/PSPMigrationAgentInstaller.msi"

# Endpoint URL the Migration Agent will communicate with after install.
$pspsvr_endpoint = $baseURL + "/Agent"


# ------------------ Dummy Active Directory Parameters -----------------
# Used to create a temporary computer object for PSP ingestion.
# The machine does NOT need to be domain-joined for this.

# Domain controller used for LDAP object creation.
$DomainController = "172.20.100.240"

# Fully qualified domain name of the dummy/staging domain.
$DomainName = "dummy.local"

# Distinguished Name of the OU where computer objects should be created.
$TargetOU = "OU=MigrationPCs,DC=dummy,DC=local"

# Credentials with permissions to create computer objects in the target OU.
$DomainUser = "DUMMY\Administrator"
$DomainPass = "Foobar12345!"


$asciiLogo=@"
 ____                        ____                   ____            
|  _ \ _____      _____ _ __/ ___| _   _ _ __   ___|  _ \ _ __ ___  
| |_) / _ \ \ /\ / / _ \ '__\___ \| | | | '_ \ / __| |_) | '__/ _ \ 
|  __/ (_) \ V  V /  __/ |   ___) | |_| | | | | (__|  __/| | | (_) |
|_|   \___/ \_/\_/ \___|_|  |____/ \__, |_| |_|\___|_|   |_|  \___/ 
                                   |___/                            
"@

# Functions
# ------------------ Logging Functions ------------------
function Info  { param($Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Ok    { param($Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Warn  { param($Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Err   { param($Message) Write-Host "[-] $Message" -ForegroundColor Red }
function Add-ADComputerObject {
    <#
    .SYNOPSIS
        Creates a computer object in Active Directory using raw LDAP.
        Works from non-domain-joined machines without RSAT.

    .PARAMETER DomainController
        FQDN or IP of the target Domain Controller.

    .PARAMETER User
        Domain user account with permissions to create computer objects.

    .PARAMETER Password
        Plain text password for the account (for lab/demo use).

    .PARAMETER OU
        Distinguished name of the OU or container where the object should be created.
        Example: CN=Computers,DC=lab,DC=rocklightnetworks,DC=com

    .PARAMETER ComputerName
        Name of the computer object to create (default: local hostname).
    #>

    param(
        [Parameter(Mandatory)] [string]$DomainController,
        [Parameter(Mandatory)] [string]$User,
        [Parameter(Mandatory)] [string]$Password,
        [Parameter(Mandatory)] [string]$OU,
        [string]$ComputerName = $env:COMPUTERNAME
    )

    Info "Attempting to create computer object '$ComputerName' in $OU"

    $LdapPath = "LDAP://$DomainController/$OU"

    try {
        $OUentry = New-Object System.DirectoryServices.DirectoryEntry($LdapPath, $User, $Password)
        if (-not $OUentry.Name) {
            throw "Unable to bind to target OU at $LdapPath"
        }
    }
    catch {
        Err "Failed to bind to OU: $($_.Exception.Message)"
        return $false
    }

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($OUentry)
    $Searcher.Filter = "(sAMAccountName=$ComputerName`$)"
    $Searcher.SearchScope = "OneLevel"
    $Searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None

    try {
        $result = $Searcher.FindOne()
    }
    catch {
        Err "LDAP search failed: $($_.Exception.Message)"
        $OUentry.Dispose()
        return $false
    }

    if ($result) {
        Warn "Computer object '$ComputerName' already exists."
    }
    else {
        Info "Creating new computer object '$ComputerName'..."
        try {
            $newComputer = $OUentry.Children.Add("CN=$ComputerName", "computer")
            $newComputer.Put("sAMAccountName", "$ComputerName`$")
            $newComputer.Put("userAccountControl", 4096) # WORKSTATION_TRUST_ACCOUNT
            $newComputer.SetInfo()
            Ok "Computer object created successfully."
        }
        catch {
            Err "Error creating computer object: $($_.Exception.Message)"
            $OUentry.Dispose()
            return $false
        }
    }

    $OUentry.Dispose()
    return $true
}
function Test-LocalUserExists {

    param([string]$Name)
    try {
        # Try to get the local user; if found, return $true
        $user = Get-LocalUser -Name $Name -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}
function Install-PSPMigrationAgent {
<#
.SYNOPSIS
    Downloads, installs, and validates the PowerSyncPro Migration Agent.

.DESCRIPTION
    This function ensures that the PowerSyncPro Migration Agent is installed
    and operational on the local workstation. If the agent is not already
    present, the function downloads the MSI installer, performs a silent
    installation, applies the required PSK and server endpoint settings, and
    verifies that the "PowerSyncPro Migration Agent" service is created and
    reaches the Running state.

    The function will:
      • Detect whether the Migration Agent is already installed.
      • Download the agent installer from the specified PSP server URL.
      • Perform a silent MSI install with custom parameters (PSK + server URL).
      • Wait for the PSP service to be created and start successfully.
      • Throw an exception if installation or startup fails, preventing the
        migration workflow from continuing in an invalid state.

.PARAMETER InstallerUrl
    The HTTP/S URL pointing to the PSP Migration Agent MSI.

.PARAMETER InstallerPath
    Local path where the MSI should be downloaded to (default: C:\Temp).

.PARAMETER PSK
    The Pre-Shared Key retrieved from the PSP API for agent registration.

.PARAMETER ServerEndpoint
    The PSP server endpoint the agent should communicate with (e.g., https://psp1.company.com/Agent).

.PARAMETER Timeout
    Number of seconds to wait for the PSP service to appear and reach Running.

.PARAMETER Interval
    The delay (in seconds) between service status checks during installation.

.NOTES
    This function throws on failure. Callers should wrap it in try/catch or run
    within an existing error-handled workflow.
#>

    param(
        [string]$InstallerUrl,
        [string]$InstallerPath = "C:\Temp\PSPMigrationAgentInstaller.msi",
        [string]$PSK,
        [string]$ServerEndpoint,
        [int]$Timeout = 20,
        [int]$Interval = 2
    )

    # Hardcoded PSP service name
    $ServiceName = "PowerSyncPro Migration Agent"

    # Check if already installed
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Info "Service '$ServiceName' already installed (Status: $($existing.Status))"
        return
    }

    Warn  "Service '$ServiceName' is not installed."
    Info  "Downloading PSP Migration Agent from $InstallerUrl ..."

    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath -UseBasicParsing -ErrorAction Stop
    }
    catch {
        Err "Failed to download PSP Migration Agent: $($_.Exception.Message)"
        throw
    }

    Info "Installing PSP Migration Agent..."

    $arguments = @(
        "/i", "`"$InstallerPath`"",
        "PSK=$PSK",
        "URL=$ServerEndpoint",
        "/qn",
        "/l*v", "`"C:\Temp\PSPAgent_Install.log`""
    )

    $exitCode = (Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru).ExitCode
    Ok "MSI exited with code $exitCode"

    # Wait for PSP service to appear and run
    $elapsed = 0
    while ($elapsed -lt $Timeout) {

        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

        if ($svc -and $svc.Status -eq "Running") {
            Ok "Service '$ServiceName' installed and running."
            return
        }

        if ($svc) {
            Warn "Service '$ServiceName' status is $($svc.Status). Waiting..."
        }
        else {
            Warn "Service '$ServiceName' not found yet. Waiting..."
        }

        Start-Sleep -Seconds $Interval
        $elapsed += $Interval
    }

    Err "Service '$ServiceName' did not reach 'Running' within $Timeout seconds."
    throw "PSP Migration Agent installation failed."
}
# ------- Start Script -------
try{
    #Transcript Logging
    $logPath = Join-Path -Path $logDir -ChildPath $logName
    Start-Transcript -Append -Path $logPath

    # Import PSP API Functions
    Import-Module $apiModule -Force

    # Get Computer Name
    $ComputerName = $env:COMPUTERNAME
    Write-Host $asciiLogo
    Info "Preparing to Migrate this Workstation using the $runBookName Runbook..."
    Start-Sleep -Seconds 3

    # Setup PSP API Access
    Info "Connecting to PSP Server via Provided Credentials..."
    try{
        $session = Get-PSPSession -BaseURL $baseURL -Username $pspUser -Password $pspPass
        if (-not $session) { throw "API returned no response." }
    }
    catch{
        Write-Error "Fatal error: $($_.Exception.Message)"
        throw  # Re-throw to bubble the error up
    }

    # Validate Local Username provided in parameters work, if not enumerate all local users on box and prompt the user to select one.
    if (-not $LocalUsername -or [string]::IsNullOrWhiteSpace($LocalUsername)) {

        # Enumerate all local users (filter out system/service accounts)
        $localUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.Name -notmatch '^(Guest)$' }

        if (-not $localUsers -or $localUsers.Count -eq 0) {
            Err "No local user accounts found on this system."
            exit 1
        }

        Write-Host ""
        Write-Host "Available local user accounts:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $localUsers.Count; $i++) {
            Write-Host ("[{0}] {1}" -f ($i + 1), $localUsers[$i].Name)
        }
        Write-Host ""

        while ($true) {
            $choice = Read-Host "Select the user to migrate (1-$($localUsers.Count)) or type a username manually"
            $choice = $choice.Trim()

            if ([int]::TryParse($choice, [ref]$null) -and $choice -ge 1 -and $choice -le $localUsers.Count) {
                $LocalUsername = $localUsers[$choice - 1].Name
                Ok "Selected local user: $LocalUsername"
                break
            }
            elseif (-not [string]::IsNullOrWhiteSpace($choice)) {
                # Manual entry fallback
                if (Get-LocalUser -Name $choice -ErrorAction SilentlyContinue) {
                    $LocalUsername = $choice
                    Ok "Valid local user found: $LocalUsername"
                    break
                }
                else {
                    Err "No local user named '$choice' exists on this system."
                }
            }
            else {
                Warn "Invalid selection. Please try again."
            }
        }

    }
    else {
        # Parameter was provided — validate it
        if (Get-LocalUser -Name $LocalUsername -ErrorAction SilentlyContinue) {
            Ok "Using provided local user: $LocalUsername"
        } else {
            Err "Error: The specified user '$LocalUsername' does not exist on this system."
            exit 1
        }
    }

    # Convert Source Local Username to SID
    # Obtain from the local system...
    # SID of the Local Workgroup User
    $SearchSID = Get-WmiObject win32_useraccount | Where-Object Name -match $LocalUserName
    $LocalSiD = $SearchSID.SID
    Info "Current SID of $LocalUsername is $LocalSiD"

    # Prompt / Validate UPN for Target User
    $emailPattern = '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
    # If the parameter was provided, validate immediately
    if ($TargetUPN) {
        $TargetUPN = $TargetUPN.Trim()

        if ($TargetUPN -match $emailPattern) {
            Ok "Using provided UPN: $TargetUPN"
        } else {
            Err "Invalid UPN format provided via parameter: $TargetUPN"
            exit 1
        }
    }
    else {
        # Otherwise prompt interactively until valid
        while ($true) {
            $TargetUPN = Read-Host "Enter the Target UPN (e.g. user@domain.com)"
            $TargetUPN = $TargetUPN.Trim()

            if ([string]::IsNullOrWhiteSpace($TargetUPN)) {
                Warn "UPN cannot be empty. Please try again."
                continue
            }

            if ($TargetUPN -match $emailPattern) {
                Ok "Valid UPN entered: $TargetUPN"
                break
            } else {
                Err "Invalid UPN format. Please enter a valid email address (user@domain.com)."
            }
        }
    }

    # Normalize case (optional)
    $TargetUPN = $TargetUPN.ToLowerInvariant()

    # Lookup Target UPN via PSP API and get Target SID
    # Get Batch
    try{
        $batch = Get-PSPBatches -BaseURL $baseURl -Session $session -Name $batchName
        if (-not $batch) { throw "API returned no response getting requested batch." }
    }
    catch{
        Write-Error "Fatal error: $($_.Exception.Message)"
        throw  # Re-throw to bubble the error up
    }

    #Write-Host $batch

    # Get Directory ID for Target
    try{
        $targetDirID = Get-PSPDirectoryIdByDisplayName -BaseUrl $baseURL -Session $session -DisplayName $batch.targetDirectoryDisplayName
        if (-not $targetDirID) { throw "API returned no response getting requested Directory ID." }
    }
    catch{
        Write-Error "Fatal error: $($_.Exception.Message)"
        throw  # Re-throw to bubble the error up
    }

    # Get Directory Type for Target
    $targetDirInfo = Get-PSPDirectories -DirectoryID $targetDirID -BaseUrl $baseURL -Session $session
    $targetDirType = $targetDirInfo.directoryTypeName

    # Get Directory ID for Source
    try{

        $sourceDirID = Get-PSPDirectoryIdByDisplayName -BaseUrl $baseURL -Session $session -DisplayName $batch.sourceDirectoryDisplayName
        if (-not $sourceDirID) { throw "API returned no response getting requested Directory ID." }
    }
    catch{
        Write-Error "Fatal error: $($_.Exception.Message)"
        throw  # Re-throw to bubble the error up
    }

    # Get Target UPN for Provided User
    try{
        $targetSID = Get-PSPSIDFromUPN -BaseUrl $baseURL -Session $session -DirectoryId $targetDirID -UserPrincipalName $TargetUPN
        if (-not $targetSID) { throw "API returned no response getting requested SID." }
    }
    catch{
        Write-Error "Fatal error: $($_.Exception.Message)"
        throw  # Re-throw to bubble the error up
    }

    Ok "Target SID for $TargetUPN is $targetSID..."

    # Get Runbook and Batch Info
    try{
        $runbook = Get-PSPRunbooks -BaseURL $baseurl -Session $session -Name $runBookName
        if (-not $runbook) { throw "API returned no response getting requested Runbook info." }
    }
    catch {
        Write-Error "Fatal error: $($_.Exception.Message)"
        throw  # Re-throw to bubble the error up
    }
    $runbookID = $runbook.ID
    $RunbookGUIDs = @($runbook.ID)
    $runbookName = $runbook.name

    $batchID = $batch.ID
    $batchName = $batch.DisplayName
    $batchTargetDir = $batch.targetDirectoryDisplayName

    Write-Host "---- Migration Summary ----" -ForegroundColor Green
    Write-Host "Runbook: $runbookName - $runbookID" -ForegroundColor Cyan
    Write-Host "Target Directory: $batchTargetDir" -ForegroundColor Cyan
    Write-Host "Source (Local) Username: $LocalUserName" -ForegroundColor Yellow
    Write-Host "Source (Local) SID: $LocalSiD" -ForegroundColor Yellow
    Write-Host "Target ($targetDirType) UPN: $TargetUPN" -ForegroundColor DarkBlue
    Write-Host "Target ($targetDirType) SID: $targetSID" -ForegroundColor DarkBlue

    Ok "Proceeding to setup job to migrate..."
    Start-Sleep -Seconds 8

    # Add Computer to Dummy AD via LDAP
    Info "Adding this machine $ComputerName to AD via LDAP Call to Domain Controller..."
    try {
        Add-ADComputerObject -DomainController $DomainController -User $DomainUser -Password $DomainPass -OU $TargetOU -ComputerName $ComputerName
    }
    catch {
        Write-Error "Fatal error while adding object to AD: $($_.Exception.Message)"
        throw  # Re-throw to bubble the error up
    }

    # Trigger Scheduled Run to Sync in new Computer Object
    Info "Triggering Schedule Run on PSP via API to sync in new object..."
    try {
        Invoke-PSPRunScheduleNow -BaseURL $baseURL -Session $session
    }
    catch {
        Write-Error "Fatal error while scheduling refresh of PSP Directory: $($_.Exception.Message)"
        throw  # Re-throw to bubble the error up
    }

    # Object should now exist in PSP, verify this via the API.
    # Try every 10 seconds up to 10 times.
    Info "Verifying that $ComputerName exists in PSP Directory..."
    $IntervalSeconds = 10
    $MaxAttempts     = 10
    $Result          = $null
    for ($i = 1; $i -le $MaxAttempts; $i++) {
        Info "Attempt $i of $MaxAttempts..."
        try {
            $Result = Find-PSPComputer -BaseURL $baseurl -Session $session -DirectoryId $sourceDirID -ComputerName $ComputerName -Exact
        }
        catch {
            Write-Error "Fatal error while determining if new object exists in PSP: $($_.Exception.Message)"
            throw  # Re-throw to bubble the error up
        }

        if ($null -ne $Result) {
            Ok "Computer $ComputerName found in PSP. Proceeding..."
            break
        }

        Warn "No result, retrying in $IntervalSeconds seconds..."
        Start-Sleep -Seconds $IntervalSeconds
    }

    if ($null -eq $Result) {
        Err "Timed out after $MaxAttempts attempts with no result. Computer not found in PSP database."
        Exit 1
    }

    # New Computer Object exists in AD and has been imported into PSP and is ready to go.
    # Add PC to Defined Batch
    Add-PSPBatchComputer -BaseURL $baseURL -Session $session -BatchID $batchID -ComputerName $ComputerName

    # Machine is now added to AD, imported into PSP, and assigned to the required batch.
    # Lets install PSP and configure the agent as a Workgroup Agent

    # Get PSP PSK from API
    try {
        $pspsvr_psk = (Get-PSPPreSharedKeys -BaseURL $baseurl -Session $session -IncludeMigrationAgents -ActiveKey).psk
        if (-not $pspsvr_psk) { throw "API returned no response getting requested PSK info." }
    }
    catch {
        Write-Error "Fatal error attempting to get PSP PSK from API: $($_.Exception.Message)"
        throw  # Re-throw to bubble the error up
    }

    # Install PSP Migration Agent.
    Install-PSPMigrationAgent `
    -InstallerUrl $pspmig_loc `
    -PSK $pspsvr_psk `
    -ServerEndpoint $pspsvr_endpoint

    Ok "PSP is installed and running, configuring workgroup migration.."

    # Creating the Translation File
    $TranslationTableLocation = Join-Path -Path $logDir -ChildPath "TranslationTable.json"
    Info "Creating Translation Table at $TranslationTableLocation"
    $TranslationTableString = '{"' + $Localsid + '":"' + $targetsid +'"}'
    $TranslationTableString | Out-File -FilePath $TranslationTableLocation -Encoding UTF8
    Ok "Translation table created..."
    Info "$TranslationTableString"

    # Run Script from PSP / Declaration Software
    $FileName = "TranslationTable.json"
    $regKey = "HKLM:\SOFTWARE\Declaration Software\Migration Agent"
    $maDataDirectory = "C:\ProgramData\Declaration Software\Migration Agent"
    $serviceName = "PowerSyncPro Migration Agent"
    $runbooksFileName = "Runbooks.json"

    if((Test-Path $TranslationTableLocation)){

        Info "Stopping Service $serviceName"

        Stop-Service -name $serviceName

        Info "Setting Registry Entries"

        # Set the values for Domain and ComputerName in the registry
        Set-ItemProperty -Path $regKey -Name "DomainName" -Value $DomainName
        Set-ItemProperty -Path $regKey -Name "ComputerName" -Value $ComputerName
        
        Ok "ComputerName and DomainName have been saved to the registry under $regKey"
        
        # Processing GUIDs
        Info "Processing RunbookGUIDs:"
        foreach ($guid in $RunbookGUIDs) {
            $translationTableTargetFolder = Join-Path -Path $maDataDirectory -ChildPath $guid
            
            if( -not (Test-Path $translationTableTargetFolder)){
                New-Item -Path $translationTableTargetFolder -ItemType "Directory" | Out-Null
            }

            Info "Copying SID Translation Table $TranslationTableLocation to $translationTableTargetFolder"

            Copy-Item $TranslationTableLocation $translationTableTargetFolder  | Out-Null
        }

        $runbookFilePath = Join-Path -Path $maDataDirectory -ChildPath $runbooksFileName
        
        Info "Removing $runbookFilePath"

        Remove-Item $runbookFilePath -ErrorAction SilentlyContinue  | Out-Null

        Info "Restarting Service $serviceName"

        Restart-Service -name $serviceName
    }
    else{
        Err "$FileName not found, script cannot continue"
    }

    Ok "Complete. If the selected batch is available for users, you should already be prompted to migrate."
}
catch {
    Write-Error "Unhandled error: $($_.Exception.Message)"
}
finally{
    Stop-Transcript
}