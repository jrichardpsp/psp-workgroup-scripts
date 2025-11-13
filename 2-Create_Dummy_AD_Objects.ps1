# Define parameters for CSV file path and OU distinguished name
param (
    [Parameter(Mandatory = $true, HelpMessage = "Path to the CSV file")]
    [string]$CsvPath,

    [Parameter(Mandatory = $true, HelpMessage = "Distinguished name of the target OU (e.g., 'OU=Computers,DC=domain,DC=com') - enclose in quotes")]
    [string]$TargetOU
)

# Import the Active Directory module
Import-Module ActiveDirectory -ErrorAction Stop

# Check if the CSV file exists
if (-not (Test-Path $CsvPath)) {
    Write-Error "The specified CSV file does not exist: $CsvPath"
    exit 1
}

# Import the CSV file
try {
    $csvData = Import-Csv -Path $CsvPath -ErrorAction Stop
    # Verify required header exists
    if ("computer_name" -notin $csvData[0].PSObject.Properties.Name) {
        Write-Error "CSV is missing required header: 'computer_name'"
        exit 1
    }
} catch {
    Write-Error "Failed to import CSV: $_"
    exit 1
}

# Get the domain DN from the current AD context if not fully specified
$domainDN = (Get-ADDomain).DistinguishedName
if ($TargetOU -notlike "*,DC=*") {
    $TargetOU = "$TargetOU,$domainDN"
}

# Check if the OU exists, create it if it doesn't
try {
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$TargetOU'" -ErrorAction SilentlyContinue)) {
        Write-Host "OU '$TargetOU' does not exist. Creating it..."
        # Split the OU path into components
        $ouParts = $TargetOU -split ","
        
        # Initialize parentPath with the domain DN
        $parentPath = $domainDN
        $ouComponents = @()
        
        # Separate OU and DC components
        foreach ($part in $ouParts) {
            if ($part -like "OU=*") {
                $ouComponents += $part
            }
        }

        # Create each OU level
        foreach ($ou in $ouComponents) {
            $ouName = $ou -replace "OU=",""
            $currentPath = "$ou,$parentPath"
            if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$currentPath'" -ErrorAction SilentlyContinue)) {
                New-ADOrganizationalUnit -Name $ouName -Path $parentPath -ErrorAction Stop
                Write-Host "Created OU: $currentPath"
            }
            $parentPath = $currentPath
        }
    } else {
        Write-Host "OU '$TargetOU' already exists."
    }
} catch {
    Write-Error "Failed to verify or create OU '$TargetOU': $_"
    exit 1
}

# Iterate through the CSV and create computer objects
foreach ($row in $csvData) {
    $computerName = $row.computer_name

    # Skip if computer_name is empty
    if ([string]::IsNullOrWhiteSpace($computerName)) {
        Write-Warning "Empty computer_name found in row. Skipping."
        continue
    }

    # Check if the computer already exists
    try {
        $existingComputer = Get-ADComputer -Filter "Name -eq '$computerName'" -ErrorAction SilentlyContinue
        if ($existingComputer) {
            Write-Warning "Computer '$computerName' already exists in AD at '$($existingComputer.DistinguishedName)'. Skipping."
            continue
        }

        # Create the computer object
        New-ADComputer -Name $computerName -Path $TargetOU -Enabled $true -ErrorAction Stop
        Write-Host "Created computer object '$computerName' in '$TargetOU'."
    } catch {
        Write-Error "Failed to create computer object '$computerName': $_"
        exit 1
    }
}

Write-Host "Script completed successfully."