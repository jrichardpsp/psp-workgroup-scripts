# Define parameter for CSV file path
param (
    [Parameter(Mandatory = $true, HelpMessage = "Path to the CSV file")]
    [string]$CsvPath
)

# Import the Microsoft Graph module
Import-Module Microsoft.Graph.Users

# Check if the CSV file exists
if (-not (Test-Path $CsvPath)) {
    Write-Error "The specified CSV file does not exist: $CsvPath"
    exit 1
}

# Connect to Microsoft Graph
try {
    Connect-MgGraph -Scopes "User.Read.All" -ErrorAction Stop
    Write-Host "Successfully connected to Microsoft Graph."
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

# Import the CSV file with explicit header validation
try {
    $csvData = Import-Csv -Path $CsvPath -ErrorAction Stop
    # Verify required headers exist
    $requiredHeaders = @("computer_name", "local_username", "target_upn", "target_entraid")
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

# Array to track non-existent UPNs
$missingUpns = @()

# Iterate through the CSV and lookup GUIDs
foreach ($row in $csvData) {
    $upn = $row.target_upn

    # Skip if UPN is empty or null
    if ([string]::IsNullOrWhiteSpace($upn)) {
        Write-Warning "Empty or invalid UPN found in row with computer_name: $($row.computer_name)"
        continue
    }

    # Lookup the user in Entra ID
    try {
        $user = Get-MgUser -UserId $upn -ErrorAction Stop
        # Store the GUID in the row (but don't write to CSV yet)
        $row.target_entraid = $user.Id
        Write-Host "Found GUID for '$upn': $($user.Id)"
    } catch {
        Write-Warning "User with UPN '$upn' not found."
        $missingUpns += $upn
    }
}

# Check if any UPNs were not found
if ($missingUpns.Count -gt 0) {
    Write-Error "The following UPNs do not exist in Entra ID: $($missingUpns -join ', '). Script aborted, CSV not updated."
    exit 1
}

# If all UPNs were found, update the CSV
try {
    $csvData | Export-Csv -Path $CsvPath -NoTypeInformation -Force
    Write-Host "CSV file successfully updated with Entra ID GUIDs: $CsvPath"
} catch {
    Write-Error "Failed to update CSV file: $_"
    exit 1
}

# Disconnect from Microsoft Graph
Disconnect-MgGraph
Write-Host "Disconnected from Microsoft Graph."