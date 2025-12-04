# PowerSyncPro-WebAPI.psm1
# Automates authentication and API calls for PowerSyncPro instances.
# Compatible with Windows PowerShell 5.1+ and PowerShell 7+

# Global Variables used to store BaseURL and Session Token for ease of use.
# region Module-scope globals
$script:PSPDefaultBaseUrl = $null
$script:PSPSession = $null
# endregion

# ---------------------------------------------------------------------
# Core API Functions
# ---------------------------------------------------------------------
function Get-PSPSession {
    <#
    .SYNOPSIS
        Authenticates to a PowerSyncPro server and creates a reusable WebRequestSession.

    .DESCRIPTION
        Logs into the PowerSyncPro web portal using username, password, and tenant ID.
        Returns a WebRequestSession object preloaded with authentication cookies and XSRF token.
        The session can be reused for subsequent Invoke-PSPApi or data retrieval calls.

    .PARAMETER BaseUrl
        Base URL of the PowerSyncPro instance (e.g. https://psp.company.com)

    .PARAMETER Username
        User name access to the PowerSyncPro portal.

    .PARAMETER Password
        Password for the PowerSyncPro account.

    .PARAMETER TenantId
        Numeric tenant ID (default 1).

    .EXAMPLE
        $session = Get-PSPSession -BaseUrl "https://psp.company.com" -Username "admin" -Password "P@ssword1"
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BaseUrl,
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)][string]$Password,
        [int]$TenantId = 1
    )

    Write-Host "Initializing PowerSyncPro authentication for $BaseUrl" -ForegroundColor Cyan
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

    try {
        # Step 1: Get login page
        $loginPage = Invoke-WebRequest -Uri "$BaseUrl/Account/Login" -WebSession $session -UseBasicParsing -ErrorAction Stop
        $tokenMatch = [regex]::Match($loginPage.Content, 'name="__RequestVerificationToken"\s+type="hidden"\s+value="([^"]+)"')
        if (-not $tokenMatch.Success) { throw "Failed to extract antiforgery token." }

        $token = $tokenMatch.Groups[1].Value
        Write-Host "Antiforgery token extracted." -ForegroundColor Yellow

        # Step 2: Add tenant cookie
        $tenantCookie = New-Object System.Net.Cookie
        $tenantCookie.Name  = "Abp.TenantId"
        $tenantCookie.Value = "$TenantId"
        $tenantCookie.Domain = ([uri]$BaseUrl).Host
        $tenantCookie.Path = "/"
        $session.Cookies.Add(([uri]$BaseUrl), $tenantCookie)
        Write-Host "Added Abp.TenantId=$TenantId cookie" -ForegroundColor Yellow

        # Step 3: Build body
        $body = "__RequestVerificationToken=$([uri]::EscapeDataString($token))" +
                "&usernameOrEmailAddress=$([uri]::EscapeDataString($Username))" +
                "&Password=$([uri]::EscapeDataString($Password))" +
                "&returnUrl=%2F&returnUrlHash="

        Write-Host "Attempting login..." -ForegroundColor Yellow

        # Step 4: POST credentials
        $loginResponse = Invoke-WebRequest -Uri "$BaseUrl/Account/Login" `
            -WebSession $session `
            -Method POST `
            -ContentType "application/x-www-form-urlencoded" `
            -Body $body `
            -UseBasicParsing `
            -ErrorAction Stop

        Write-Host "Login response: HTTP $($loginResponse.StatusCode) $($loginResponse.StatusDescription)" -ForegroundColor Green

        # Step 5: Parse JSON
        try { $json = $loginResponse.Content | ConvertFrom-Json } catch { $json = $null }

        if ($null -ne $json -and $json.success -eq $false) {
            $err = $json.error.details
            if (-not $err) { $err = $json.error.message }
            throw "Login failed: $err"
        }

        # Step 6: Refresh antiforgery token
        $refresh = Invoke-WebRequest -Uri "$BaseUrl/" -WebSession $session -UseBasicParsing
        $xsrf = ($session.Cookies.GetCookies($BaseUrl) | Where-Object { $_.Name -eq "XSRF-TOKEN" }).Value
        if (-not $xsrf) { throw "Failed to obtain refreshed XSRF token." }

        $session | Add-Member -NotePropertyName XsrfToken -NotePropertyValue $xsrf -Force
        Write-Host "Login successful for user '$Username' (TenantId=$TenantId)" -ForegroundColor Green

        # persist in module scope
        $script:PSPSession = $session
        $script:PSPDefaultBaseUrl = $BaseUrl

        Write-Host "Session stored for $BaseUrl" -ForegroundColor Green

        return $session
    }
    catch {
        Write-Host ""
        Write-Host "Login failed: $($_.Exception.Message)" -ForegroundColor Red

        $rawBody = $null
        if ($_.Exception.Response) {
            try {
                $reader = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
                $rawBody = $reader.ReadToEnd()
            } catch {}
        }

        # If Invoke-WebRequest swallowed the response, retry low-level read
        if (-not $rawBody) {
            try {
                $postData = "__RequestVerificationToken=$([uri]::EscapeDataString($token))" +
                            "&usernameOrEmailAddress=$([uri]::EscapeDataString($Username))" +
                            "&Password=$([uri]::EscapeDataString($Password))" +
                            "&returnUrl=%2F&returnUrlHash="

                $req = [System.Net.HttpWebRequest]::Create("$BaseUrl/Account/Login")
                $req.Method = "POST"
                $req.ContentType = "application/x-www-form-urlencoded"
                $req.CookieContainer = $session.Cookies
                $req.AllowAutoRedirect = $false
                $req.UserAgent = "PowerShellDiag"

                $bytes = [System.Text.Encoding]::UTF8.GetBytes($postData)
                $req.ContentLength = $bytes.Length
                $stream = $req.GetRequestStream()
                $stream.Write($bytes, 0, $bytes.Length)
                $stream.Close()

                try {
                    $resp = $req.GetResponse()
                    $reader = New-Object IO.StreamReader($resp.GetResponseStream())
                    $rawBody = $reader.ReadToEnd()
                    $resp.Close()
                }
                catch [System.Net.WebException] {
                    if ($_.Exception.Response) {
                        $resp = $_.Exception.Response
                        $reader = New-Object IO.StreamReader($resp.GetResponseStream())
                        $rawBody = $reader.ReadToEnd()
                    }
                }
            }
            catch {
                Write-Host "Diagnostic retry failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        # If we got a JSON body, decode and interpret it
        if ($rawBody -and $rawBody.Trim().StartsWith('{')) {
            try {
                $jsonErr = $rawBody | ConvertFrom-Json -ErrorAction Stop
                if ($jsonErr.error.details -match "Invalid user name or password") {
                    Write-Host "Invalid username or password. Please verify credentials and try again." -ForegroundColor Yellow
                }
                elseif ($jsonErr.error.details) {
                    Write-Host "Server returned error: $($jsonErr.error.details)" -ForegroundColor Yellow
                }
                else {
                    Write-Host "Server returned: $($jsonErr.error.message)" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Could not parse JSON error body." -ForegroundColor Yellow
                Write-Host ($rawBody.Substring(0, [Math]::Min(800, $rawBody.Length)))
            }
        }
        elseif ($rawBody) {
            Write-Host ($rawBody.Substring(0, [Math]::Min(800, $rawBody.Length)))
        }
        else {
            Write-Host "(No response body received)" -ForegroundColor Yellow
        }

        return $null
    }
}
function Destroy-PSPSession {
    <#
    .SYNOPSIS
        Destroys an active PowerSyncPro WebRequestSession and optionally logs out server-side.

    .DESCRIPTION
        Safely removes all cookies, XSRF tokens, and note properties from the PowerSyncPro
        session object. Optionally performs an HTTP logout request before clearing data.
        If no session is passed explicitly, the function will use the stored session
        ($script:PSPSession) and base URL ($script:PSPDefaultBaseUrl) if available.

    .PARAMETER Session
        The WebRequestSession object created by Get-PSPSession or Connect-PSPServer.
        If not provided, the stored session will be used.

    .PARAMETER BaseUrl
        (Optional) Base URL of the PowerSyncPro server (e.g. https://psp.company.com).
        Required only if -Logout is specified. Defaults to the stored base URL.

    .PARAMETER Logout
        If specified, attempts to log out from the PowerSyncPro server using /Account/Logout.

    .EXAMPLE
        Destroy-PSPSession
        # Clears the stored session (if present) and resets defaults.

    .EXAMPLE
        Destroy-PSPSession -Session $session
        # Clears a specific session passed explicitly.

    .EXAMPLE
        Destroy-PSPSession -Logout
        # Performs server logout and clears stored session data.
    #>
    [CmdletBinding()]
    param(
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$BaseUrl,
        [switch]$Logout
    )

    process {
        # --- Prefer explicit parameters; fall back to stored values ---
        if (-not $Session -and $script:PSPSession) {
            Write-Verbose "Using stored PowerSyncPro session."
            $Session = $script:PSPSession
        }

        if (-not $BaseUrl -and $script:PSPDefaultBaseUrl) {
            Write-Verbose "Using stored PowerSyncPro BaseUrl."
            $BaseUrl = $script:PSPDefaultBaseUrl
        }

        if (-not $Session) {
            Write-Warning "No active PowerSyncPro session found to destroy."
            return
        }

        try {
            if ($Logout -and $BaseUrl) {
                Write-Host "Attempting server logout..." -ForegroundColor Yellow
                try {
                    $logoutUrl = "$BaseUrl/Account/Logout"
                    Invoke-WebRequest -Uri $logoutUrl -WebSession $Session -Method GET -UseBasicParsing -ErrorAction Stop | Out-Null
                    Write-Host "Server-side logout completed." -ForegroundColor Green
                }
                catch {
                    Write-Warning "Warning: server logout request failed: $($_.Exception.Message)"
                }
            }

            # --- Reset cookies ---
            if ($Session.Cookies -and $Session.Cookies -is [System.Net.CookieContainer]) {
                $Session.Cookies = New-Object System.Net.CookieContainer
            }

            # --- Remove custom note properties ---
            foreach ($prop in @('XsrfToken','BaseUrl','TenantId')) {
                if ($Session.PSObject.Properties.Name -contains $prop) {
                    $Session.PSObject.Properties.Remove($prop)
                }
            }

            # --- Clear stored session variables ---
            if ($Session -eq $script:PSPSession) {
                Write-Verbose "Clearing stored PowerSyncPro session and BaseUrl."
                $script:PSPSession = $null
                $script:PSPDefaultBaseUrl = $null
            }

            # --- Garbage collection cleanup ---
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()

            Write-Host "PowerSyncPro session destroyed. All cookies and tokens cleared." -ForegroundColor Green
        }
        catch {
            Write-Host "Error clearing session: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}
function Get-PSPSessionStatus {
    <#
    .SYNOPSIS
        Displays the current PowerSyncPro session and connection status.

    .DESCRIPTION
        Reports information about the stored PowerSyncPro session ($script:PSPSession)
        and base URL ($script:PSPDefaultBaseUrl).  If no session is currently active,
        it clearly indicates that state.  When a session exists, it extracts key details
        such as XSRF token presence, cookie count, tenant ID, and age.

    .EXAMPLE
        Get-PSPSessionStatus
        # Shows whether a PowerSyncPro session is active and ready for API calls.
    #>
    [CmdletBinding()]
    param()

    # Check stored values
    $hasSession = $null -ne $script:PSPSession
    $hasBaseUrl = $null -ne $script:PSPDefaultBaseUrl

    if (-not $hasSession -and -not $hasBaseUrl) {
        Write-Host "No PowerSyncPro session or BaseUrl is currently stored." -ForegroundColor Yellow
        return
    }

    $status = [ordered]@{
        BaseUrl           = if ($hasBaseUrl) { $script:PSPDefaultBaseUrl } else { "(none)" }
        SessionPresent    = $hasSession
        CookiesCount      = if ($hasSession -and $script:PSPSession.Cookies) {
                                try { ($script:PSPSession.Cookies.GetCookies($script:PSPDefaultBaseUrl)).Count }
                                catch { "N/A" }
                            } else { 0 }
        XSRFTokenPresent  = if ($hasSession -and $script:PSPSession.PSObject.Properties.Name -contains 'XsrfToken') {
                                -not [string]::IsNullOrWhiteSpace($script:PSPSession.XsrfToken)
                            } else { $false }
        TenantId          = if ($hasSession -and $script:PSPSession.PSObject.Properties.Name -contains 'TenantId') {
                                $script:PSPSession.TenantId
                            } else { "(not set)" }
        CreatedTime       = if ($hasSession -and $script:PSPSession.PSObject.Properties.Name -contains 'CreatedTime') {
                                $script:PSPSession.CreatedTime
                            } else { "(unknown)" }
    }

    # Output status
    Write-Host ""
    Write-Host "=== PowerSyncPro Session Status ===" -ForegroundColor Cyan
    $status.GetEnumerator() | ForEach-Object {
        $color = "Gray"
        if ($_.Key -eq "SessionPresent" -and $_.Value -eq $false) { $color = "Red" }
        if ($_.Key -eq "SessionPresent" -and $_.Value -eq $true)  { $color = "Green" }
        Write-Host ("{0,-20}: {1}" -f $_.Key, $_.Value) -ForegroundColor $color
    }
    Write-Host "===================================" -ForegroundColor Cyan

    # Return object for scripting use
    [PSCustomObject]$status
}

function Invoke-PSPAPI {
    <#
    .SYNOPSIS
        Performs a low-level authenticated API request to a PowerSyncPro server.

    .DESCRIPTION
        Invoke-PSPAPI is the core HTTP communication function used by all
        higher-level PSP commands. It sends requests using the session cookie
        container, includes the XSRF token if present, and returns data in the
        most useful form for scripting.

        - JSON responses are returned as PowerShell objects
        - Non-JSON responses (HTML, modal page, plain text) are returned as string
        - The -Silent switch suppresses console output for non-JSON payloads

        This allows the same function to retrieve structured API results and
        HTML modal reports that require parsing or scraping.

    .PARAMETER BaseUrl
        The root PowerSyncPro URL, such as https://psp.company.com
        Defaults to $script:PSPDefaultBaseUrl if available.

    .PARAMETER Session
        Authenticated WebRequestSession from Get-PSPSession.
        Defaults to $script:PSPSession.

    .PARAMETER Endpoint
        API path beginning with "/"
        Examples:
            /api/services/app/Agents/GetAll
            /SingleObjectReport/SourceDetailViewModal?id=<GUID>

    .PARAMETER Method
        HTTP verb: GET (default), POST, PUT, DELETE

    .PARAMETER Body
        JSON data for POST or PUT requests.
        Ignored for GET and DELETE.

    .PARAMETER Silent
        When set, Invoke-PSPAPI does not print the body of non-JSON responses.
        This is useful when retrieving HTML for scraping or automation.

    .EXAMPLE
        Invoke-PSPAPI -Endpoint "/api/services/app/Agents/GetAll"

    .EXAMPLE
        $html = Invoke-PSPAPI -Endpoint "/SingleObjectReport/SourceDetailViewModal?id=$id" -Method POST -Silent

    .EXAMPLE
        Invoke-PSPAPI -Endpoint "/api/services/app/Agents/Update" -Method PUT -Body '{"id":1,"enabled":true}'

    .OUTPUTS
        PSCustomObject   if JSON is returned
        String           if HTML or other non-JSON content is returned
        null             on communication failure

    .NOTES
        This function is the primary interface for all raw PSP API access.
        Updates to the PSP backend API should be handled here first.
    #>
    [CmdletBinding()]
    param(
        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession,
        [Parameter(Mandatory)][string]$Endpoint,
        [ValidateSet("GET","POST","PUT","DELETE")][string]$Method = "GET",
        [string]$Body,
        [switch]$Silent
    )

    # Normalize URL
    if ($Endpoint -notmatch '^/') { $Endpoint = "/$Endpoint" }
    $uri = "$BaseUrl$Endpoint"

    # Build headers
    $headers = @{ "Accept" = "application/json, text/plain, */*" }
    if ($Session.PSObject.Properties.Name -contains "XsrfToken") {
        $headers["x-xsrf-token"] = $Session.XsrfToken
    }

    if (-not $Silent) {
        Write-Host "Calling $uri ($Method)..." -ForegroundColor Yellow
    }

    try {
        if ($Method -in @("POST","PUT")) {
            if (-not $Body) { $Body = "{}" }
            $resp = Invoke-WebRequest -Uri $uri `
                -WebSession $Session `
                -Method $Method `
                -Headers $headers `
                -ContentType "application/json" `
                -Body $Body `
                -UseBasicParsing `
                -ErrorAction Stop
        } else {
            $resp = Invoke-WebRequest -Uri $uri `
                -WebSession $Session `
                -Method $Method `
                -Headers $headers `
                -UseBasicParsing `
                -ErrorAction Stop
        }

        # Try JSON → fallback to raw string, but silent if requested
        try {
            return ($resp.Content | ConvertFrom-Json -ErrorAction Stop)
        } catch {
            if (-not $Silent) {
                Write-Host "Non-JSON response body:" -ForegroundColor Yellow
                Write-Host ($resp.Content.Substring(0, [Math]::Min(400, $resp.Content.Length)))
            }
            return $resp.Content
        }
    }
    catch {
        if (-not $Silent) {
            Write-Host "API call failed: $($_.Exception.Message)" -ForegroundColor Red
        }
        return $null
    }
}
# ---------------------------------------------------------------------
# Scheduling & Triggers
# ---------------------------------------------------------------------
function Invoke-PSPRunScheduleNow {
    <#
    .SYNOPSIS
        Immediately triggers the PowerSyncPro scheduler.

    .DESCRIPTION
        Calls /api/services/app/Schedule/RunScheduleNow to start all scheduled jobs immediately.

    .PARAMETER BaseUrl
        Base URL of the PowerSyncPro server.

    .PARAMETER Session
        Authenticated WebRequestSession from Get-PSPSession.

    .EXAMPLE
        Invoke-PSPRunScheduleNow -BaseUrl $baseurl -Session $session
    #>

    [CmdletBinding()]
    param(
        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession
    )

    Write-Verbose "Calling RunScheduleNow..."
    Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Endpoint "/api/services/app/Schedule/RunScheduleNow" -Method POST
}
function Get-PSPJobSummary {
    <#
    .SYNOPSIS
        Retrieves and summarizes job / schedule information from a PowerSyncPro server.

    .DESCRIPTION
        Calls /api/services/app/Schedule/LoadJobInfo and returns a flattened,
        human-readable list of jobs with status, profile, timing, and counts.
        Supports filtering for running, error, or specific profile jobs.

    .PARAMETER BaseUrl
        Base URL of the PSP instance (e.g. https://psp.company.com)

    .PARAMETER Session
        Authenticated web session (from Get-PSPSession)

    .PARAMETER ErrorsOnly
        Filters to only jobs with status "Error"

    .PARAMETER RunningOnly
        Filters to only jobs currently "Running"

    .PARAMETER Profile
        Filters to only a specific Sync Profile name (supports wildcards)

    .EXAMPLE
        Get-PSPJobSummary -BaseUrl "https://psp.company.com" -Session $session

    .EXAMPLE
        Get-PSPJobSummary -BaseUrl $base -Session $session -ErrorsOnly

    .EXAMPLE
        Get-PSPJobSummary -BaseUrl $base -Session $session -Profile "AD to Entra*"
    #>
    [CmdletBinding()]
    param(
        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession,
        [switch]$ErrorsOnly,
        [switch]$RunningOnly,
        [string]$Profile
    )

    Write-Host "Querying PSP scheduler..." -ForegroundColor Cyan
    $resp = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Method POST -Endpoint "/api/services/app/Schedule/LoadJobInfo"

    if (-not $resp.success -or -not $resp.result) {
        Write-Warning "No valid response or authentication expired."
        return
    }

    $flatJobs = @()
    foreach ($dir in $resp.result.directories) {
        foreach ($job in $dir.jobInformation) {
            $flatJobs += [PSCustomObject]@{
                Directory       = $dir.directoryName
                SyncProfile     = $job.syncProfileName
                JobType         = switch ($job.jobType) {
                                     0 { 'Import Containers' }
                                     1 { 'Import Objects' }
                                     2 { 'Sync Objects' }
                                     3 { 'Export Objects' }
                                     default { "Unknown ($($job.jobType))" }
                                 }
                Status          = switch ($job.status) {
                                     2 { 'Running' }
                                     3 { 'Success' }
                                     4 { 'Error' }
                                     default { "Unknown ($($job.status))" }
                                 }
                LastStarted     = $job.lastStarted
                ProcessedCount  = $job.processedCount
                ErrorCount      = $job.errorCount
                JobId           = $job.jobId
            }
        }
    }

    # Apply filters
    if ($ErrorsOnly)   { $flatJobs = $flatJobs | Where-Object { $_.Status -eq 'Error' } }
    if ($RunningOnly)  { $flatJobs = $flatJobs | Where-Object { $_.Status -eq 'Running' } }
    if ($Profile)      { $flatJobs = $flatJobs | Where-Object { $_.SyncProfile -like $Profile } }

    if (-not $flatJobs) {
        Write-Host "No matching jobs found." -ForegroundColor Yellow
        return
    }

    $flatJobs | Sort-Object Directory, JobType | Format-Table -AutoSize
}
# ---------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------
function Get-PSPDirectories {
<#
.SYNOPSIS
    Retrieves directory connectors registered in PowerSyncPro.

.DESCRIPTION
    Calls /api/services/app/Directories/GetAll and returns all directories by default.
    If -DirectoryId is provided, this function filters to that ID and returns only that
    directory object. This allows fast lookup for specific connector IDs.

.PARAMETER BaseUrl
    Base PSP URL, defaults to stored global value.

.PARAMETER Session
    Authenticated session created by Get-PSPSession.

.PARAMETER SkipCount
    Pagination start offset. Default: 0.

.PARAMETER MaxResultCount
    Pagination max items. Default: 100.

.PARAMETER DirectoryId
    Optional filter to return a single directory by numeric ID.

.EXAMPLE
    Get-PSPDirectories
    Returns all directories.

.EXAMPLE
    Get-PSPDirectories -DirectoryId 1
    Returns only the directory with ID 1.

.EXAMPLE
    Get-PSPDirectories -DirectoryId 0
    Useful for zero-index test connectors or placeholder IDs.

#>
    [CmdletBinding()]
    param(
        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession,
        [int]$DirectoryId,
        [int]$SkipCount = 0,
        [int]$MaxResultCount = 100
    )

    Write-Host "Retrieving directories from $BaseUrl..." -ForegroundColor Cyan

    $endpoint = "/api/services/app/Directories/GetAll?sorting=DisplayName%20asc&skipCount=$SkipCount&maxResultCount=$MaxResultCount"
    $result = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Method GET -Endpoint $endpoint

    if (-not $result.success -or -not $result.result.items) {
        Write-Warning "No directories returned or request failed."
        return @()
    }

    # Filter if DirectoryId provided
    if ($PSBoundParameters.ContainsKey("DirectoryId")) {
        return $result.result.items |
            Where-Object { $_.id -eq $DirectoryId } |
            Select-Object id, displayName, name, directoryTypeName, directoryType, username, serverName, hasSyncProfiles, hasPasswordAgent
    }

    # Otherwise return full set
    return $result.result.items |
        Select-Object id, displayName, name, directoryTypeName, directoryType, username, serverName, hasSyncProfiles, hasPasswordAgent
}
function Get-PSPDirectoryIdByDisplayName {
    <#
    .SYNOPSIS
        Retrieves a directory’s numeric ID by its display name.

    .DESCRIPTION
        Queries all registered directories via Get-PSPDirectories and returns the ID
        for the first match whose DisplayName matches (case-insensitive).

    .PARAMETER BaseUrl
        PowerSyncPro server root URL.

    .PARAMETER Session
        Authenticated WebRequestSession from Get-PSPSession.

    .PARAMETER DisplayName
        Display name of the directory (as shown in the PowerSyncPro portal).

    .EXAMPLE
        Get-PSPDirectoryIdByDisplayName -BaseUrl $baseurl -Session $session -DisplayName "Company AD"
    #>

    [CmdletBinding()]
    param(
        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession,
        [Parameter(Mandatory)][string]$DisplayName
    )

    $dirs = Get-PSPDirectories -BaseUrl $BaseUrl -Session $Session
    if (-not $dirs) { throw "No directories returned from server." }

    $dir = $dirs | Where-Object { $_.displayName -ieq $DisplayName } | Select-Object -First 1
    if (-not $dir) { throw "Directory with displayName '$DisplayName' not found." }

    return $dir.id
}
function Get-PSPDirectoryComputers {
    <#
    .SYNOPSIS
        Retrieves all computer objects from a directory in PowerSyncPro.
    .DESCRIPTION
        Wraps /api/services/app/BatchItems/GetComputerSearchResults which
        returns computer objects for the given directoryId.
    .PARAMETER BaseUrl
        The base URL of the PSP server.
    .PARAMETER Session
        The authenticated WebRequestSession.
    .PARAMETER DirectoryId
        The directory ID to query.
    .EXAMPLE
        Get-PSPDirectoryComputers -DirectoryId 1
    #>
    [CmdletBinding()]
    param(
        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession,
        [Parameter(Mandatory)][int]$DirectoryId
    )

    Write-Host "Retrieving computers for directory ID $DirectoryId..." -ForegroundColor Cyan

    # New API endpoint
    $endpoint = "/api/services/app/BatchItems/GetComputerSearchResults?directoryId=$DirectoryId"

    # Perform API call
    $result = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Method GET -Endpoint $endpoint

    if ($result.success -and $result.result.items) {
        $count = $result.result.items.Count
        Write-Host "Retrieved $count computers from directory $DirectoryId." -ForegroundColor Green

        return $result.result.items |
            Select-Object `
                name,
                displayName,
                serialNumber,
                objectUid,
                objectSid,
                agentVersion,
                agentLastContact,
                index
    }
    else {
        Write-Warning "No computers returned or request failed."
        if ($result.error) {
            Write-Warning "Error: $($result.error.message)"
        }
        return @()
    }
}
function Find-PSPComputer {
    <#
    .SYNOPSIS
        Searches one or all directories in PowerSyncPro for a computer by hostname.
    .DESCRIPTION
        If -DirectoryId is supplied, only that directory is searched.
        Otherwise, all directories are enumerated.
        Each directory is queried via /ImportObjects/GetAllForDirectory with objectType=4 (computers).
    .PARAMETER BaseUrl
        PowerSyncPro server root (e.g. https://psp.company.com)
    .PARAMETER Session
        The active WebRequestSession from Get-PSPSession
    .PARAMETER ComputerName
        The hostname (or partial name) to search for
    .PARAMETER DirectoryId
        Optional. If specified, restricts the search to this directory ID
    .PARAMETER Exact
        If set, only returns exact matches (case-insensitive)
    .EXAMPLE
        Find-PSPComputer -BaseUrl $baseurl -Session $session -ComputerName "WRKSTN-001"
    .EXAMPLE
        Find-PSPComputer -BaseUrl $baseurl -Session $session -ComputerName "WRKSTN-001" -DirectoryId 4
    #>
    [CmdletBinding()]
    param(
        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession,
        [Parameter(Mandatory)][string]$ComputerName,
        [int]$DirectoryId,
        [switch]$Exact
    )

    if ($PSBoundParameters.ContainsKey('DirectoryId')) {
        Write-Host "Searching directory ID $DirectoryId for computer '$ComputerName'..." -ForegroundColor Cyan
        $directories = @(@{ id = $DirectoryId; displayName = "Directory $DirectoryId" })
    }
    else {
        Write-Host "Searching all directories for computer '$ComputerName'..." -ForegroundColor Cyan
        $directories = Get-PSPDirectories -BaseUrl $BaseUrl -Session $Session
        if (-not $directories -or $directories.Count -eq 0) {
            Write-Warning "No directories found."
            return
        }
    }

    $found = @()

    foreach ($dir in $directories) {
        Write-Host "Checking directory: $($dir.displayName) [$($dir.id)]..." -ForegroundColor DarkGray

        $computers = Get-PSPDirectoryComputers -BaseUrl $BaseUrl -Session $Session -DirectoryId $dir.id
        if (-not $computers) { continue }

        if ($Exact) {
            $matches = $computers | Where-Object { $_.name -ieq $ComputerName }
        }
        else {
            $matches = $computers | Where-Object { $_.name -imatch [regex]::Escape($ComputerName) }
        }

        foreach ($m in $matches) {
            $found += [pscustomobject]@{
                DirectoryName   = $dir.displayName
                DirectoryId     = $dir.id
                ComputerName    = $m.name
                ObjectUid       = $m.objectUid
                ImportObjectSid = $m.importObjectSid
                ObjectType      = $m.objectType
            }
        }
    }

    if ($found.Count -gt 0) {
        Write-Host "Found $($found.Count) match(es)." -ForegroundColor Green
        return $found
    }
    else {
        Write-Warning "No computers found matching '$ComputerName'."
        return @()
    }
}
# ---------------------------------------------------------------------
# Migration Agent
# ---------------------------------------------------------------------
function Get-PSPTranslationTable {
    <#
    .SYNOPSIS
        Retrieves translation mappings between source and target directories.

    .DESCRIPTION
        Calls /api/services/app/CheckTranslationEntries/GetReport for a given DirectoryId.
        Supports pagination and optional full retrieval (-All).  Returns flattened PowerShell
        objects with key source and target fields.

    .PARAMETER BaseUrl
        PowerSyncPro server root (e.g. https://psp.company.com)

    .PARAMETER Session
        The authenticated WebRequestSession (from Get-PSPSession)

    .PARAMETER DirectoryId
        Numeric ID of the directory to query.

    .PARAMETER MaxCount
        Maximum number of entries to retrieve (default 1000). Ignored when -All is used.

    .PARAMETER PageSize
        Number of entries per request (default 100).

    .PARAMETER ExportPath
        Optional CSV export file path.

    .PARAMETER All
        Retrieve *all* available pages instead of limiting to MaxCount.

    .EXAMPLE
        Get-PSPTranslationTable -DirectoryId 5

    .EXAMPLE
        Get-PSPTranslationTable -DirectoryId 5 -All -ExportPath "C:\Temp\TranslationReport.csv"
    #>
    [CmdletBinding()]
    param(
        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession,
        [Parameter(Mandatory)][int]$DirectoryId,
        [int]$MaxCount = 1000,
        [int]$PageSize = 100,
        [string]$ExportPath,
        [switch]$All
    )

    Write-Host "Retrieving translation table for directory ID $DirectoryId..." -ForegroundColor Cyan

    $skip = 0
    $allItems = @()
    $page = 0

    do {
        $endpoint = "/api/services/app/CheckTranslationEntries/GetReport" +
                    "?directoryId=$DirectoryId&skipCount=$skip&maxResultCount=$PageSize"
        Write-Host "Calling $endpoint ..." -ForegroundColor DarkGray

        try {
            $resp = Invoke-PSPAPI -BaseUrl $BaseUrl -Session $Session -Endpoint $endpoint -Method GET
        }
        catch {
            Write-Warning ("Request failed at skip={0}: {1}" -f $skip, $_.Exception.Message)
            break
        }

        if (-not $resp.success -or -not $resp.result -or -not $resp.result.items) {
            Write-Warning "No more results or invalid response from server."
            break
        }

        $items = $resp.result.items
        $allItems += $items
        $page++
        Write-Host ("Retrieved {0} entries (total so far: {1})" -f $items.Count, $allItems.Count) -ForegroundColor Gray

        $skip += $PageSize

        # Continue if -All was specified and we got a full page of results
        $continue = $All -and ($items.Count -eq $PageSize)

        # Stop if we’ve reached MaxCount (unless -All)
        if (-not $All -and $allItems.Count -ge $MaxCount) {
            Write-Host "Reached MaxCount limit ($MaxCount)." -ForegroundColor Yellow
            break
        }
    }
    while ($continue)

    if ($allItems.Count -eq 0) {
        Write-Warning "No translation entries returned for directory ID $DirectoryId."
        return @()
    }

    $table = $allItems | ForEach-Object {
        [pscustomobject]@{
            SourceName       = $_.sourceObjectName
            SourceUPN        = $_.sourceUserPrincipalName
            SourceSID        = $_.sourceSecurityId
            SourceContainer  = $_.sourceObjectContainer
            TargetName       = $_.targetObjectName
            TargetUPN        = $_.targetUserPrincipalName
            TargetSID        = $_.targetSecurityId
            TargetContainer  = $_.targetObjectContainer
        }
    }

    Write-Host "Retrieved $($table.Count) total translation records." -ForegroundColor Green

    if ($ExportPath) {
        try {
            $table | Export-Csv -Path $ExportPath -NoTypeInformation -Force
            Write-Host "Exported translation table to $ExportPath" -ForegroundColor Yellow
        }
        catch {
            Write-Warning "CSV export failed: $($_.Exception.Message)"
        }
    }

    return $table
}
function Get-PSPPreSharedKeys {
    [CmdletBinding()]
    param(
        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession,
        [int]$SkipCount = 0,
        [int]$MaxResultCount = 100,
        [switch]$IncludeMigrationAgents,
        [switch]$ActiveKey,
        [switch]$Raw
    )

    $endpoint = "/api/services/app/PreSharedKeys/GetAll?skipCount=$SkipCount&maxResultCount=$MaxResultCount"
    if ($IncludeMigrationAgents) {
        $endpoint += "&getMigrationAgents=true"
    }

    try {
        Write-Host "Retrieving Pre-Shared Keys from $BaseUrl..." -ForegroundColor Cyan
        $response = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Method "GET" -Endpoint $endpoint

        if (-not $response) {
            throw "No response from API."
        }
        if (-not $response.success) {
            $msg = if ($response.error) { $response.error.message } else { "Unknown API error." }
            throw "API reported failure: $msg"
        }

        $items = $response.result.items
        if (-not $items -or $items.Count -eq 0) {
            Write-Warning "No Pre-Shared Keys found."
            return @()
        }

        if ($ActiveKey) {
            $items = $items | Where-Object { $_.isHistoric -eq $false }
            if (-not $items -or $items.Count -eq 0) {
                Write-Warning "No active (non-historic) keys found."
                return @()
            }
            Write-Host ("Filtered to {0} active Pre-Shared Key(s)." -f $items.Count) -ForegroundColor Yellow
        }
        else {
            Write-Host ("Found {0} total Pre-Shared Key(s)." -f $items.Count) -ForegroundColor Green
        }

        if ($Raw) { 
            return $response 
        } else {
            return $items | Select-Object `
                id,
                psk,
                isHistoric,
                agentType,
                generatedTime,
                machineName,
                domainName
        }
    }
    catch {
        Write-Error "Error retrieving Pre-Shared Keys: $($_.Exception.Message)"
        throw
    }
}
# ---------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------
function Get-PSPMigrationAgents {
    <#
    .SYNOPSIS
        Retrieves all registered migration agents from PowerSyncPro.

    .DESCRIPTION
        Calls /api/services/app/Agents/GetAll?getMigrationAgents=true to enumerate migration
        agent records and returns their properties such as ID, objectName, directory affiliation,
        version, operating system, and last contact time.
        Supports optional filtering by DirectoryId, Version, or MachineName.
        Use -Raw to view the complete JSON payload returned by the API.

    .PARAMETER BaseUrl
        Root URL of the PowerSyncPro server (e.g. https://psp.company.com)

    .PARAMETER Session
        Authenticated WebRequestSession object from Get-PSPSession.

    .PARAMETER SkipCount
        Number of records to skip from the beginning of the result set (default 0).

    .PARAMETER MaxResultCount
        Maximum number of records to return (default 100).

    .PARAMETER Version
        Optional version string to filter agents (for example "1.3.0.0").

    .PARAMETER MachineName
        Optional partial or exact machine name to filter results.

    .PARAMETER DirectoryId
        Numeric Directory ID (previously called -Domain) to limit results to a specific directory.

    .PARAMETER Raw
        Returns the raw API response instead of flattened PowerShell objects.

    .EXAMPLE
        Get-PSPMigrationAgents -BaseUrl $baseurl -Session $session
        # Lists all migration agents registered on the server.

    .EXAMPLE
        Get-PSPMigrationAgents -BaseUrl $baseurl -Session $session -DirectoryId 4
        # Retrieves all agents associated with Directory ID 4.

    .EXAMPLE
        Get-PSPMigrationAgents -BaseUrl $baseurl -Session $session -MachineName "PSP-JAMIE"
        # Filters results to agents whose machine name includes "PSP-JAMIE".

    .EXAMPLE
        Get-PSPMigrationAgents -BaseUrl $baseurl -Session $session -Version "1.3.0.0" -Raw
        # Displays the unprocessed JSON structure of agents running a specific version.

    .EXAMPLE
        ($agents = Get-PSPMigrationAgents -BaseUrl $baseurl -Session $session) |
            Sort-Object lastContact | Format-Table objectName, directoryDisplayName, version, lastContact
        # Sorts agents by their last contact time for quick status review.
    #>

    [CmdletBinding()]
    param(
        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession,
        [int]$SkipCount = 0,
        [int]$MaxResultCount = 100,
        [string]$Version,
        [string]$MachineName,

        # Actual variable is $DirId, but user-facing parameter is -DirectoryId
        [Alias("Domain","DirectoryId")]
        [string]$DirId,

        [switch]$Raw
    )

    # --- Construct Endpoint ---
    $endpoint = "/api/services/app/Agents/GetAll?getMigrationAgents=true&sorting=MachineName%20asc&skipCount=$SkipCount&maxResultCount=$MaxResultCount"

    if ($Version)     { $endpoint += "&version=$([uri]::EscapeDataString($Version))" }
    if ($MachineName) { $endpoint += "&machineName=$([uri]::EscapeDataString($MachineName))" }
    if ($DirId) { $endpoint += "&domain=$([uri]::EscapeDataString($DirId))" }

    try {
        Write-Host "Retrieving Migration Agents from $BaseUrl..." -ForegroundColor Cyan
        $response = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Method "GET" -Endpoint $endpoint

        if (-not $response) { throw "No response from API." }
        if (-not $response.success) {
            $msg = if ($response.error) { $response.error.message } else { "Unknown API error." }
            throw "API reported failure: $msg"
        }

        $items = $response.result.items
        if (-not $items -or $items.Count -eq 0) {
            Write-Warning "No migration agents found."
            return @()
        }

        Write-Host ("Found {0} Migration Agent(s)." -f $items.Count) -ForegroundColor Green

        if ($Raw) {
            return $response
        } else {
            return $items | Select-Object `
                id,
                agentType,
                objectName,
                directoryDisplayName,
                directoryName,
                version,
                osVersion,
                lastContact,
                registrationComplete,
                isApproved
        }
    }
    catch {
        Write-Error "Error retrieving Migration Agents: $($_.Exception.Message)"
        throw
    }
}
function Remove-PSPMigrationAgent {
    <#
    .SYNOPSIS
        Removes a PowerSyncPro Migration Agent by ID or by name.

    .DESCRIPTION
        Wraps /api/services/app/Agents/Delete to delete an agent.
        Supports search-by-name using fuzzy or exact match within a specified DirectoryId.
        Includes -WhatIf and -Confirm integration, and can bypass confirmation with -Force.

    .PARAMETER BaseUrl
        Root URL of the PowerSyncPro server.

    .PARAMETER Session
        Authenticated WebRequestSession from Get-PSPSession.

    .PARAMETER AgentId
        Unique GUID of the migration agent to remove (direct mode).

    .PARAMETER AgentName
        Name (usually FQDN) of the agent to remove (search mode).

    .PARAMETER DirectoryId
        Directory ID scope used when searching for the agent.

    .PARAMETER Exact
        Performs a case-insensitive exact match on the AgentName.

    .PARAMETER Force
        Skips the confirmation prompt.

    .EXAMPLE
        Remove-PSPMigrationAgent -BaseUrl $baseurl -Session $session -AgentId "975bbe91-2c59-4432-b664-08ddf5f1384e" -Force

    .EXAMPLE
        Remove-PSPMigrationAgent -BaseUrl $baseurl -Session $session -AgentName "DEMO-PC01" -DirectoryId 4 -Exact
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'ById')]
    param(
        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession,

        [Parameter(ParameterSetName = 'ById')][string]$AgentId,
        [Parameter(ParameterSetName = 'BySearch')][string]$AgentName,
        [Parameter(ParameterSetName = 'BySearch')][int]$DirectoryId,
        [Parameter(ParameterSetName = 'BySearch')][switch]$Exact,

        [switch]$Force
    )

    try {
        if ($PSCmdlet.ParameterSetName -eq 'BySearch') {
            if (-not $AgentName -or -not $DirectoryId) {
                throw "Both -AgentName and -DirectoryId must be provided when using name-based removal."
            }

            Write-Host "Searching for migration agent '$AgentName' in directory ID $DirectoryId..." -ForegroundColor Cyan

            # Limit API call to only agents in the specified directory
            $agents = Get-PSPMigrationAgents -BaseUrl $BaseUrl -Session $Session -DirectoryId $DirectoryId

            if (-not $agents -or $agents.Count -eq 0) {
                Write-Warning "No migration agents found in directory ID $DirectoryId."
                return
            }

            # Matching logic (exact vs fuzzy)
            if ($Exact) {
                $matches = $agents | Where-Object { $_.objectName -ieq $AgentName }
            } else {
                $matches = $agents | Where-Object { $_.objectName -like "*$AgentName*" }
            }

            if (-not $matches) {
                Write-Warning "No migration agent found matching '$AgentName' in directory ID $DirectoryId."
                return
            }

            if ($matches.Count -gt 1) {
                Write-Warning "Multiple agents matched name '$AgentName' in directory ID $DirectoryId."
                $matches | Select-Object id, objectName, version, lastContact
                return
            }

            $AgentId = $matches.id
            Write-Host "Resolved agent '$AgentName' to ID [$AgentId]" -ForegroundColor Green
        }

        if (-not $AgentId) {
            throw "No AgentId resolved for removal."
        }

        if (-not $Force -and -not $PSCmdlet.ShouldProcess("Agent ID: $AgentId", "Remove Migration Agent")) {
            Write-Host "Operation cancelled by user." -ForegroundColor Yellow
            return
        }

        $endpoint = "/api/services/app/Agents/Delete?id=$AgentId"
        Write-Host "Calling DELETE $endpoint..." -ForegroundColor DarkGray

        $response = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Method "DELETE" -Endpoint $endpoint

        if (-not $response) { throw "No response from API." }
        if (-not $response.success) {
            $msg = if ($response.error) { $response.error.message } else { "Unknown API error." }
            throw "API reported failure: $msg"
        }

        Write-Host "Migration agent [$AgentId] removed successfully." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Error removing migration agent: $($_.Exception.Message)"
        throw
    }
}
function Get-PSPMigrationProgressDetail {
    <#
    .SYNOPSIS
        Retrieves detailed migration progress records for all or specific agents/batches/runbooks.

    .DESCRIPTION
        Calls /api/services/app/MigrationProgress/GetAllMigrationProgressDetail to obtain per-agent,
        per-phase migration progress. Supports filtering by Batch ID, Runbook ID, Phase, or Status.
        When -All is specified, automatically retrieves all pages of results.

    .PARAMETER BaseUrl
        Root URL of the PowerSyncPro server (e.g. https://psp1.rocklightnetworks.com)

    .PARAMETER Session
        Authenticated WebRequestSession from Get-PSPSession.

    .PARAMETER BatchId
        (Optional) Filters results to a specific Batch ID.

    .PARAMETER RunbookId
        (Optional) Filters results to a specific Runbook ID.

    .PARAMETER Phase
        (Optional) Filters to a specific migration phase (e.g. "Apps", "Permissions", "Completion").

    .PARAMETER Status
        (Optional) Filters by migration status (e.g. "Completed", "InProgress", "Error").

    .PARAMETER SkipCount
        (Optional) Number of records to skip (default 0).

    .PARAMETER MaxResultCount
        (Optional) Maximum number of records to return per request (default 100).

    .PARAMETER All
        If specified, retrieves *all* pages of results.

    .PARAMETER Raw
        If specified, returns the full raw API response rather than simplified objects.
    #>
    [CmdletBinding()]
    param(
        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession,
        [string]$BatchId,
        [string]$RunbookId,
        [string]$Phase,
        [string]$Status,
        [int]$SkipCount = 0,
        [int]$MaxResultCount = 100,
        [switch]$All,
        [switch]$Raw
    )

    Write-Host "Retrieving migration progress details..." -ForegroundColor Cyan

    $allItems = @()
    $page = 0

    do {
        # Build endpoint each iteration with current skip
        $endpoint = "/api/services/app/MigrationProgress/GetAllMigrationProgressDetail?skipCount=$SkipCount&maxResultCount=$MaxResultCount"
        if ($BatchId)  { $endpoint += "&batchId=$([uri]::EscapeDataString($BatchId))" }
        if ($RunbookId){ $endpoint += "&runbookId=$([uri]::EscapeDataString($RunbookId))" }
        if ($Phase)    { $endpoint += "&phase=$([uri]::EscapeDataString($Phase))" }
        if ($Status)   { $endpoint += "&status=$([uri]::EscapeDataString($Status))" }

        try {
            $response = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Method "GET" -Endpoint $endpoint
        }
        catch {
            Write-Error ("API request failed on page {0}: {1}" -f $page, $_.Exception.Message)
            break
        }

        if (-not $response -or -not $response.success) {
            Write-Warning "Request failed or returned no data on page $page."
            break
        }

        $items = $response.result.items
        if (-not $items -or $items.Count -eq 0) {
            break
        }

        $allItems += $items
        $page++

        Write-Host ("Retrieved {0} records (total so far: {1})..." -f $items.Count, $allItems.Count) -ForegroundColor DarkGray

        # Increment skip for next page
        $SkipCount += $items.Count

        # Rate limit safety
        Start-Sleep -Milliseconds 200

    } while ($All -and $items.Count -eq $MaxResultCount)

    if ($allItems.Count -eq 0) {
        Write-Warning "No migration progress details found."
        return @()
    }

    Write-Host ("Total records retrieved: {0}" -f $allItems.Count) -ForegroundColor Green

    if ($Raw) {
        return $response
    }
    else {
        return $allItems | Select-Object `
            agentId,
            runbookId,
            computerName,
            runbookName,
            phase,
            status,
            lastUpdate,
            lastError
    }
}
function Get-PSPDirectoryMigrationSummary {
    <#
    .SYNOPSIS
        Retrieves migration progress summaries for all agents in a given directory.

    .DESCRIPTION
        - Looks up the Directory ID by display name.
        - Gets all migration agents in that directory.
        - Fetches *all* migration progress detail records (paginated internally).
        - Filters progress records for those agents.
        - Reports the latest known status per agent.
        - Includes agents that have *no* progress entries at all with
          "No Status Updates" noted.

    .PARAMETER DisplayName
        The directory display name (e.g. "Rocklight Lab").

    .PARAMETER BaseUrl
        PowerSyncPro API base URL.

    .PARAMETER Session
        Authenticated WebRequestSession (from Get-PSPSession).

    .EXAMPLE
        Get-PSPDirectoryMigrationSummary -DisplayName "Rocklight Lab"
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [string]$BaseUrl   = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession
    )

    Write-Host "Fetching Directory ID for '$DisplayName'..." -ForegroundColor Cyan
    $dirID = Get-PSPDirectoryIdByDisplayName -DisplayName $DisplayName -BaseUrl $BaseUrl -Session $Session
    if (-not $dirID) {
        Write-Warning "No directory found with display name '$DisplayName'."
        return
    }

    Write-Host "Fetching agents for Directory ID $dirID..." -ForegroundColor Cyan
    $agents = Get-PSPMigrationAgents -DirectoryID $dirID -BaseUrl $BaseUrl -Session $Session
    if (-not $agents -or $agents.Count -eq 0) {
        Write-Warning "No migration agents found in directory '$DisplayName'."
        return
    }

    Write-Host "Retrieving all migration progress details..." -ForegroundColor Cyan
    $migrationStatus = Get-PSPMigrationProgressDetail -BaseUrl $BaseUrl -Session $Session -All
    if (-not $migrationStatus) {
        Write-Warning "No migration progress records found."
        $migrationStatus = @()   # still continue to mark agents as "No Status Updates"
    }

    Write-Host "Filtering migration progress to agents in directory '$DisplayName'..." -ForegroundColor Gray
    $agentIds = $agents.id
    $filtered = if ($migrationStatus.Count -gt 0) {
        $migrationStatus | Where-Object { $agentIds -contains $_.agentId }
    } else { @() }

    # --- Build results for every agent ---
    $results = foreach ($agent in $agents) {
        $records = $filtered | Where-Object { $_.agentId -eq $agent.id }

        if ($records.Count -gt 0) {
            # Sort newest first
            $entries     = $records | Sort-Object lastUpdate -Descending
            $latestEntry = $entries | Select-Object -First 1
            $phaseEntry  = $entries | Where-Object { $_.phase -and $_.phase.Trim() } | Select-Object -First 1

            [PSCustomObject]@{
                ComputerName = $agent.objectName
                RunbookName  = $latestEntry.runbookName
                Phase        = if ($latestEntry.phase) { $latestEntry.phase }
                               elseif ($phaseEntry)    { $phaseEntry.phase }
                               else                    { "(none)" }
                Status       = $latestEntry.status
                LastUpdate   = $latestEntry.lastUpdate
            }
        }
        else {
            # Agent has never reported migration progress
            [PSCustomObject]@{
                ComputerName = $agent.objectName
                RunbookName  = "(none)"
                Phase        = "(none)"
                Status       = "No Status Updates"
                LastUpdate   = "(none)"
            }
        }
    }

    Write-Host "Compiled $($results.Count) agent migration summaries." -ForegroundColor Green
    return $results | Sort-Object ComputerName
}

# ---------------------------------------------------------------------
# Batches
# ---------------------------------------------------------------------
function Get-PSPBatches {
    <#
    .SYNOPSIS
        Retrieves all migration batches, or a specific batch by name.
    .DESCRIPTION
        Calls /api/services/app/Batches/GetAll to fetch available batches.
        If -Name is provided, filters results for the matching batch (case-insensitive).
    .PARAMETER BaseUrl
        The PowerSyncPro server root (e.g. https://psp.company.com)
    .PARAMETER Session
        Authenticated WebRequestSession (from Get-PSPSession)
    .PARAMETER Name
        (Optional) The name of a batch to return instead of the full list.
    .EXAMPLE
        Get-PSPBatches -BaseUrl $baseurl -Session $session
        Get-PSPBatches -BaseUrl $baseurl -Session $session -Name "AD to Entra - Batch 1"
    #>
    [CmdletBinding()]
    param(
        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession,
        [string]$Name
    )

    Write-Host "Retrieving batch list..." -ForegroundColor Cyan
    $endpoint = "/api/services/app/Batches/GetAll"
    $result = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Method GET -Endpoint $endpoint

    if (-not $result.success) {
        Write-Warning "Failed to retrieve batch list."
        if ($result.error) { Write-Warning "Error: $($result.error.message)" }
        return
    }

    $batches = $result.result.items

    if (-not $batches -or $batches.Count -eq 0) {
        Write-Warning "No batches found."
        return
    }

    if ($Name) {
        Write-Host "Filtering batches for name match: '$Name'..." -ForegroundColor DarkGray
        $MatchedBatches = $batches | Where-Object { $_.name -ieq $Name }

        # Always force into an array for consistent .Count
        $MatchedBatches = @($MatchedBatches)

        if ($MatchedBatches.Count -eq 0) {
            Write-Warning "No batch found with name '$Name'."
            return
        }

        # Proper pluralization
        $count = $MatchedBatches.Count
        $plural = if ($count -eq 1) { '' } else { 'es' }
        Write-Host "Found $count matching batch$plural." -ForegroundColor Green

        return $MatchedBatches
    }

    Write-Host "Retrieved $($batches.Count) total batches." -ForegroundColor Green
    return $batches
}
function Get-PSPBatchRunbooks {
<#
.SYNOPSIS
    Retrieves runbooks associated with a specific PowerSyncPro batch.

.DESCRIPTION
    Calls the API endpoint:
        /api/services/app/BatchRunbooks/GetBatchRunbooks
    and returns the list of runbooks currently assigned to the batch.
    These runbooks must be preserved and passed unchanged when updating
    the batch to avoid losing scheduling information.

.PARAMETER BaseUrl
    PowerSyncPro server root URL.

.PARAMETER Session
    Authenticated WebRequestSession object.

.PARAMETER BatchId
    The batch ID to query.

.EXAMPLE
    Get-PSPBatchRunbooks -BatchId "d37c2f2e-a732-..." | Format-Table
#>
    [CmdletBinding()]
    param(
        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession,
        [Parameter(Mandatory)][string]$BatchId
    )

    $endpoint = "/api/services/app/BatchRunbooks/GetBatchRunbooks?batchId=$BatchId"
    $resp = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Endpoint $endpoint -Method GET

    if (-not $resp.success) {
        Write-Warning "Failed to retrieve batch runbooks for BatchId $BatchId"
        return @()
    }

    return $resp.result.items
}
function Build-PSPBatchUpdateBundle {
<#
.SYNOPSIS
    Internal helper to build and submit a Batches/Update payload.

.DESCRIPTION
    Retrieves batch metadata, runbooks, and the current exempted computers list
    for the given BatchId. It then invokes a caller-supplied script block to
    mutate the computer list (and optionally flags), enforces GUI-compatible
    semantics for allComputers/noComputer, and finally submits a PUT request
    to /api/services/app/Batches/Update with a JSON payload that matches what
    the web UI sends.

.PARAMETER BatchId
    The ID of the batch to update.

.PARAMETER MutateScript
    Scriptblock that receives:
        param([ref]$computers, [ref]$noComputer, [ref]$allComputers)

    and can modify the computers collection and/or flags in-place.

.PARAMETER BaseUrl
    Root URL of the PowerSyncPro server (for example https://psp.company.com).

.PARAMETER Session
    Authenticated WebRequestSession returned by Get-PSPSession.

.RETURNS
    The AjaxResponse from the Batches/Update call, as returned by Invoke-PSPApi.

.NOTES
    This is intended as a shared internal helper used by Add-PSPBatchComputer
    and Remove-PSPBatchComputer so that runbook handling and JSON shaping
    stay consistent with the web UI.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$BatchId,

        [Parameter(Mandatory=$true)]
        [scriptblock]$MutateScript,

        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession
    )

    #
    # Retrieve batch metadata
    #
    $batchList = Get-PSPBatches -BaseUrl $BaseUrl -Session $Session
    $batch = $batchList | Where-Object id -eq $BatchId
    if (-not $batch) {
        throw "Batch not found: $BatchId"
    }

    $SourceId = $batch.sourceDirectoryId
    $TargetId = $batch.targetDirectoryId

    #
    # Retrieve runbooks for this batch
    #
    $runResp = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Method GET `
        -Endpoint "/api/services/app/BatchRunbooks/GetBatchRunbooks?batchId=$BatchId"

    $runbooks = @()
    if ($runResp.success -and $runResp.result.items) {
        $runbooks = $runResp.result.items
    }

    #
    # Retrieve exemptedComputers for this batch
    #
    $compResp = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Method GET `
        -Endpoint "/api/services/app/BatchItems/GetAllExemptedComputerItems?batchId=$BatchId"

    $computers = @()
    if ($compResp.success -and $compResp.result.items) {
        $computers = $compResp.result.items
    }

    #
    # Initial flags (we normalize after mutation)
    #
    $noComputer = $true
    $allComputers = $false

    #
    # Let the caller mutate the list and flags
    #
    & $MutateScript ([ref]$computers) ([ref]$noComputer) ([ref]$allComputers)

    #
    # Enforce GUI-compatible semantics:
    # For now we always use "explicit inclusion list" mode:
    #   allComputers = $false
    #   noComputer   = $true
    #
    $allComputers = $false
    $noComputer = $true

    #
    # Prepare runbook payload in the shape the API expects
    #
    $runbookPayload = @()
    foreach ($rb in $runbooks) {
        $runbookPayload += @{
            runbookId         = $rb.runbookId
            availableFromTime = $rb.availableFromTime
            startTime         = $rb.startTime
            timezone          = $rb.timezone
        }
    }

    #
    # Build final payload matching the web UI
    #
    $payload = @{
        id                = "$BatchId"
        name              = "$($batch.name)"
        sourceId          = "$SourceId"
        targetId          = "$TargetId"
        allComputers      = $allComputers
        noComputer        = $noComputer
        runbooks          = $runbookPayload
        exemptedComputers = $computers
    } | ConvertTo-Json -Depth 12

    #
    # Submit update
    #
    $resp = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session `
        -Method PUT -Endpoint "/api/services/app/Batches/Update" -Body $payload

    return $resp
}
function Get-PSPBatchComputers {
    <#
    .SYNOPSIS
        Lists computer objects belonging to a specific migration batch.

    .DESCRIPTION
        Calls /api/services/app/BatchItems/GetAllExemptedComputerItems for the given BatchId.
        Supports resolving BatchId automatically by specifying -BatchName.

    .PARAMETER BaseUrl
        PowerSyncPro server root.

    .PARAMETER Session
        Authenticated WebRequestSession.

    .PARAMETER BatchId
        Unique batch ID. Optional if -BatchName is supplied.

    .PARAMETER BatchName
        Name of the batch to resolve to a BatchId.

    .PARAMETER Included
        Only return computers marked as included in the batch.

    .EXAMPLE
        Get-PSPBatchComputers -BatchId "e34e..." -Included

    .EXAMPLE
        Get-PSPBatchComputers -BatchName "HR Migration" -Included
    #>

    [CmdletBinding(DefaultParameterSetName="ById")]
    param(
        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession,

        [Parameter(ParameterSetName="ById")]
        [string]$BatchId,

        [Parameter(ParameterSetName="ByName")]
        [string]$BatchName,

        [switch]$Included
    )

    #
    # Resolve BatchId if needed
    #
    if ($PSCmdlet.ParameterSetName -eq "ByName") {

        if (-not $BatchName) {
            Write-Error "You must supply -BatchName or -BatchId."
            return
        }

        Write-Host "Resolving BatchName '$BatchName'..." -ForegroundColor Cyan
        $matched = Get-PSPBatches -BaseUrl $BaseUrl -Session $Session -Name $BatchName

        if (-not $matched) {
            Write-Warning "Batch '$BatchName' not found."
            return
        }

        if ($matched.Count -gt 1) {
            Write-Warning "Batch name '$BatchName' matched multiple entries:"
            $matched | Format-Table name, id
            return
        }

        $BatchId = $matched[0].id
        Write-Host "Resolved '$BatchName' → BatchId = $BatchId" -ForegroundColor Green
    }

    #
    # Validate BatchId
    #
    if (-not $BatchId) {
        Write-Error "BatchId is required. Use -BatchId or -BatchName."
        return
    }

    #
    # Query batch computers
    #
    $flag = if ($Included) { "true" } else { "false" }
    Write-Host "Retrieving computers for batch $BatchId (includedInBatch=$flag)..." -ForegroundColor Cyan

    $endpoint = "/api/services/app/BatchItems/GetAllExemptedComputerItems?batchId=$BatchId&includedInBatch=$flag"
    $resp = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Method GET -Endpoint $endpoint

    if ($resp.success -ne $true) {
        Write-Warning "Computer query failed."
        return $null
    }

    return $resp.result.items
}
function Get-PSPTargetSID {
    <#
    .SYNOPSIS
        Retrieves the target Security Identifier (SID) for a given source UPN.
    .DESCRIPTION
        Uses /CheckTranslationEntries/GetReport via Get-PSPTranslationTable to find
        the corresponding TargetSID for a specific SourceUPN in the given target directory.
    .PARAMETER BaseUrl
        PowerSyncPro server root (e.g. https://psp.company.com)
    .PARAMETER Session
        The authenticated WebRequestSession (from Get-PSPSession)
    .PARAMETER TargetDirectoryId
        Numeric target directory ID to query (e.g. 5)
    .PARAMETER SourceUPN
        The source user principal name to search for
    .EXAMPLE
        Get-PSPTargetSID -BaseUrl $baseurl -Session $session -TargetDirectoryId 5 -SourceUPN "miles.morales@lab.rocklightnetworks.com"
    #>
    [CmdletBinding()]
    param(
        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession,
        [Parameter(Mandatory)][int]$TargetDirectoryId,
        [Parameter(Mandatory)][string]$SourceUPN
    )

    Write-Host "Looking up target SID for source UPN '$SourceUPN' in target directory ID $TargetDirectoryId..." -ForegroundColor Cyan

    try {
        $translationTable = Get-PSPTranslationTable -BaseUrl $BaseUrl -Session $Session -DirectoryId $TargetDirectoryId -MaxCount 1000 -PageSize 100
    }
    catch {
        Write-Warning ("Failed to retrieve translation table: " + $_.Exception.Message)
        return $null
    }

    if (-not $translationTable -or $translationTable.Count -eq 0) {
        Write-Warning "No translation data available for directory ID $TargetDirectoryId."
        return $null
    }

    $match = $translationTable | Where-Object { $_.SourceUPN -ieq $SourceUPN }

    if ($match) {
        $targetSID = $match.TargetSID
        Write-Host "Found target SID: $targetSID" -ForegroundColor Green
        return $targetSID
    }
    else {
        Write-Warning "No matching entry found for source UPN '$SourceUPN'."
        return $null
    }
}
function Add-PSPBatchComputer {
<#
.SYNOPSIS
    Adds one or more computers to a PowerSyncPro migration batch.

.DESCRIPTION
    Supports adding computers by name or from a CSV.
    Updates the batch using the new Update bundle format.
    Preserves runbooks, allComputers/noComputer flags, and other metadata.

.PARAMETER BatchId
    The ID of the batch to modify.

.PARAMETER ComputerName
    One or more computer names to add.
    Example: -ComputerName PC1,PC2,PC3

.PARAMETER CsvPath
    CSV file containing a "ComputerName" column.

.PARAMETER WhatIf
    Shows what would happen without modifying the batch.

.EXAMPLE
    Add-PSPBatchComputer -BatchId "xxxx" -ComputerName "PC1"

.EXAMPLE
    Add-PSPBatchComputer -BatchId "xxxx" -ComputerName PC1,PC2,PC3

.EXAMPLE
    Add-PSPBatchComputer -BatchId "xxxx" -CsvPath "C:\Temp\list.csv"

#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BatchId,

        [string[]]$ComputerName,

        [string]$CsvPath,

        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession
    )

    Write-Host "Adding computers to batch $BatchId..." -ForegroundColor Yellow

    #
    # Resolve batch metadata
    #
    $batch = Get-PSPBatches -BaseUrl $BaseUrl -Session $Session |
             Where-Object { $_.id -eq $BatchId }

    if (-not $batch) {
        throw "Batch $BatchId not found."
    }

    #
    # Load runbooks
    #
    $runbookResp = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Method GET `
        -Endpoint "/api/services/app/BatchRunbooks/GetBatchRunbooks?batchId=$BatchId"

    $runbooks = @()
    if ($runbookResp.result.items) {
        $runbooks = $runbookResp.result.items
    }

    #
    # Loaded state values
    #
    $sourceId     = $batch.sourceDirectoryId
    $targetId     = $batch.targetDirectoryId
    $allComputers = $batch.allComputers
    $noComputer   = $batch.noComputer

    #
    # Get existing batch computers (full list)
    #
    $existing = Get-PSPBatchComputers -BatchId $BatchId
    $existingNames = $existing.name

    #
    # Build list of input computer names
    #
    $inputNames = @()

    if ($ComputerName) {
        $inputNames += $ComputerName
    }

    if ($CsvPath) {
        if (-not (Test-Path $CsvPath)) {
            throw "CSV not found: $CsvPath"
        }
        $csv = Import-Csv -Path $CsvPath
        foreach ($row in $csv) {
            if ($row.ComputerName) {
                $inputNames += $row.ComputerName
            }
        }
    }

    $inputNames = $inputNames | Sort-Object -Unique

    if ($inputNames.Count -eq 0) {
        throw "No computer names were provided."
    }

    #
    # Load directory computers for validation
    #
    $dirResp = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Method GET `
        -Endpoint "/api/services/app/BatchItems/GetComputerSearchResults?directoryId=$sourceId"

    $dirList = $dirResp.result.items

    #
    # Build new exemptedComputers list
    #
    $newList = @()

    foreach ($item in $existing) {
        $newList += [PSCustomObject]@{
            name        = $item.name
            displayName = $item.displayName
            objectUid   = $item.objectUid
            objectSid   = $item.objectSid
            serialNumber= $item.serialNumber
        }
    }

    #
    # Add incoming computers
    #
    foreach ($name in $inputNames) {

        if ($existingNames -contains $name) {
            Write-Host "Skipping $name (already in batch)" -ForegroundColor DarkGray
            continue
        }

        $match = $dirList | Where-Object { $_.name -eq $name } | Select-Object -First 1

        if (-not $match) {
            Write-Warning "Computer $name not found in directory."
            continue
        }

        # Build safe displayName fallback
        $display = $match.displayName
        if (-not $display) { $display = $match.name }

        $newObj = [PSCustomObject]@{
            name        = $match.name
            displayName = $display
            objectUid   = $match.objectUid
            objectSid   = $match.objectSid
            serialNumber= $match.serialNumber
        }

        Write-Host "Adding $name" -ForegroundColor Green
        $newList += $newObj
    }

    #
    # Nothing new?
    #
    if ($newList.Count -eq $existing.Count) {
        Write-Warning "No new computers were added. Nothing to update."
        return
    }

    #
    # Build update bundle
    #
    $payloadObj = @{
        id                 = $BatchId
        name               = $batch.name
        sourceId           = $sourceId
        targetId           = $targetId
        allComputers       = $allComputers
        noComputer         = $noComputer
        runbooks           = $runbooks
        exemptedComputers  = $newList
    }

    if ($PSCmdlet.ShouldProcess("Batch $BatchId", "Add $($inputNames -join ', ')")) {
        $json = $payloadObj | ConvertTo-Json -Depth 10

        $resp = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Method PUT `
            -Endpoint "/api/services/app/Batches/Update" -Body $json

        if ($resp.success) {
            Write-Host "Batch updated successfully." -ForegroundColor Green
        } else {
            Write-Warning "Batch update failed."
        }
    }
}
function Remove-PSPBatchComputer {
<#
.SYNOPSIS
    Removes computers from a PowerSyncPro migration batch.

.DESCRIPTION
    Supports removing one or more computers by name or from a CSV.
    Preserves runbooks, allComputers/noComputer flags, and other metadata.

.PARAMETER BatchId
    The ID of the batch to modify.

.PARAMETER ComputerName
    One or more computer names to remove.

.PARAMETER CsvPath
    CSV file containing "ComputerName" column.

.PARAMETER WhatIf
    Shows what would happen without modifying the batch.

.EXAMPLE
    Remove-PSPBatchComputer -BatchId "xxxx" -ComputerName "PC1"

.EXAMPLE
    Remove-PSPBatchComputer -BatchId "xxxx" -ComputerName PC1,PC2,PC3

.EXAMPLE
    Remove-PSPBatchComputer -BatchId "xxxx" -CsvPath "C:\Temp\remove.csv"

#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BatchId,

        [string[]]$ComputerName,

        [string]$CsvPath,

        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession
    )

    Write-Host "Removing computers from batch $BatchId..." -ForegroundColor Yellow

    #
    # Resolve batch
    #
    $batch = Get-PSPBatches -BaseUrl $BaseUrl -Session $Session |
             Where-Object { $_.id -eq $BatchId }

    if (-not $batch) {
        throw "Batch $BatchId not found."
    }

    #
    # Get runbooks
    #
    $runbookResp = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Method GET `
        -Endpoint "/api/services/app/BatchRunbooks/GetBatchRunbooks?batchId=$BatchId"

    $runbooks = @()
    if ($runbookResp.result.items) {
        $runbooks = $runbookResp.result.items
    }

    #
    # Read existing computers
    #
    $existing = Get-PSPBatchComputers -BatchId $BatchId
    $existingNames = $existing.name

    #
    # Read input names
    #
    $inputNames = @()

    if ($ComputerName) {
        $inputNames += $ComputerName
    }

    if ($CsvPath) {
        if (-not (Test-Path $CsvPath)) { throw "CSV not found: $CsvPath" }
        $csv = Import-Csv $CsvPath
        foreach ($row in $csv) {
            if ($row.ComputerName) {
                $inputNames += $row.ComputerName
            }
        }
    }

    $inputNames = $inputNames | Sort-Object -Unique

    if ($inputNames.Count -eq 0) {
        throw "No computer names provided."
    }

    #
    # Build new list excluding removals
    #
    $newList = @()

    foreach ($item in $existing) {
        if ($inputNames -contains $item.name) {
            Write-Host "Removing $($item.name)" -ForegroundColor Yellow
            continue
        }

        $newList += [PSCustomObject]@{
            name        = $item.name
            displayName = $item.displayName
            objectUid   = $item.objectUid
            objectSid   = $item.objectSid
            serialNumber= $item.serialNumber
        }
    }

    #
    # Build payload
    #
    $payloadObj = @{
        id                 = $BatchId
        name               = $batch.name
        sourceId           = $batch.sourceDirectoryId
        targetId           = $batch.targetDirectoryId
        allComputers       = $batch.allComputers
        noComputer         = $batch.noComputer
        runbooks           = $runbooks
        exemptedComputers  = $newList
    }

    if ($PSCmdlet.ShouldProcess("Batch $BatchId", "Remove $($inputNames -join ', ')")) {
        $json = $payloadObj | ConvertTo-Json -Depth 10

        $resp = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Method PUT `
            -Endpoint "/api/services/app/Batches/Update" -Body $json

        if ($resp.success) {
            Write-Host "Batch updated successfully." -ForegroundColor Green
        } else {
            Write-Warning "Batch update failed."
        }
    }
}
# ---------------------------------------------------------------------
# Runbooks
# ---------------------------------------------------------------------
function Get-PSPRunbooks {
    <#
    .SYNOPSIS
        Retrieves all Runbooks or a specific Runbook by name from PowerSyncPro.

    .DESCRIPTION
        Calls /api/services/app/Runbooks/GetAll to return available Runbooks.
        Supports pagination, full-detail output, and the -All switch to automatically
        retrieve all Runbooks from the server.

    .PARAMETER BaseUrl
        PowerSyncPro server root (e.g. https://psp.company.com)

    .PARAMETER Session
        The authenticated WebRequestSession (from Get-PSPSession or Connect-PSPServer)

    .PARAMETER Name
        Optional Runbook name to filter results (case-insensitive).

    .PARAMETER SkipCount
        Number of records to skip (default 0).

    .PARAMETER MaxResultCount
        Maximum number of results to return per request (default 100).

    .PARAMETER Full
        If specified, returns the full Runbook object(s) as provided by the API.

    .PARAMETER All
        Retrieve *all* available Runbooks by paginating through the API.

    .EXAMPLE
        Get-PSPRunbooks
        # Retrieves the first 100 runbooks.

    .EXAMPLE
        Get-PSPRunbooks -All
        # Retrieves all runbooks via automatic pagination.

    .EXAMPLE
        Get-PSPRunbooks -Name "RLN Hybrid AD to Entra"
        # Retrieves the runbook matching the provided name.
    #>

    [CmdletBinding()]
    param(
        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession,
        [string]$Name,
        [int]$SkipCount = 0,
        [int]$MaxResultCount = 100,
        [switch]$Full,
        [switch]$All
    )

    Write-Host "Retrieving runbooks from $BaseUrl..." -ForegroundColor Cyan

    $allRunbooks = @()
    $page = 0

    do {
        $endpoint = "/api/services/app/Runbooks/GetAll?sorting=Name%20asc&skipCount=$SkipCount&maxResultCount=$MaxResultCount"
        Write-Host "Calling $endpoint ..." -ForegroundColor DarkGray

        try {
            $response = Invoke-PSPApi -BaseUrl $BaseUrl -Session $Session -Method GET -Endpoint $endpoint
        }
        catch {
            Write-Warning ("Request failed at skip={0}: {1}" -f $SkipCount, $_.Exception.Message)
            break
        }

        if (-not $response.success -or -not $response.result.items) {
            Write-Warning "No runbooks found or invalid response from server."
            break
        }

        $items = $response.result.items
        $page++
        $allRunbooks += $items

        Write-Host ("Page {0}: Retrieved {1} runbook(s) (total so far: {2})" -f $page, $items.Count, $allRunbooks.Count) -ForegroundColor Gray

        $SkipCount += $MaxResultCount
        $continue = $All -and ($items.Count -eq $MaxResultCount)
    }
    while ($continue)

    if ($allRunbooks.Count -eq 0) {
        Write-Warning "No runbooks returned by the API."
        return @()
    }

    # Optional name filter
    if ($Name) {
        Write-Host "Filtering runbooks for name match: '$Name'..." -ForegroundColor DarkGray
        $filtered = $allRunbooks | Where-Object { $_.name -ieq $Name }

        if (-not $filtered -or $filtered.Count -eq 0) {
            Write-Warning "No runbook found with name '$Name'."
            return @()
        }

        Write-Host ("Found {0} matching runbook(s)." -f $filtered.Count) -ForegroundColor Green

        if ($Full) { return $filtered }
        return $filtered | Select-Object id, name, sourceDirectoryDisplayName, sourceDirectoryName, targetDirectoryDisplayName, targetDirectoryName
    }

    Write-Host ("Retrieved {0} total runbook(s)." -f $allRunbooks.Count) -ForegroundColor Green

    if ($Full) {
        return $allRunbooks
    }
    else {
        return $allRunbooks | Select-Object id, name, sourceDirectoryDisplayName, sourceDirectoryName, targetDirectoryDisplayName, targetDirectoryName
    }
}
function Create-PSPRunbook {
    [CmdletBinding()]
    param(
        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Parameter(Mandatory)][string]$SourceDirectory,
        [Parameter(Mandatory)][string]$TargetDirectory,
        [Parameter(Mandatory)][string]$Name,
        [Parameter()][string]$FallbackUsername = "",
        [Parameter()][string]$FallbackPassword = ""
    )

    if (-not $script:PSPSession) {
        Write-Host "No active PSP session. Authenticate using Get-PSPSession first." -ForegroundColor Red
        return
    }

    Write-Host "Resolving directories from $BaseUrl..." -ForegroundColor Cyan

    $dirs = Invoke-WebRequest `
        -Uri "$BaseUrl/api/services/app/Directories/GetAll?sorting=DisplayName asc&skipCount=0&maxResultCount=100" `
        -WebSession $script:PSPSession -UseBasicParsing

    $dirObj = $dirs.Content | ConvertFrom-Json
    $sourceId = ($dirObj.result.items | Where-Object {$_.displayName -eq $SourceDirectory}).id
    $targetId = ($dirObj.result.items | Where-Object {$_.displayName -eq $TargetDirectory}).id

    if (-not $sourceId -or -not $targetId) {
        Write-Host "Directory lookup failed. Source or Target not found." -ForegroundColor Red
        return
    }

    Write-Host "Creating runbook '$Name'..." -ForegroundColor Cyan

    $payload = @{
        # identity
        name                          = $Name
        sourceDirectoryIds            = @("$sourceId")
        targetDirectoryId             = "$targetId"

        # directory join/remove
        directoryTypeToRemoveFrom     = 0  # None
        directoryTypeToJoinTo         = 0  # None

        # fallback account
        fallbackAccountUsername       = $FallbackUsername
        fallbackAccountPassword       = $FallbackPassword
        fallbackAccountDeletionDelayInDays = 5

        # toggles (matching UI defaults)
        updateServicesPermissions     = $true
        updateScheduledTaskPermissions= $true
        updateUserRightPermissions    = $true
        updateLocalGroupPermissions   = $true
        updateWindowsProfilePermissions = $true
        updateRegistryPermissions     = $true
        updateFileSharePermissions    = $true
        updateSqlServerPermissions    = $true
        updateIisPermissions          = $true
        UpdateFileSystemPermissions   = $true

        updatePrintersPermissions     = $true
        reconfigureOutlook            = $true
        reconfigureEdge               = $true
        reconfigureMicrosoft365       = $true
        reconfigureAzureInformationProtection = $true
        reconfigureOneDrive           = $true
        reconfigureApplications       = $false

        makeOneDriveFilesCloudOnly    = $true
        setOneDriveSilentAccountConfig= 0
        setOutlookZeroConfigExchange  = 0
        setProxyAutoDetect            = 0
        shouldEnrollToIntune          = $true
        silentMode                    = $false
        permissionUpdateType          = 2    # Admin+Files
        migrationInProgressImageType  = 0
        culture                       = "Default"

        areasToIgnore = "%SystemRoot%\*\r\n%ProgramFiles%\*\r\n%ProgramFiles(x86)%\*\r\n*:\System Volume Information\*\r\n*:\DumpStack.log*\r\n*:\hiberfil.sys\r\n*:\pagefile.sys\r\n*:\swapfile.sys\r\nc:\Windows.old\r\n%ProgramData%\Microsoft\Windows\AppRepository\*"

        # dialogs AT ROOT — required structure
        qrCodeUrl = @{
            key="QRCodeUrl"; title="QR Code Url"; stringType=3; values=@{Default=$null}
        }
        cacheCredentialsDialog = @{
            key="CacheCredentials"; title="Cache Credentials"
            usernameLabel=@{key="UsernameLabel";title="Username Label";stringType=0;values=@{Default="Username"}}
            passwordLabel=@{key="PasswordLabel";title="Password Label";stringType=0;values=@{Default="Password"}}
            usernamePlaceholder=@{key="UsernamePlaceholder";title="Username Placeholder";stringType=0;values=@{Default="first.last@domain.com"}}
            loginText=@{key="LoginText";title="Login Text";stringType=1;values=@{Default="Please provide your login details."}}
            saveButton=@{key="SaveButton";title="Save Button";stringType=0;values=@{Default="Save"}}
            cancelButton=@{key="CancelButton";title="Cancel Button";stringType=0;values=@{Default="Cancel"}}
            invalidInputTitle=@{key="InvalidInputTitle";title="Invalid Input Title";stringType=0;values=@{Default="Invalid Credentials"}}
            invalidInputMessage=@{key="InvalidInputMessage";title="Invalid Input Message";stringType=0;values=@{Default="Username and password must be provided"}}
            credentialCacheFailureTitle=@{key="CredentialCacheFailureTitle";title="Credential Cache Failure Title";stringType=0;values=@{Default="Invalid Credentials"}}
            credentialCacheFailureMessage=@{key="CredentialCacheFailureMessage";title="Credential Cache Failure Message";stringType=0;values=@{Default="Invalid Credentials"}}
            windowTitle=@{key="WindowTitle";title="Window Title";stringType=0;values=@{Default="Cache Credentials"}}
            logo=@{key="Logo";title="Logo";stringType=2;values=@{Default=""}}
            mainMessage=@{key="MainMessage";title="Main Message";stringType=1;values=@{Default="Migration is available."}}
        }
        migrationInProgressDialog = @{
            key="MigrationInProgress";title="Migration In Progress"
            windowTitle=@{key="WindowTitle";title="Window Title";stringType=0;values=@{Default="Migration in progress"}}
            mainMessage=@{key="MainMessage";title="Main Message";stringType=1;values=@{Default="Migration in progress, please wait.."}}
        }
        legalNoticeDialog = @{
            key="LegalNotice";title="Legal Notice"
            legalNoticeCaption=@{key="LegalNoticeCaption";title="Legal Notice Caption";stringType=0;values=@{Default="Migration in Progress"}}
            legalNoticeText=@{key="LegalNoticeText";title="Legal Notice Text";stringType=0;values=@{Default="This is a migration.  Do not try to login."}}
        }
        migrationStartingDialog = @{
            key="MigrationStarting";title="Migration Starting"
            windowTitle=@{key="WindowTitle";title="Window Title";stringType=0;values=@{Default="Start Device Migration"}}
            mainMessage=@{key="MainMessage";stringType=1;values=@{Default="Your device migration will start in {0} minutes.  Please save your work.`r`n`r`nDo you want to start your device migration now?  If so click Yes, otherwise click No"}}
            yesButton=@{key="YesButton";title="Yes Button";stringType=0;values=@{Default="Yes"}}
            noButton=@{key="NoButton";title="No Button";stringType=0;values=@{Default="No"}}
        }
        migrationAvailableDialog = @{
            key="MigrationAvailable";title="Migration Available"
            windowTitle=@{key="WindowTitle";stringType=0;values=@{Default="Migration Available"}}
            mainMessage=@{key="MainMessage";stringType=1;values=@{Default="A migration is available to be run.`r`nPlease save your work and start the migration now, or wait until a better time.`r`n`r`nThe migration will be forced to occur at: {StartDate}."}}
            startButton=@{key="StartButton";stringType=0;values=@{Default="Start"}}
            snoozeButton=@{key="SnoozeButton";stringType=0;values=@{Default="Snooze"}}
            snoozeLabel=@{key="SnoozeLabel";stringType=0;values=@{Default="or, snooze until"}}
            snooze15Minutes=@{key="Snooze15Minutes";stringType=5;values=@{Default="Minutes"}}
            snooze30Minutes=@{key="Snooze30Minutes";stringType=5;values=@{Default="Minutes"}}
            snooze1Hour=@{key="Snooze1Hour";stringType=5;values=@{Default="Hour"}}
            snooze4Hours=@{key="Snooze4Hours";stringType=5;values=@{Default="Hours"}}
            snooze1Day=@{key="Snooze1Day";stringType=5;values=@{Default="Day"}}
            snooze1Week=@{key="Snooze1Week";stringType=5;values=@{Default="Week"}}
            snooze5Minutes=@{key="Snooze5Minutes";stringType=5;values=@{Default="Minutes"}}
        }
        migrationCompleteDialog = @{
            key="MigrationComplete";title="Migration Complete"
            windowTitle=@{key="WindowTitle";stringType=0;values=@{Default="Migration Complete"}}
            mainMessage=@{key="MainMessage";stringType=1;values=@{Default="The migration agent has now completed."}}
            okButton=@{key="OkButton";stringType=0;values=@{Default="OK"}}
        }
        serviceUnavailableDialog = @{
            key="ServiceUnavailable";title="Service Unavailable"
            windowTitle=@{key="WindowTitle";stringType=0;values=@{Default="Service Unavailable"}}
            mainMessage=@{key="MainMessage";stringType=1;values=@{Default="Unable to contact the PowerSyncPro server. Migration will retry periodically."}}
            okButton=@{key="OkButton";stringType=0;values=@{Default="OK"}}
        }
    }

    $json = $payload | ConvertTo-Json -Depth 20
    #Write-Host "`nJSON Payload:" -ForegroundColor Yellow
    #$json | Write-Host

    $headers = @{
        "X-XSRF-TOKEN" = $script:PSPSession.XsrfToken
    }

    try {
        $response = Invoke-WebRequest `
            -Uri "$BaseUrl/api/services/app/Runbooks/Create" `
            -Method POST -ContentType "application/json" `
            -Headers $headers -WebSession $script:PSPSession `
            -Body $json -UseBasicParsing

        Write-Host "Runbook created successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "API call failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}
# ---------------------------------------------------------------------
# Info & Helpers
# ---------------------------------------------------------------------
function Get-PSPSIDFromUPN {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$DirectoryId,
        [Parameter(Mandatory)][string]$UserPrincipalName,

        [string]$BaseUrl = $script:PSPDefaultBaseUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session = $script:PSPSession
    )

    # STEP 1 — Search object
    $EncodedUPN = [System.Web.HttpUtility]::UrlEncode($UserPrincipalName)
    $endpoint = "/api/services/app/SingleObjectReport/GetAll?directoryId=$DirectoryId&searchTerm=$EncodedUPN&skipCount=0&maxResultCount=10"
    $getAll   = Invoke-PSPApi -Method GET -BaseUrl $BaseUrl -Session $Session -Endpoint $endpoint

    if (-not $getAll.result.items) {
        throw "No object found for UPN '$UserPrincipalName' in directory '$DirectoryId'"
    }

    $objectId = $getAll.result.items[0].importObjectId

    # STEP 2 — Pull modal HTML
    $modal = "/SingleObjectReport/SourceDetailViewModal?id=$objectId&showAsTarget=false"
    $html  = Invoke-PSPApi -Silent -Method POST -BaseUrl $BaseUrl -Session $Session -Endpoint $modal

    # STEP 3 — Extract *source* SID only (first SID in table)
    $sid = [regex]::Match($html,'(?s)objectSid.*?<td>\s*<p class="attribute-text">\s*(S-[0-9-]+)').Groups[1].Value
    return $sid
}