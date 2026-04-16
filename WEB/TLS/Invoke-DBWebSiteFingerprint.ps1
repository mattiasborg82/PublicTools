function Invoke-DBWebSiteFingerprint {
    <#
.SYNOPSIS
Performs TLS (JARM) and non-TLS fingerprinting of a web server or host.

.DESCRIPTION
Invoke-DBWebSiteFingerprint generates a composite fingerprint of a target
URL or host by combining multiple techniques:

- Native JARM TLS fingerprinting (no external tools required)
- HTTP response analysis (headers, title, content)
- Directory listing and file inventory detection
- URL extraction from HTML and script content
- Optional TCP port probing with banner grabbing
- Basic WHOIS/provider enrichment

The function is designed for threat hunting, infrastructure clustering,
malware hosting identification, and identifying related attacker-owned
assets even when TLS is not present.

When TLS is available, a full JARM fingerprint is generated using
10 crafted TLS ClientHello probes, similar to the Salesforce reference
implementation.

When TLS is not available, a composite fingerprint is built from HTTP,
content, and infrastructure characteristics.

.PARAMETER Url
The target URL to analyze. Can be HTTP or HTTPS and may be a domain name or IP address.

.PARAMETER Ports
Optional list of TCP ports to probe. The function will attempt to connect
and retrieve service banners where possible, contributing to the overall fingerprint.

.PARAMETER JarmOnly
If specified, only the TLS JARM fingerprint is generated and returned.
All HTTP and non-TLS analysis is skipped.

.EXAMPLE
Invoke-DBWebSiteFingerprint -Url "https://www.google.se"

Performs full fingerprinting of the target including:
- JARM TLS fingerprint
- HTTP analysis
- Extracted URLs
- Composite fingerprint

.EXAMPLE
Invoke-DBWebSiteFingerprint -Url "http://194.87.39.183" -Ports 22,80,443

Fingerprints a suspected malware host using:
- HTTP content and directory listing analysis
- Port scanning and banner grabbing
- Composite infrastructure fingerprinting

Useful when TLS is not available.

.EXAMPLE
Invoke-DBWebSiteFingerprint -Url "https://example.com" -JarmOnly

Returns only the JARM TLS fingerprint for the target.

.EXAMPLE
$r = Invoke-DBWebSiteFingerprint -Url "https://www.google.se"
$r.Tls.JarmHash

Extracts the JARM fingerprint from the result object.

.OUTPUTS
PSCustomObject with the following structure:

- Http                 : HTTP metadata and content fingerprints
- Tls                  : JARM fingerprint and raw probe results
- Network              : Port scan and banner data
- Provider             : WHOIS/provider information
- CompositeFingerprint : Combined fingerprint for clustering

.NOTES
Author: Mattias Borg | Defender Boys
Version: 1.0 (Native PowerShell JARM Implementation)

Key features:
- No external dependencies (no Python required)
- Compatible with Windows PowerShell 5.1 and newer
- Designed for security research and threat intelligence

Limitations:
- WHOIS parsing is best-effort and may vary by registry
- JARM accuracy depends on correct TLS response parsing
- Some servers may rate-limit or block repeated TLS probes

Use responsibly and only against systems you are authorized to analyze.

.LINK
https://github.com/salesforce/jarm
#>
<#
    @MattiasBorg82
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [int[]]$Ports,

        [switch]$JarmOnly
    )

    begin {
        function ConvertTo-DbSha256Hex {
            param(
                [Parameter(Mandatory = $true)]
                [AllowEmptyString()]
                [string]$InputString
            )

            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            try {
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
                $hash = $sha256.ComputeHash($bytes)
                return ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
            }
            finally {
                $sha256.Dispose()
            }
        }

        function ConvertTo-DbHex {
            param(
                [Parameter(Mandatory = $true)]
                [byte[]]$Bytes
            )
            return ([System.BitConverter]::ToString($Bytes) -replace '-', '').ToLowerInvariant()
        }

        function ConvertTo-DbBytesFromHex {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Hex
            )

            $clean = ($Hex -replace '\s+', '').ToLowerInvariant()
            if (($clean.Length % 2) -ne 0) {
                throw "Invalid hex length"
            }

            $bytes = New-Object byte[] ($clean.Length / 2)
            for ($i = 0; $i -lt $clean.Length; $i += 2) {
                $bytes[$i / 2] = [Convert]::ToByte($clean.Substring($i, 2), 16)
            }
            return $bytes
        }

        function Add-DbBytes {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.MemoryStream]$Stream,

        [AllowNull()]
        [byte[]]$Bytes
    )

    if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
        return
    }

    $Stream.Write($Bytes, 0, $Bytes.Length)
}

     function Get-DbRandomBytes {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Length
    )

    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }

    return $bytes
}

        function Get-DbBigEndianUint16Bytes {
            param(
                [Parameter(Mandatory = $true)]
                [int]$Value
            )

            return [byte[]]@(
                (($Value -shr 8) -band 0xff),
                ($Value -band 0xff)
            )
        }

        function Get-DbBigEndianUint24Bytes {
            param(
                [Parameter(Mandatory = $true)]
                [int]$Value
            )

            return [byte[]]@(
                (($Value -shr 16) -band 0xff),
                (($Value -shr 8) -band 0xff),
                ($Value -band 0xff)
            )
        }

        function Get-DbRangeBytes {
            param(
                [Parameter(Mandatory = $true)]
                [byte[]]$Data,

                [Parameter(Mandatory = $true)]
                [int]$Offset,

                [Parameter(Mandatory = $true)]
                [int]$Length
            )

            if ($Offset -lt 0 -or $Length -lt 0 -or ($Offset + $Length) -gt $Data.Length) {
                throw "Byte range out of bounds"
            }

            $out = New-Object byte[] $Length
            [Array]::Copy($Data, $Offset, $out, 0, $Length)
            return $out
        }

        function Get-DbUint16 {
            param(
                [Parameter(Mandatory = $true)]
                [byte[]]$Data,

                [Parameter(Mandatory = $true)]
                [int]$Offset
            )

            if (($Offset + 1) -ge $Data.Length) {
                throw "Uint16 out of bounds"
            }

            return (($Data[$Offset] -shl 8) -bor $Data[$Offset + 1])
        }

        function ConvertTo-DbNormalizedText {
            param(
                [AllowNull()]
                [string]$Text
            )

            if ([string]::IsNullOrEmpty($Text)) {
                return ''
            }

            $normalized = $Text
            $normalized = $normalized -replace "`r", ''
            $normalized = $normalized -replace "`n", ' '
            $normalized = $normalized -replace '\s+', ' '
            $normalized = $normalized.Trim()
            return $normalized.ToLowerInvariant()
        }

        function ConvertTo-DbBodyFingerprintText {
            param(
                [AllowNull()]
                [string]$Text
            )

            if ([string]::IsNullOrEmpty($Text)) {
                return ''
            }

            $normalized = $Text
            $normalized = $normalized -replace '(?is)<script\b[^>]*>.*?</script>', ' '
            $normalized = $normalized -replace '(?is)<style\b[^>]*>.*?</style>', ' '
            $normalized = $normalized -replace '(?i)\b[0-9a-f]{32,64}\b', ' '
            $normalized = $normalized -replace '\b\d{4}-\d{2}-\d{2}\b', ' '
            $normalized = $normalized -replace '\b\d{2}:\d{2}(:\d{2})?\b', ' '
            $normalized = $normalized -replace '\b\d+\b', ' '
            $normalized = $normalized -replace '(?i)last modified', ' '
            $normalized = $normalized -replace '(?i)size', ' '
            $normalized = $normalized -replace '(?i)date', ' '
            $normalized = $normalized -replace '(?s)<[^>]+>', ' '
            $normalized = [System.Net.WebUtility]::HtmlDecode($normalized)
            $normalized = ConvertTo-DbNormalizedText -Text $normalized
            return $normalized
        }

        function Get-DbUriInfo {
            param(
                [Parameter(Mandatory = $true)]
                [string]$InputUrl
            )

            $uri = $null
            if (-not [System.Uri]::TryCreate($InputUrl, [System.UriKind]::Absolute, [ref]$uri)) {
                throw "Invalid URL: $InputUrl"
            }

            $isIp = $false
            $ipObj = $null
            if ([System.Net.IPAddress]::TryParse($uri.Host, [ref]$ipObj)) {
                $isIp = $true
            }

            [pscustomobject]@{
                Uri         = $uri
                Host        = $uri.Host
                Scheme      = $uri.Scheme
                Port        = $uri.Port
                IsIpAddress = $isIp
            }
        }

        function Resolve-DbHostToIp {
            param(
                [Parameter(Mandatory = $true)]
                [string]$TargetHost
            )

            $results = New-Object System.Collections.Generic.List[string]
            try {
                $addresses = [System.Net.Dns]::GetHostAddresses($TargetHost)
                foreach ($address in $addresses) {
                    $ip = $address.IPAddressToString
                    if (-not [string]::IsNullOrWhiteSpace($ip) -and -not $results.Contains($ip)) {
                        $results.Add($ip)
                    }
                }
            }
            catch {
            }

            return @($results)
        }

        function Invoke-DbHttpRequest {
            param(
                [Parameter(Mandatory = $true)]
                [System.Uri]$Uri
            )

            $response = $null
            $body = $null
            $headers = @{}
            $errorText = $null

            try {
                $request = [System.Net.HttpWebRequest]::Create($Uri)
                $request.Method = 'GET'
                $request.Timeout = 10000
                $request.ReadWriteTimeout = 10000
                $request.AllowAutoRedirect = $true
                $request.UserAgent = 'DBWebSiteFingerprint/2.0'
                $request.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
                $request.Proxy = $null
                $response = [System.Net.HttpWebResponse]$request.GetResponse()
            }
            catch [System.Net.WebException] {
                if ($_.Exception.Response) {
                    $response = [System.Net.HttpWebResponse]$_.Exception.Response
                }
                else {
                    $errorText = $_.Exception.Message
                }
            }
            catch {
                $errorText = $_.Exception.Message
            }

            if ($response) {
                try {
                    foreach ($key in $response.Headers.AllKeys) {
                        $headers[$key] = $response.Headers[$key]
                    }

                    $stream = $response.GetResponseStream()
                    if ($stream) {
                        $reader = New-Object System.IO.StreamReader($stream)
                        try {
                            $body = $reader.ReadToEnd()
                        }
                        finally {
                            $reader.Dispose()
                            $stream.Dispose()
                        }
                    }
                }
                finally {
                    $statusCode = [int]$response.StatusCode
                    $statusDescription = [string]$response.StatusDescription
                    $contentType = [string]$response.ContentType
                    $finalUri = $response.ResponseUri
                    $response.Close()
                }

                return [pscustomobject]@{
                    Success           = $true
                    StatusCode        = $statusCode
                    StatusDescription = $statusDescription
                    ContentType       = $contentType
                    ResponseUri       = $finalUri
                    Headers           = $headers
                    Body              = $body
                    Error             = $null
                }
            }

            return [pscustomobject]@{
                Success           = $false
                StatusCode        = $null
                StatusDescription = $null
                ContentType       = $null
                ResponseUri       = $Uri
                Headers           = @{}
                Body              = $null
                Error             = $errorText
            }
        }

        function Get-DbHtmlTitle {
            param(
                [AllowNull()]
                [string]$Html
            )

            if ([string]::IsNullOrEmpty($Html)) {
                return $null
            }

            $m = [regex]::Match($Html, '(?is)<title[^>]*>(.*?)</title>')
            if ($m.Success) {
                return (ConvertTo-DbNormalizedText -Text ([System.Net.WebUtility]::HtmlDecode($m.Groups[1].Value)))
            }

            return $null
        }

        function Get-DbExtractedUrls {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Content,

                [Parameter(Mandatory = $true)]
                [System.Uri]$BaseUri
            )

            $results = New-Object System.Collections.Generic.List[string]

            $patterns = @(
                '(?is)\bhref\s*=\s*["'']([^"'']+)["'']',
                '(?is)\bsrc\s*=\s*["'']([^"'']+)["'']',
                '(?is)\baction\s*=\s*["'']([^"'']+)["'']',
                '(?i)\bhttps?://[^\s"''<>()]+'
            )

            foreach ($pattern in $patterns) {
                foreach ($match in [regex]::Matches($Content, $pattern)) {
                    $candidate = $null

                    if ($match.Groups.Count -gt 1 -and -not [string]::IsNullOrWhiteSpace($match.Groups[1].Value)) {
                        $candidate = $match.Groups[1].Value
                    }
                    else {
                        $candidate = $match.Value
                    }

                    if ([string]::IsNullOrWhiteSpace($candidate)) {
                        continue
                    }

                    $candidate = $candidate.Trim()

                    if ($candidate.StartsWith('javascript:', [System.StringComparison]::OrdinalIgnoreCase)) {
                        continue
                    }
                    if ($candidate.StartsWith('mailto:', [System.StringComparison]::OrdinalIgnoreCase)) {
                        continue
                    }
                    if ($candidate.StartsWith('#')) {
                        continue
                    }

                    try {
                        $resolved = [System.Uri]::new($BaseUri, $candidate)
                        $text = $resolved.AbsoluteUri
                        if (-not $results.Contains($text)) {
                            $results.Add($text)
                        }
                    }
                    catch {
                    }
                }
            }

            return @($results | Sort-Object -Unique)
        }

        function Get-DbFileInventory {
            param(
                [Parameter(Mandatory = $true)]
                [string[]]$Urls
            )

            $items = New-Object System.Collections.Generic.List[object]

            foreach ($url in $Urls) {
                try {
                    $u = [System.Uri]$url
                    $path = $u.AbsolutePath
                    if ([string]::IsNullOrWhiteSpace($path) -or $path -eq '/') {
                        continue
                    }

                    $name = [System.IO.Path]::GetFileName($path)
                    if ([string]::IsNullOrWhiteSpace($name)) {
                        continue
                    }

                    $ext = [System.IO.Path]::GetExtension($name).ToLowerInvariant()
                    $normalizedName = $name.ToLowerInvariant()

                    $items.Add([pscustomobject]@{
                        Name      = $normalizedName
                        Extension = $ext
                        Path      = $path.ToLowerInvariant()
                    })
                }
                catch {
                }
            }

            return @($items | Sort-Object Path, Name -Unique)
        }

        function Test-DbDirectoryListing {
            param(
                [AllowNull()]
                [string]$Content
            )

            if ([string]::IsNullOrEmpty($Content)) {
                return $false
            }

            $signals = @(
                '(?i)<title>\s*index of',
                '(?i)<h1>\s*index of',
                '(?i)directory listing for',
                '(?i)parent directory'
            )

            foreach ($signal in $signals) {
                if ($Content -match $signal) {
                    return $true
                }
            }

            return $false
        }

        function Get-DbWhoisInfo {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Target
            )

            $result = [ordered]@{
                Query       = $Target
                Registrar   = $null
                Org         = $null
                Country     = $null
                NetName     = $null
                CIDR        = $null
                Source      = $null
                Fingerprint = $null
                RawSummary  = $null
                Error       = $null
            }

            try {
                $whoisServer = 'whois.iana.org'
                $query = $Target

                $client = New-Object System.Net.Sockets.TcpClient
                try {
                    $client.ReceiveTimeout = 7000
                    $client.SendTimeout = 7000
                    $client.Connect($whoisServer, 43)

                    $stream = $client.GetStream()
                    $writer = New-Object System.IO.StreamWriter($stream)
                    $reader = New-Object System.IO.StreamReader($stream)
                    $writer.NewLine = "`r`n"
                    $writer.AutoFlush = $true
                    $writer.WriteLine($query)

                    $response = $reader.ReadToEnd()
                    $refServer = $null

                    foreach ($line in ($response -split "`r?`n")) {
                        if ($line -match '^(?i)(refer|whois):\s*(.+)$') {
                            $refServer = $matches[2].Trim()
                            break
                        }
                    }

                    if (-not [string]::IsNullOrWhiteSpace($refServer)) {
                        $client2 = New-Object System.Net.Sockets.TcpClient
                        try {
                            $client2.ReceiveTimeout = 7000
                            $client2.SendTimeout = 7000
                            $client2.Connect($refServer, 43)

                            $stream2 = $client2.GetStream()
                            $writer2 = New-Object System.IO.StreamWriter($stream2)
                            $reader2 = New-Object System.IO.StreamReader($stream2)
                            $writer2.NewLine = "`r`n"
                            $writer2.AutoFlush = $true
                            $writer2.WriteLine($query)

                            $response = $reader2.ReadToEnd()
                            $result.Source = $refServer
                        }
                        finally {
                            $client2.Close()
                        }
                    }
                    else {
                        $result.Source = $whoisServer
                    }

                    foreach ($line in ($response -split "`r?`n")) {
                        if (-not $result.Registrar -and $line -match '^(?i)(registrar|registrar name):\s*(.+)$') {
                            $result.Registrar = $matches[2].Trim()
                            continue
                        }
                        if (-not $result.Org -and $line -match '^(?i)(orgname|org-name|organization|descr):\s*(.+)$') {
                            $result.Org = $matches[2].Trim()
                            continue
                        }
                        if (-not $result.Country -and $line -match '^(?i)country:\s*(.+)$') {
                            $result.Country = $matches[1].Trim()
                            continue
                        }
                        if (-not $result.NetName -and $line -match '^(?i)netname:\s*(.+)$') {
                            $result.NetName = $matches[1].Trim()
                            continue
                        }
                        if (-not $result.CIDR -and $line -match '^(?i)cidr:\s*(.+)$') {
                            $result.CIDR = $matches[1].Trim()
                            continue
                        }
                    }

                    $summary = @(
                        "query=$($result.Query)"
                        "registrar=$($result.Registrar)"
                        "org=$($result.Org)"
                        "country=$($result.Country)"
                        "netname=$($result.NetName)"
                        "cidr=$($result.CIDR)"
                        "source=$($result.Source)"
                    ) -join '|'

                    $result.RawSummary = $summary
                    $result.Fingerprint = ConvertTo-DbSha256Hex -InputString (ConvertTo-DbNormalizedText -Text $summary)
                }
                finally {
                    $client.Close()
                }
            }
            catch {
                $result.Error = $_.Exception.Message
            }

            return [pscustomobject]$result
        }

        function Get-DbTcpBanner {
            param(
                [Parameter(Mandatory = $true)]
                [string]$TargetHost,

                [Parameter(Mandatory = $true)]
                [int]$Port
            )

            $result = [ordered]@{
                Port        = $Port
                Connected   = $false
                Service     = $null
                Banner      = $null
                Fingerprint = $null
                Error       = $null
            }

            $client = New-Object System.Net.Sockets.TcpClient
            try {
                $iar = $client.BeginConnect($TargetHost, $Port, $null, $null)
                if (-not $iar.AsyncWaitHandle.WaitOne(4000, $false)) {
                    throw "Connection timeout"
                }

                $client.EndConnect($iar)
                $result.Connected = $true

                $stream = $client.GetStream()
                $stream.ReadTimeout = 4000
                $stream.WriteTimeout = 4000

                Start-Sleep -Milliseconds 200

                $banner = $null
                $buffer = New-Object byte[] 4096

                if ($stream.DataAvailable) {
                    $read = $stream.Read($buffer, 0, $buffer.Length)
                    if ($read -gt 0) {
                        $banner = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $read)
                    }
                }

                if (-not $banner) {
                    if ($Port -in 80,8080,8000,8888) {
                        $requestBytes = [System.Text.Encoding]::ASCII.GetBytes("HEAD / HTTP/1.0`r`nHost: $TargetHost`r`nConnection: close`r`n`r`n")
                        $stream.Write($requestBytes, 0, $requestBytes.Length)
                        $read = $stream.Read($buffer, 0, $buffer.Length)
                        if ($read -gt 0) {
                            $banner = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $read)
                            $result.Service = 'http'
                        }
                    }
                }

                if (-not $result.Service) {
                    switch ($Port) {
                        21  { $result.Service = 'ftp' }
                        22  { $result.Service = 'ssh' }
                        25  { $result.Service = 'smtp' }
                        80  { $result.Service = 'http' }
                        110 { $result.Service = 'pop3' }
                        143 { $result.Service = 'imap' }
                        443 { $result.Service = 'https-or-tls' }
                        465 { $result.Service = 'smtps' }
                        587 { $result.Service = 'smtp-submission' }
                        993 { $result.Service = 'imaps' }
                        995 { $result.Service = 'pop3s' }
                        default { $result.Service = 'unknown' }
                    }
                }

                if ($banner) {
                    $normalizedBanner = ConvertTo-DbNormalizedText -Text $banner
                    $normalizedBanner = $normalizedBanner -replace '\b\d{1,2}:\d{2}(:\d{2})?\b', ' '
                    $normalizedBanner = $normalizedBanner -replace '\b\d{4}-\d{2}-\d{2}\b', ' '
                    $normalizedBanner = $normalizedBanner -replace '\s+', ' '
                    $normalizedBanner = $normalizedBanner.Trim()
                    $result.Banner = $normalizedBanner
                    $result.Fingerprint = ConvertTo-DbSha256Hex -InputString "$Port|$($result.Service)|$normalizedBanner"
                }
            }
            catch {
                $result.Error = $_.Exception.Message
            }
            finally {
                $client.Close()
            }

            return [pscustomobject]$result
        }

        function Get-DbJarmGreaseValue {
            $greaseList = @(
                [byte[]](0x0a,0x0a), [byte[]](0x1a,0x1a), [byte[]](0x2a,0x2a), [byte[]](0x3a,0x3a),
                [byte[]](0x4a,0x4a), [byte[]](0x5a,0x5a), [byte[]](0x6a,0x6a), [byte[]](0x7a,0x7a),
                [byte[]](0x8a,0x8a), [byte[]](0x9a,0x9a), [byte[]](0xaa,0xaa), [byte[]](0xba,0xba),
                [byte[]](0xca,0xca), [byte[]](0xda,0xda), [byte[]](0xea,0xea), [byte[]](0xfa,0xfa)
            )

            return $greaseList[(Get-Random -Minimum 0 -Maximum $greaseList.Count)]
        }

       function Get-DbJarmCipherList {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CipherSetName
    )

    $all = @(
        [byte[]](0x00,0x16), [byte[]](0x00,0x33), [byte[]](0x00,0x67), [byte[]](0xc0,0x9e), [byte[]](0xc0,0xa2),
        [byte[]](0x00,0x9e), [byte[]](0x00,0x39), [byte[]](0x00,0x6b), [byte[]](0xc0,0x9f), [byte[]](0xc0,0xa3),
        [byte[]](0x00,0x9f), [byte[]](0x00,0x45), [byte[]](0x00,0xbe), [byte[]](0x00,0x88), [byte[]](0x00,0xc4),
        [byte[]](0x00,0x9a), [byte[]](0xc0,0x08), [byte[]](0xc0,0x09), [byte[]](0xc0,0x23), [byte[]](0xc0,0xac),
        [byte[]](0xc0,0xae), [byte[]](0xc0,0x2b), [byte[]](0xc0,0x0a), [byte[]](0xc0,0x24), [byte[]](0xc0,0xad),
        [byte[]](0xc0,0xaf), [byte[]](0xc0,0x2c), [byte[]](0xc0,0x72), [byte[]](0xc0,0x73), [byte[]](0xcc,0xa9),
        [byte[]](0x13,0x02), [byte[]](0x13,0x01), [byte[]](0xcc,0x14), [byte[]](0xc0,0x07), [byte[]](0xc0,0x12),
        [byte[]](0xc0,0x13), [byte[]](0xc0,0x27), [byte[]](0xc0,0x2f), [byte[]](0xc0,0x14), [byte[]](0xc0,0x28),
        [byte[]](0xc0,0x30), [byte[]](0xc0,0x60), [byte[]](0xc0,0x61), [byte[]](0xc0,0x76), [byte[]](0xc0,0x77),
        [byte[]](0xcc,0xa8), [byte[]](0x13,0x05), [byte[]](0x13,0x04), [byte[]](0x13,0x03), [byte[]](0xcc,0x13),
        [byte[]](0xc0,0x11), [byte[]](0x00,0x0a), [byte[]](0x00,0x2f), [byte[]](0x00,0x3c), [byte[]](0xc0,0x9c),
        [byte[]](0xc0,0xa0), [byte[]](0x00,0x9c), [byte[]](0x00,0x35), [byte[]](0x00,0x3d), [byte[]](0xc0,0x9d),
        [byte[]](0xc0,0xa1), [byte[]](0x00,0x9d), [byte[]](0x00,0x41), [byte[]](0x00,0xba), [byte[]](0x00,0x84),
        [byte[]](0x00,0xc0), [byte[]](0x00,0x07), [byte[]](0x00,0x04), [byte[]](0x00,0x05)
    )

    switch ($CipherSetName) {
        'ALL' {
            return $all
        }

        'NO1.3' {
            return @(
                $all | Where-Object {
                    $hex = ([System.BitConverter]::ToString($_) -replace '-', '').ToLowerInvariant()
                    $hex -notin @('1301','1302','1303','1304','1305')
                }
            )
        }

        default {
            return $all
        }
    }
}

        function Invoke-DbJarmMung {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Items,

        [Parameter(Mandatory = $true)]
        [string]$Request
    )

    if ($null -eq $Items -or $Items.Count -eq 0) {
        return @()
    }

    $count = $Items.Count
    $result = New-Object System.Collections.ArrayList

    switch ($Request) {
        'REVERSE' {
            for ($i = $count - 1; $i -ge 0; $i--) {
                [void]$result.Add($Items[$i])
            }
        }

        'BOTTOM_HALF' {
            if (($count % 2) -eq 1) {
                $start = [int]($count / 2) + 1
            }
            else {
                $start = [int]($count / 2)
            }

            for ($i = $start; $i -lt $count; $i++) {
                [void]$result.Add($Items[$i])
            }
        }

        'TOP_HALF' {
            if (($count % 2) -eq 1) {
                [void]$result.Add($Items[[int]($count / 2)])
            }

            $reverse = @(Invoke-DbJarmMung -Items $Items -Request 'REVERSE')
            $bottom = @(Invoke-DbJarmMung -Items $reverse -Request 'BOTTOM_HALF')

            foreach ($item in $bottom) {
                [void]$result.Add($item)
            }
        }

        'MIDDLE_OUT' {
            $middle = [int]($count / 2)

            if (($count % 2) -eq 1) {
                [void]$result.Add($Items[$middle])

                for ($i = 1; $i -le $middle; $i++) {
                    if (($middle + $i) -lt $count) {
                        [void]$result.Add($Items[$middle + $i])
                    }
                    if (($middle - $i) -ge 0) {
                        [void]$result.Add($Items[$middle - $i])
                    }
                }
            }
            else {
                for ($i = 0; $i -lt $middle; $i++) {
                    $right = $middle + $i
                    $left = $middle - 1 - $i

                    if ($right -lt $count) {
                        [void]$result.Add($Items[$right])
                    }
                    if ($left -ge 0) {
                        [void]$result.Add($Items[$left])
                    }
                }
            }
        }

        default {
            foreach ($item in $Items) {
                [void]$result.Add($item)
            }
        }
    }

    return @($result.ToArray())
}
function Get-DbJarmSelectedCiphers {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Probe
    )

    $list = @(Get-DbJarmCipherList -CipherSetName $Probe[3])

    if ($Probe[4] -ne 'FORWARD') {
        $list = @(Invoke-DbJarmMung -Items $list -Request $Probe[4])
    }

    $output = New-Object System.Collections.Generic.List[byte]

    if ($Probe[5] -eq 'GREASE') {
        foreach ($b in (Get-DbJarmGreaseValue)) {
            [void]$output.Add($b)
        }
    }

    foreach ($cipher in $list) {
        if ($null -eq $cipher) {
            continue
        }

        foreach ($b in [byte[]]$cipher) {
            [void]$output.Add($b)
        }
    }

    return [byte[]]$output.ToArray()
}

        function Get-DbJarmServerNameExtension {
            param(
                [Parameter(Mandatory = $true)]
                [string]$TargetHost
            )

            $hostBytes = [System.Text.Encoding]::ASCII.GetBytes($TargetHost)
            $ms = New-Object System.IO.MemoryStream

            Add-DbBytes -Stream $ms -Bytes ([byte[]](0x00,0x00))
            Add-DbBytes -Stream $ms -Bytes (Get-DbBigEndianUint16Bytes -Value ($hostBytes.Length + 5))
            Add-DbBytes -Stream $ms -Bytes (Get-DbBigEndianUint16Bytes -Value ($hostBytes.Length + 3))
            Add-DbBytes -Stream $ms -Bytes ([byte[]](0x00))
            Add-DbBytes -Stream $ms -Bytes (Get-DbBigEndianUint16Bytes -Value $hostBytes.Length)
            Add-DbBytes -Stream $ms -Bytes $hostBytes

            $bytes = $ms.ToArray()
            $ms.Dispose()
            return $bytes
        }

        function Get-DbJarmAlpnExtension {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Probe
    )

    if ($Probe[6] -eq 'RARE_APLN') {
        $alpns = @(
            [byte[]](0x08,0x68,0x74,0x74,0x70,0x2f,0x30,0x2e,0x39),
            [byte[]](0x08,0x68,0x74,0x74,0x70,0x2f,0x31,0x2e,0x30),
            [byte[]](0x06,0x73,0x70,0x64,0x79,0x2f,0x31),
            [byte[]](0x06,0x73,0x70,0x64,0x79,0x2f,0x32),
            [byte[]](0x06,0x73,0x70,0x64,0x79,0x2f,0x33),
            [byte[]](0x03,0x68,0x32,0x63),
            [byte[]](0x02,0x68,0x71)
        )
    }
    else {
        $alpns = @(
            [byte[]](0x08,0x68,0x74,0x74,0x70,0x2f,0x30,0x2e,0x39),
            [byte[]](0x08,0x68,0x74,0x74,0x70,0x2f,0x31,0x2e,0x30),
            [byte[]](0x08,0x68,0x74,0x74,0x70,0x2f,0x31,0x2e,0x31),
            [byte[]](0x06,0x73,0x70,0x64,0x79,0x2f,0x31),
            [byte[]](0x06,0x73,0x70,0x64,0x79,0x2f,0x32),
            [byte[]](0x06,0x73,0x70,0x64,0x79,0x2f,0x33),
            [byte[]](0x02,0x68,0x32),
            [byte[]](0x03,0x68,0x32,0x63),
            [byte[]](0x02,0x68,0x71)
        )
    }

    if ($Probe[8] -ne 'FORWARD') {
        $alpns = @(Invoke-DbJarmMung -Items $alpns -Request $Probe[8])
    }

    $allAlpns = New-Object System.Collections.Generic.List[byte]
    foreach ($alpn in $alpns) {
        if ($null -eq $alpn) { continue }
        foreach ($b in [byte[]]$alpn) {
            [void]$allAlpns.Add($b)
        }
    }

    $alpnBytes = [byte[]]$allAlpns.ToArray()

    $ms = New-Object System.IO.MemoryStream
    Add-DbBytes -Stream $ms -Bytes ([byte[]](0x00,0x10))
    Add-DbBytes -Stream $ms -Bytes (Get-DbBigEndianUint16Bytes -Value ($alpnBytes.Length + 2))
    Add-DbBytes -Stream $ms -Bytes (Get-DbBigEndianUint16Bytes -Value $alpnBytes.Length)
    Add-DbBytes -Stream $ms -Bytes $alpnBytes

    $bytes = $ms.ToArray()
    $ms.Dispose()
    return $bytes
}

        function Get-DbJarmKeyShareExtension {
            param(
                [Parameter(Mandatory = $true)]
                [bool]$UseGrease
            )

            $shareExt = New-Object System.Collections.Generic.List[byte]
            if ($UseGrease) {
                foreach ($b in (Get-DbJarmGreaseValue)) {
                    [void]$shareExt.Add($b)
                }
                foreach ($b in [byte[]](0x00,0x01,0x00)) {
                    [void]$shareExt.Add($b)
                }
            }

            foreach ($b in [byte[]](0x00,0x1d)) {
                [void]$shareExt.Add($b)
            }
            foreach ($b in [byte[]](0x00,0x20)) {
                [void]$shareExt.Add($b)
            }
            foreach ($b in (Get-DbRandomBytes -Length 32)) {
                [void]$shareExt.Add($b)
            }

            $ms = New-Object System.IO.MemoryStream
            Add-DbBytes -Stream $ms -Bytes ([byte[]](0x00,0x33))
            Add-DbBytes -Stream $ms -Bytes (Get-DbBigEndianUint16Bytes -Value ($shareExt.Count + 2))
            Add-DbBytes -Stream $ms -Bytes (Get-DbBigEndianUint16Bytes -Value $shareExt.Count)
            Add-DbBytes -Stream $ms -Bytes ([byte[]]$shareExt.ToArray())

            $bytes = $ms.ToArray()
            $ms.Dispose()
            return $bytes
        }

       function Get-DbJarmSupportedVersionsExtension {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Probe,

        [Parameter(Mandatory = $true)]
        [bool]$UseGrease
    )

    if ($Probe[7] -eq '1.2_SUPPORT') {
        $tlsVersions = @(
            [byte[]](0x03,0x01),
            [byte[]](0x03,0x02),
            [byte[]](0x03,0x03)
        )
    }
    else {
        $tlsVersions = @(
            [byte[]](0x03,0x01),
            [byte[]](0x03,0x02),
            [byte[]](0x03,0x03),
            [byte[]](0x03,0x04)
        )
    }

    if ($Probe[8] -ne 'FORWARD') {
        $tlsVersions = @(Invoke-DbJarmMung -Items $tlsVersions -Request $Probe[8])
    }

    $versions = New-Object System.Collections.Generic.List[byte]

    if ($UseGrease) {
        foreach ($b in (Get-DbJarmGreaseValue)) {
            [void]$versions.Add($b)
        }
    }

    foreach ($version in $tlsVersions) {
        if ($null -eq $version) { continue }
        foreach ($b in [byte[]]$version) {
            [void]$versions.Add($b)
        }
    }

    $versionBytes = [byte[]]$versions.ToArray()

    $ms = New-Object System.IO.MemoryStream
    Add-DbBytes -Stream $ms -Bytes ([byte[]](0x00,0x2b))
    Add-DbBytes -Stream $ms -Bytes (Get-DbBigEndianUint16Bytes -Value ($versionBytes.Length + 1))
    Add-DbBytes -Stream $ms -Bytes ([byte[]]($versionBytes.Length))
    Add-DbBytes -Stream $ms -Bytes $versionBytes

    $bytes = $ms.ToArray()
    $ms.Dispose()
    return $bytes
}

        function Get-DbJarmExtensions {
            param(
                [Parameter(Mandatory = $true)]
                [object[]]$Probe
            )

            $allExtensions = New-Object System.Collections.Generic.List[byte]
            $grease = $false

            if ($Probe[5] -eq 'GREASE') {
                foreach ($b in (Get-DbJarmGreaseValue)) {
                    [void]$allExtensions.Add($b)
                }
                foreach ($b in [byte[]](0x00,0x00)) {
                    [void]$allExtensions.Add($b)
                }
                $grease = $true
            }

            foreach ($b in (Get-DbJarmServerNameExtension -TargetHost $Probe[0])) {
                [void]$allExtensions.Add($b)
            }
            foreach ($b in [byte[]](0x00,0x17,0x00,0x00)) {
                [void]$allExtensions.Add($b)
            }
            foreach ($b in [byte[]](0x00,0x01,0x00,0x01,0x01)) {
                [void]$allExtensions.Add($b)
            }
            foreach ($b in [byte[]](0xff,0x01,0x00,0x01,0x00)) {
                [void]$allExtensions.Add($b)
            }
            foreach ($b in [byte[]](0x00,0x0a,0x00,0x0a,0x00,0x08,0x00,0x1d,0x00,0x17,0x00,0x18,0x00,0x19)) {
                [void]$allExtensions.Add($b)
            }
            foreach ($b in [byte[]](0x00,0x0b,0x00,0x02,0x01,0x00)) {
                [void]$allExtensions.Add($b)
            }
            foreach ($b in [byte[]](0x00,0x23,0x00,0x00)) {
                [void]$allExtensions.Add($b)
            }
            foreach ($b in (Get-DbJarmAlpnExtension -Probe $Probe)) {
                [void]$allExtensions.Add($b)
            }
            foreach ($b in [byte[]](0x00,0x0d,0x00,0x14,0x00,0x12,0x04,0x03,0x08,0x04,0x04,0x01,0x05,0x03,0x08,0x05,0x05,0x01,0x08,0x06,0x06,0x01,0x02,0x01)) {
                [void]$allExtensions.Add($b)
            }
            foreach ($b in (Get-DbJarmKeyShareExtension -UseGrease $grease)) {
                [void]$allExtensions.Add($b)
            }
            foreach ($b in [byte[]](0x00,0x2d,0x00,0x02,0x01,0x01)) {
                [void]$allExtensions.Add($b)
            }

            if ($Probe[2] -eq 'TLS_1.3' -or $Probe[7] -eq '1.2_SUPPORT') {
                foreach ($b in (Get-DbJarmSupportedVersionsExtension -Probe $Probe -UseGrease $grease)) {
                    [void]$allExtensions.Add($b)
                }
            }

            $ms = New-Object System.IO.MemoryStream
            Add-DbBytes -Stream $ms -Bytes (Get-DbBigEndianUint16Bytes -Value $allExtensions.Count)
            Add-DbBytes -Stream $ms -Bytes ([byte[]]$allExtensions.ToArray())
            $bytes = $ms.ToArray()
            $ms.Dispose()
            return $bytes
        }

        function New-DbJarmPacket {
            param(
                [Parameter(Mandatory = $true)]
                [object[]]$Probe
            )

            $recordVersion = switch ($Probe[2]) {
                'TLS_1.3' { [byte[]](0x03,0x01) }
                'SSLv3'   { [byte[]](0x03,0x00) }
                'TLS_1'   { [byte[]](0x03,0x01) }
                'TLS_1.1' { [byte[]](0x03,0x02) }
                default   { [byte[]](0x03,0x03) }
            }

            $clientHelloVersion = switch ($Probe[2]) {
                'SSLv3'   { [byte[]](0x03,0x00) }
                'TLS_1'   { [byte[]](0x03,0x01) }
                'TLS_1.1' { [byte[]](0x03,0x02) }
                default   { [byte[]](0x03,0x03) }
            }

            $clientHello = New-Object System.IO.MemoryStream
            Add-DbBytes -Stream $clientHello -Bytes $clientHelloVersion
            Add-DbBytes -Stream $clientHello -Bytes (Get-DbRandomBytes -Length 32)

            $sessionId = Get-DbRandomBytes -Length 32
            Add-DbBytes -Stream $clientHello -Bytes ([byte[]]($sessionId.Length))
            Add-DbBytes -Stream $clientHello -Bytes $sessionId

            $cipherChoice = Get-DbJarmSelectedCiphers -Probe $Probe
            Add-DbBytes -Stream $clientHello -Bytes (Get-DbBigEndianUint16Bytes -Value $cipherChoice.Length)
            if ($null -eq $cipherChoice -or $cipherChoice.Length -eq 0) {
    throw "Cipher choice generation failed for probe: $($Probe -join ',')"
}
            Add-DbBytes -Stream $clientHello -Bytes $cipherChoice

            Add-DbBytes -Stream $clientHello -Bytes ([byte[]](0x01))
            Add-DbBytes -Stream $clientHello -Bytes ([byte[]](0x00))

            Add-DbBytes -Stream $clientHello -Bytes (Get-DbJarmExtensions -Probe $Probe)

            $clientHelloBytes = $clientHello.ToArray()
            $clientHello.Dispose()

            $handshake = New-Object System.IO.MemoryStream
            Add-DbBytes -Stream $handshake -Bytes ([byte[]](0x01))
            Add-DbBytes -Stream $handshake -Bytes (Get-DbBigEndianUint24Bytes -Value $clientHelloBytes.Length)
            Add-DbBytes -Stream $handshake -Bytes $clientHelloBytes
            $handshakeBytes = $handshake.ToArray()
            $handshake.Dispose()

            $record = New-Object System.IO.MemoryStream
            Add-DbBytes -Stream $record -Bytes ([byte[]](0x16))
            Add-DbBytes -Stream $record -Bytes $recordVersion
            Add-DbBytes -Stream $record -Bytes (Get-DbBigEndianUint16Bytes -Value $handshakeBytes.Length)
            Add-DbBytes -Stream $record -Bytes $handshakeBytes

            $packet = $record.ToArray()
            $record.Dispose()
            return $packet
        }

        function Send-DbJarmPacket {
            param(
                [Parameter(Mandatory = $true)]
                [byte[]]$Packet,

                [Parameter(Mandatory = $true)]
                [string]$TargetHost,

                [Parameter(Mandatory = $true)]
                [int]$Port
            )

            $resolvedIp = $null
            $client = $null
            try {
                $client = New-Object System.Net.Sockets.TcpClient
                $iar = $client.BeginConnect($TargetHost, $Port, $null, $null)
                if (-not $iar.AsyncWaitHandle.WaitOne(20000, $false)) {
                    throw [System.TimeoutException]::new("Connection timeout")
                }

                $client.EndConnect($iar)
                $resolvedIp = $client.Client.RemoteEndPoint.Address.ToString()

                $stream = $client.GetStream()
                $stream.ReadTimeout = 20000
                $stream.WriteTimeout = 20000
                $stream.Write($Packet, 0, $Packet.Length)

                $buffer = New-Object byte[] 1484
                $read = $stream.Read($buffer, 0, $buffer.Length)
                if ($read -le 0) {
                    return [pscustomobject]@{
                        Data = $null
                        IP   = $resolvedIp
                        Type = 'EMPTY'
                    }
                }

                $data = New-Object byte[] $read
                [Array]::Copy($buffer, 0, $data, 0, $read)

                return [pscustomobject]@{
                    Data = $data
                    IP   = $resolvedIp
                    Type = 'OK'
                }
            }
            catch [System.TimeoutException] {
                return [pscustomobject]@{
                    Data = $null
                    IP   = $resolvedIp
                    Type = 'TIMEOUT'
                }
            }
            catch {
                return [pscustomobject]@{
                    Data = $null
                    IP   = $resolvedIp
                    Type = 'ERROR'
                }
            }
            finally {
                if ($client) {
                    try { $client.Close() } catch {}
                }
            }
        }

        function Find-DbJarmExtensionValue {
            param(
                [Parameter(Mandatory = $true)]
                [string]$ExtensionTypeHex,

                [Parameter(Mandatory = $true)]
                [string[]]$Types,

                [Parameter(Mandatory = $true)]
                [object[]]$Values
            )

            for ($i = 0; $i -lt $Types.Count; $i++) {
                if ($Types[$i] -eq $ExtensionTypeHex) {
                    if ($ExtensionTypeHex -eq '0010') {
                        $val = $Values[$i]
                        if ($val -is [byte[]] -and $val.Length -ge 4) {
                            return [System.Text.Encoding]::ASCII.GetString($val, 3, $val.Length - 3)
                        }
                        return ""
                    }

                    $v = $Values[$i]
                    if ($v -is [byte[]]) {
                        return (ConvertTo-DbHex -Bytes $v)
                    }
                    return ""
                }
            }

            return ""
        }

        function Get-DbJarmExtensionsInfo {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Data,

        [Parameter(Mandatory = $true)]
        [int]$ExtensionsLengthOffset
    )

    try {
        if (($ExtensionsLengthOffset + 2) -gt $Data.Length) {
            return "|"
        }

        $extensionsLength = Get-DbUint16 -Data $Data -Offset $ExtensionsLengthOffset
        $offset = $ExtensionsLengthOffset + 2
        $endOffset = $offset + $extensionsLength

        if ($endOffset -gt $Data.Length) {
            $endOffset = $Data.Length
        }

        $types = New-Object System.Collections.Generic.List[string]
        $alpn = ""

        while (($offset + 4) -le $endOffset) {
            $extTypeBytes = Get-DbRangeBytes -Data $Data -Offset $offset -Length 2
            $extTypeHex = ConvertTo-DbHex -Bytes $extTypeBytes

            $extLen = Get-DbUint16 -Data $Data -Offset ($offset + 2)
            $extValueOffset = $offset + 4
            $extValueEnd = $extValueOffset + $extLen

            if ($extValueEnd -gt $endOffset) {
                break
            }

            [void]$types.Add($extTypeHex)

            # ALPN extension (0010)
            if ($extTypeHex -eq '0010' -and $extLen -ge 3) {
                # ServerHello ALPN ext_data is:
                #   2 bytes protocol_name_list_length
                #   1 byte protocol_name_length
                #   protocol bytes
                if (($extValueOffset + 3) -le $extValueEnd) {
                    $nameLen = [int]$Data[$extValueOffset + 2]
                    $nameOffset = $extValueOffset + 3

                    if (($nameOffset + $nameLen) -le $extValueEnd) {
                        $alpnBytes = Get-DbRangeBytes -Data $Data -Offset $nameOffset -Length $nameLen
                        $alpn = [System.Text.Encoding]::ASCII.GetString($alpnBytes)
                    }
                }
            }

            $offset = $extValueEnd
        }

        $extTypeString = ($types -join '-')
        return ($alpn + "|" + $extTypeString)
    }
    catch {
        return "|"
    }
}

        function Read-DbJarmServerHello {
    param(
        [AllowNull()]
        [byte[]]$Data
    )

    try {
        if (-not $Data -or $Data.Length -lt 50) {
            return "|||"
        }

        # TLS Alert
        if ($Data[0] -eq 21) {
            return "|||"
        }

        # TLS Handshake record + ServerHello
        if ($Data[0] -ne 22 -or $Data[5] -ne 2) {
            return "|||"
        }

        $recordLength = Get-DbUint16 -Data $Data -Offset 3
        if (($recordLength + 5) -gt $Data.Length) {
            $recordLength = $Data.Length - 5
        }

        # Handshake body starts at offset 9:
        # 5 record header + 4 handshake header
        $bodyOffset = 9

        # ServerHello version
        $version = ConvertTo-DbHex -Bytes (Get-DbRangeBytes -Data $Data -Offset $bodyOffset -Length 2)

        # Random = 32 bytes
        $sessionIdLenOffset = $bodyOffset + 2 + 32
        $sessionIdLength = [int]$Data[$sessionIdLenOffset]

        $cipherOffset = $sessionIdLenOffset + 1 + $sessionIdLength
        if (($cipherOffset + 2) -gt $Data.Length) {
            return "|||"
        }

        $selectedCipher = ConvertTo-DbHex -Bytes (Get-DbRangeBytes -Data $Data -Offset $cipherOffset -Length 2)

        # compression method is 1 byte after cipher
        $extensionsLengthOffset = $cipherOffset + 2 + 1
        if (($extensionsLengthOffset + 2) -gt $Data.Length) {
            return ($selectedCipher + "|" + $version + "||")
        }

        $extensionsInfo = Get-DbJarmExtensionsInfo -Data $Data -ExtensionsLengthOffset $extensionsLengthOffset

        return ($selectedCipher + "|" + $version + "|" + $extensionsInfo)
    }
    catch {
        return "|||"
    }
}

        function Get-DbJarmCipherBytes {
            param(
                [AllowEmptyString()]
                [string]$Cipher
            )

            if ([string]::IsNullOrEmpty($Cipher)) {
                return "00"
            }

            $list = @(
                '0004','0005','0007','000a','0016','002f','0033','0035','0039','003c','003d','0041','0045','0067','006b',
                '0084','0088','009a','009c','009d','009e','009f','00ba','00be','00c0','00c4','c007','c008','c009','c00a',
                'c011','c012','c013','c014','c023','c024','c027','c028','c02b','c02c','c02f','c030','c060','c061','c072',
                'c073','c076','c077','c09c','c09d','c09e','c09f','c0a0','c0a1','c0a2','c0a3','c0ac','c0ad','c0ae','c0af',
                'cc13','cc14','cca8','cca9','1301','1302','1303','1304','1305'
            )

            $count = 1
            foreach ($item in $list) {
                if ($Cipher -eq $item) {
                    break
                }
                $count++
            }

            return ('{0:x2}' -f $count)
        }

        function Get-DbJarmVersionByte {
            param(
                [AllowEmptyString()]
                [string]$Version
            )

            if ([string]::IsNullOrEmpty($Version)) {
                return "0"
            }

            $options = "abcdef"
            $count = [int]::Parse($Version.Substring(3,1))
            return $options[$count]
        }

        function Get-DbJarmHash {
            param(
                [Parameter(Mandatory = $true)]
                [string]$JarmRaw
            )

            if ($JarmRaw -eq "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||") {
                return ("0" * 62)
            }

            $fuzzyHash = ""
            $alpnsAndExt = ""
            $handshakes = $JarmRaw.Split(',')

            foreach ($handshake in $handshakes) {
                $components = $handshake.Split('|')
                $cipherPart = if ($components.Length -gt 0) { $components[0] } else { "" }
                $versionPart = if ($components.Length -gt 1) { $components[1] } else { "" }
                $alpnPart = if ($components.Length -gt 2) { $components[2] } else { "" }
                $extPart = if ($components.Length -gt 3) { $components[3] } else { "" }

                $fuzzyHash += (Get-DbJarmCipherBytes -Cipher $cipherPart)
                $fuzzyHash += (Get-DbJarmVersionByte -Version $versionPart)
                $alpnsAndExt += $alpnPart
                $alpnsAndExt += $extPart
            }

            $sha = ConvertTo-DbSha256Hex -InputString $alpnsAndExt
            return ($fuzzyHash + $sha.Substring(0, 32))
        }

        function Get-DbJarmFingerprint {
            param(
                [Parameter(Mandatory = $true)]
                [string]$TargetHost,

                [int]$Port = 443
            )

            $probes = @(
                @($TargetHost, $Port, "TLS_1.2", "ALL",   "FORWARD",    "NO_GREASE", "APLN",      "1.2_SUPPORT", "REVERSE"),
                @($TargetHost, $Port, "TLS_1.2", "ALL",   "REVERSE",    "NO_GREASE", "APLN",      "1.2_SUPPORT", "FORWARD"),
                @($TargetHost, $Port, "TLS_1.2", "ALL",   "TOP_HALF",   "NO_GREASE", "APLN",      "NO_SUPPORT",  "FORWARD"),
                @($TargetHost, $Port, "TLS_1.2", "ALL",   "BOTTOM_HALF","NO_GREASE", "RARE_APLN", "NO_SUPPORT",  "FORWARD"),
                @($TargetHost, $Port, "TLS_1.2", "ALL",   "MIDDLE_OUT", "GREASE",    "RARE_APLN", "NO_SUPPORT",  "REVERSE"),
                @($TargetHost, $Port, "TLS_1.1", "ALL",   "FORWARD",    "NO_GREASE", "APLN",      "NO_SUPPORT",  "FORWARD"),
                @($TargetHost, $Port, "TLS_1.3", "ALL",   "FORWARD",    "NO_GREASE", "APLN",      "1.3_SUPPORT", "REVERSE"),
                @($TargetHost, $Port, "TLS_1.3", "ALL",   "REVERSE",    "NO_GREASE", "APLN",      "1.3_SUPPORT", "FORWARD"),
                @($TargetHost, $Port, "TLS_1.3", "NO1.3", "FORWARD",    "NO_GREASE", "APLN",      "1.3_SUPPORT", "FORWARD"),
                @($TargetHost, $Port, "TLS_1.3", "ALL",   "MIDDLE_OUT", "GREASE",    "APLN",      "1.3_SUPPORT", "REVERSE")
            )

            $rawResponses = New-Object System.Collections.Generic.List[string]
            $resolvedIp = $null
            $timedOut = $false

            foreach ($probe in $probes) {
                $packet = New-DbJarmPacket -Probe $probe
                $response = Send-DbJarmPacket -Packet $packet -TargetHost $TargetHost -Port $Port
                if ($response.IP) {
                    $resolvedIp = $response.IP
                }

                if ($response.Type -eq 'TIMEOUT') {
                    $timedOut = $true
                    break
                }

                $raw = Read-DbJarmServerHello -Data $response.Data
                [void]$rawResponses.Add($raw)
            }

            $rawString = if ($timedOut) {
                "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||"
            }
            else {
                ($rawResponses -join ',')
            }

            $jarmHash = Get-DbJarmHash -JarmRaw $rawString

            return [pscustomobject][ordered]@{
                Host        = $TargetHost
                Port        = $Port
                ResolvedIP  = $resolvedIp
                Raw         = $rawString
                Jarm        = $jarmHash
                TimedOut    = $timedOut
                ProbeCount  = 10
                Responses   = if ($timedOut) { @() } else { @($rawResponses) }
            }
        }

        function Get-DbHeaderSummary {
            param(
                [hashtable]$Headers
            )

            if (-not $Headers) {
                return [ordered]@{}
            }

            $interesting = @(
                'Server',
                'WWW-Authenticate',
                'X-Powered-By',
                'Via',
                'Content-Type',
                'Content-Length',
                'ETag',
                'Last-Modified'
            )

            $summary = [ordered]@{}
            foreach ($name in $interesting) {
                if ($Headers.ContainsKey($name)) {
                    $summary[$name] = $Headers[$name]
                }
            }

            return $summary
        }
    }

    process {
        $uriInfo = Get-DbUriInfo -InputUrl $Url

        $resolvedIps = if ($uriInfo.IsIpAddress) {
            @($uriInfo.Host)
        }
        else {
            Resolve-DbHostToIp -TargetHost $uriInfo.Host
        }

        $defaultJarmPort = if ($uriInfo.Scheme -eq 'https') { $uriInfo.Port } else { 443 }
        $jarm = Get-DbJarmFingerprint -TargetHost $uriInfo.Host -Port $defaultJarmPort

        if ($JarmOnly) {
            return [pscustomobject][ordered]@{
                TargetType           = 'DBWebSiteFingerprint'
                Url                  = $Url
                Host                 = $uriInfo.Host
                Scheme               = $uriInfo.Scheme
                Port                 = $uriInfo.Port
                ResolvedIPs          = @($resolvedIps)
                JarmOnly             = $true
                TimestampUtc         = [DateTime]::UtcNow.ToString('o')
                Tls                  = [pscustomobject][ordered]@{
                    JarmHash         = $jarm.Jarm
                    JarmRaw          = $jarm.Raw
                    JarmResolvedIP   = $jarm.ResolvedIP
                    JarmProbeCount   = $jarm.ProbeCount
                    TimedOut         = $jarm.TimedOut
                    Responses        = @($jarm.Responses)
                }
                CompositeFingerprint = if ($jarm.Jarm) { ConvertTo-DbSha256Hex -InputString $jarm.Jarm } else { $null }
            }
        }

        $httpResult = Invoke-DbHttpRequest -Uri $uriInfo.Uri

        $title = $null
        $directoryListing = $false
        $extractedUrls = @()
        $fileInventory = @()
        $headerSummary = [ordered]@{}
        $serverBanner = $null
        $bodySha256 = $null
        $bodyFingerprint = $null
        $urlFingerprint = $null
        $httpFingerprint = $null

        if ($httpResult.Success -or $httpResult.Body) {
            $headerSummary = Get-DbHeaderSummary -Headers $httpResult.Headers

            if ($httpResult.Headers.ContainsKey('Server')) {
                $serverBanner = ConvertTo-DbNormalizedText -Text $httpResult.Headers['Server']
            }

            $title = Get-DbHtmlTitle -Html $httpResult.Body
            $directoryListing = Test-DbDirectoryListing -Content $httpResult.Body
            $extractedUrls = Get-DbExtractedUrls -Content ($httpResult.Body | Out-String) -BaseUri $httpResult.ResponseUri
            $fileInventory = Get-DbFileInventory -Urls $extractedUrls

            $normalizedBody = ConvertTo-DbBodyFingerprintText -Text $httpResult.Body
            $bodySha256 = ConvertTo-DbSha256Hex -InputString $normalizedBody

            $bodyFingerprintText = @(
                "title=$title"
                "server=$serverBanner"
                "status=$($httpResult.StatusCode)"
                "contenttype=$($httpResult.ContentType)"
                "directorylisting=$directoryListing"
                "body=$bodySha256"
            ) -join '|'

            $bodyFingerprint = ConvertTo-DbSha256Hex -InputString $bodyFingerprintText

            $normalizedUrlTokens = @(
                $extractedUrls |
                ForEach-Object {
                    try {
                        $u = [System.Uri]$_
                        "$($u.Host.ToLowerInvariant())$($u.AbsolutePath.ToLowerInvariant())"
                    }
                    catch {
                    }
                } |
                Sort-Object -Unique
            )

            $urlFingerprint = ConvertTo-DbSha256Hex -InputString (($normalizedUrlTokens -join '|'))

            $fileInventoryTokens = @(
                $fileInventory |
                ForEach-Object { $_.Path } |
                Sort-Object -Unique
            )

            $httpFingerprintSource = @(
                "server=$serverBanner"
                "title=$title"
                "status=$($httpResult.StatusCode)"
                "contenttype=$($httpResult.ContentType)"
                "directorylisting=$directoryListing"
                "bodyfp=$bodyFingerprint"
                "urlfp=$urlFingerprint"
                "filesfp=$(ConvertTo-DbSha256Hex -InputString (($fileInventoryTokens -join '|')))"
            ) -join '|'

            $httpFingerprint = ConvertTo-DbSha256Hex -InputString $httpFingerprintSource
        }

        $portResults = @()
        if ($Ports) {
            foreach ($port in ($Ports | Sort-Object -Unique)) {
                $portResults += Get-DbTcpBanner -TargetHost $uriInfo.Host -Port $port
            }
        }

        $portFingerprint = $null
        if ($portResults.Count -gt 0) {
            $portTokens = @(
                $portResults |
                ForEach-Object {
                    $bannerPart = if ($_.Banner) { $_.Banner } else { '' }
                    "$($_.Port)|$($_.Service)|$bannerPart|$($_.Connected)"
                } |
                Sort-Object -Unique
            )
            $portFingerprint = ConvertTo-DbSha256Hex -InputString (($portTokens -join '|'))
        }

        $whoisTarget = if ($resolvedIps.Count -gt 0) { $resolvedIps[0] } else { $uriInfo.Host }
        $whoisInfo = Get-DbWhoisInfo -Target $whoisTarget

        $compositeSource = @(
            'v2'
            "host=$($uriInfo.Host.ToLowerInvariant())"
            "scheme=$($uriInfo.Scheme.ToLowerInvariant())"
            "jarm=$($jarm.Jarm)"
            "http=$httpFingerprint"
            "body=$bodyFingerprint"
            "urls=$urlFingerprint"
            "ports=$portFingerprint"
            "provider=$($whoisInfo.Fingerprint)"
        ) -join '|'

        $compositeFingerprint = ConvertTo-DbSha256Hex -InputString $compositeSource

        [pscustomobject][ordered]@{
            TargetType           = 'DBWebSiteFingerprint'
            Url                  = $Url
            Host                 = $uriInfo.Host
            Scheme               = $uriInfo.Scheme
            Port                 = $uriInfo.Port
            IsIpAddress          = $uriInfo.IsIpAddress
            ResolvedIPs          = @($resolvedIps)
            TimestampUtc         = [DateTime]::UtcNow.ToString('o')

            Http                 = [pscustomobject][ordered]@{
                Success             = $httpResult.Success
                StatusCode          = $httpResult.StatusCode
                StatusDescription   = $httpResult.StatusDescription
                FinalUrl            = if ($httpResult.ResponseUri) { $httpResult.ResponseUri.AbsoluteUri } else { $null }
                ContentType         = $httpResult.ContentType
                ServerBanner        = $serverBanner
                Title               = $title
                DirectoryListing    = $directoryListing
                HeaderSummary       = [pscustomobject]$headerSummary
                ExtractedUrls       = @($extractedUrls)
                FileInventory       = @($fileInventory)
                BodySha256          = $bodySha256
                BodyFingerprint     = $bodyFingerprint
                UrlFingerprint      = $urlFingerprint
                HttpFingerprint     = $httpFingerprint
                Error               = $httpResult.Error
            }

            Tls                  = [pscustomobject][ordered]@{
                JarmHash           = $jarm.Jarm
                JarmRaw            = $jarm.Raw
                JarmResolvedIP     = $jarm.ResolvedIP
                JarmProbeCount     = $jarm.ProbeCount
                TimedOut           = $jarm.TimedOut
                Responses          = @($jarm.Responses)
            }

            Network              = [pscustomobject][ordered]@{
                Ports              = @($Ports | Sort-Object -Unique)
                BannerResults      = @($portResults)
                PortFingerprint    = $portFingerprint
            }

            Provider             = $whoisInfo
            CompositeFingerprint = $compositeFingerprint
        }
    }
}