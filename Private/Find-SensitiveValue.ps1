# Compiled once at module load — matched case-insensitively on every leaf key name
$script:SensitiveKeyPattern = [System.Text.RegularExpressions.Regex]::new(
    '^.*(password|secret|token|key|apikey|api_key|auth|credential|private).*$',
    ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled)
)

function Find-SensitiveValue {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [object] $Value,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $KeyName
    )

    if ($null -eq $Value -or $Value -is [bool]) {
        return $null
    }

    $isStringValue = $Value -is [string]
    $stringVal     = if ($isStringValue) { $Value } else { [string]$Value }

    # --- Key-name heuristic (highest priority) ---
    if ($script:SensitiveKeyPattern.IsMatch($KeyName)) {
        return [PSCustomObject]@{
            DetectedType = 'KeyNameMatch'
            MatchedValue = $stringVal
        }
    }

    # --- Only apply pattern/entropy checks to string values ---
    if (-not $isStringValue) {
        return $null
    }

    if ([string]::IsNullOrWhiteSpace($stringVal)) {
        return $null
    }

    # JWT / Bearer token
    if ($stringVal -match '^Bearer\s+\S+' -or $stringVal -match '^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+') {
        return [PSCustomObject]@{
            DetectedType = 'BearerToken'
            MatchedValue = $stringVal
        }
    }

    # Email address
    if ($stringVal -match '^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$') {
        return [PSCustomObject]@{
            DetectedType = 'Email'
            MatchedValue = $stringVal
        }
    }

    # URL with embedded credentials  (scheme://user:pass@host)
    if ($stringVal -match '^[a-zA-Z][a-zA-Z0-9+\-.]*://[^:@/\s]+:[^@/\s]+@') {
        return [PSCustomObject]@{
            DetectedType = 'CredentialUrl'
            MatchedValue = $stringVal
        }
    }

    # IPv4 address
    if ($stringVal -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        return [PSCustomObject]@{
            DetectedType = 'IpAddress'
            MatchedValue = $stringVal
        }
    }

    # US phone number
    if ($stringVal -match '^\+?1?[\s.\-]?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}$') {
        return [PSCustomObject]@{
            DetectedType = 'PhoneNumber'
            MatchedValue = $stringVal
        }
    }

    # Social Security Number
    if ($stringVal -match '^\d{3}-\d{2}-\d{4}$') {
        return [PSCustomObject]@{
            DetectedType = 'SSN'
            MatchedValue = $stringVal
        }
    }

    # Credit card (Luhn-validated, 13–19 digits, optional spaces/dashes)
    $ccDigits = $stringVal -replace '[\s\-]', ''
    if ($ccDigits -match '^\d{13,19}$' -and (Test-LuhnChecksum -Number $ccDigits)) {
        return [PSCustomObject]@{
            DetectedType = 'CreditCard'
            MatchedValue = $stringVal
        }
    }

    # Multi-label hostname / internal FQDN  (e.g. server01.corp.contoso.local)
    # Must have at least two labels, no spaces, no slashes, and not already matched as IP
    if ($stringVal -match '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?){1,}$' `
        -and $stringVal -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        return [PSCustomObject]@{
            DetectedType = 'Hostname'
            MatchedValue = $stringVal
        }
    }

    # High-entropy string (potential API key / secret)
    if ($stringVal.Length -ge 20 -and (Get-ShannonEntropy -InputString $stringVal) -gt 3.5) {
        return [PSCustomObject]@{
            DetectedType = 'HighEntropyString'
            MatchedValue = $stringVal
        }
    }

    return $null
}

function Get-ShannonEntropy {
    [CmdletBinding()]
    [OutputType([double])]
    param(
        [Parameter(Mandatory)]
        [string] $InputString
    )

    $length = $InputString.Length
    if ($length -eq 0) { return 0.0 }

    $freq = @{}
    foreach ($char in $InputString.ToCharArray()) {
        $key = [string]$char
        if ($freq.ContainsKey($key)) { $freq[$key]++ } else { $freq[$key] = 1 }
    }

    $entropy = 0.0
    foreach ($count in $freq.Values) {
        $p = $count / $length
        $entropy -= $p * [System.Math]::Log($p, 2)
    }

    return $entropy
}

function Test-LuhnChecksum {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Number
    )

    $digits  = $Number.ToCharArray() | ForEach-Object { [int]::Parse($_) }
    $sum     = 0
    $doubled = $false

    for ($i = $digits.Length - 1; $i -ge 0; $i--) {
        $d = $digits[$i]
        if ($doubled) {
            $d *= 2
            if ($d -gt 9) { $d -= 9 }
        }
        $sum    += $d
        $doubled = -not $doubled
    }

    return ($sum % 10 -eq 0)
}
