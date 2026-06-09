function New-FakeReplacement {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $DetectedType,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $OriginalValue
    )

    # Seed with a new GUID on each call so outputs are unpredictable
    $rng = [System.Random]::new([System.Math]::Abs([System.BitConverter]::ToInt32([System.Guid]::NewGuid().ToByteArray(), 0)))

    switch ($DetectedType) {
        'Email'            { return New-FakeEmail -Rng $rng }
        'IpAddress'        { return New-FakeIp -Rng $rng }
        'PhoneNumber'      { return '(555) 000-{0:D4}' -f $rng.Next(0, 9999) }
        'SSN'              { return '000-00-{0:D4}' -f $rng.Next(0, 9999) }
        'CreditCard'       { return '4111111111111{0:D4}' -f $rng.Next(1000, 9999) }
        'BearerToken'      { return New-FakeToken -OriginalValue $OriginalValue -Rng $rng }
        'CredentialUrl'    { return New-FakeCredentialUrl -OriginalValue $OriginalValue -Rng $rng }
        'Hostname'         { return 'internal-host-{0}.local' -f (New-RandomString -Charset 'abcdefghijklmnopqrstuvwxyz0123456789' -Length 6 -Rng $rng) }
        'HighEntropyString'{ return New-FakeApiKey -OriginalValue $OriginalValue -Rng $rng }
        'KeyNameMatch'     { return '[REDACTED-KEYNAME-{0}]' -f (New-RandomString -Charset 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' -Length 32 -Rng $rng) }
        default            { return '[REDACTED]' }
    }
}

function New-FakeEmail {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [System.Random] $Rng)

    $firstNames = @(
        'alex','blake','casey','dana','drew','emery','finley','harper',
        'jamie','jordan','kendall','logan','morgan','parker','quinn',
        'reese','riley','sage','skyler','taylor'
    )
    $domains = @('fakecorp.io', 'testmsp.net', 'sampleco.org', 'demolab.dev', 'sandboxco.net')

    $name   = $firstNames[$Rng.Next(0, $firstNames.Count)]
    $suffix = $Rng.Next(10, 999)
    $domain = $domains[$Rng.Next(0, $domains.Count)]

    return '{0}{1}@{2}' -f $name, $suffix, $domain
}

function New-FakeIp {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [System.Random] $Rng)

    return '192.168.{0}.{1}' -f $Rng.Next(0, 255), $Rng.Next(1, 254)
}

function New-FakeToken {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string]       $OriginalValue,
        [Parameter(Mandatory)] [System.Random] $Rng
    )

    $suffix = New-RandomString -Charset 'abcdef0123456789' -Length 8 -Rng $Rng
    $targetLen = [System.Math]::Max(16, [System.Math]::Min($OriginalValue.Length, 64))
    return '[REDACTED-TOKEN-{0}]' -f $suffix.PadRight($targetLen - 18).Substring(0, [System.Math]::Max(0, $targetLen - 18))
}

function New-FakeCredentialUrl {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string]       $OriginalValue,
        [Parameter(Mandatory)] [System.Random] $Rng
    )

    # Replace only the user:pass portion, preserve scheme and host
    $fakeUser = New-RandomString -Charset 'abcdefghijklmnopqrstuvwxyz' -Length 8 -Rng $Rng
    $fakePass = New-RandomString -Charset 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' -Length 16 -Rng $Rng

    return [System.Text.RegularExpressions.Regex]::Replace(
        $OriginalValue,
        '(?<=://)[^:@/\s]+:[^@/\s]+(?=@)',
        ('{0}:{1}' -f $fakeUser, $fakePass)
    )
}

function New-FakeApiKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string]       $OriginalValue,
        [Parameter(Mandatory)] [System.Random] $Rng
    )

    $charset = Resolve-ApiKeyCharset -Sample $OriginalValue
    return New-RandomString -Charset $charset -Length $OriginalValue.Length -Rng $Rng
}

function Resolve-ApiKeyCharset {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Sample
    )

    if ($Sample -match '^[0-9a-f]+$')                              { return '0123456789abcdef' }
    if ($Sample -match '^[0-9A-F]+$')                              { return '0123456789ABCDEF' }
    if ($Sample -match '^[A-Za-z0-9+/]+=*$' -and $Sample.Length % 4 -eq 0) { return 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' }
    if ($Sample -match '^[A-Za-z0-9_-]+$')                        { return 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-' }
    return 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
}

function New-RandomString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string]       $Charset,
        [Parameter(Mandatory)] [int]          $Length,
        [Parameter(Mandatory)] [System.Random] $Rng
    )

    $sb = [System.Text.StringBuilder]::new($Length)
    for ($i = 0; $i -lt $Length; $i++) {
        $null = $sb.Append($Charset[$Rng.Next(0, $Charset.Length)])
    }
    return $sb.ToString()
}
