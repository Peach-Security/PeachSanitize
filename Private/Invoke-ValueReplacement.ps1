function Invoke-ValueReplacement {
    <#
        Recursively walks a deserialized JSON object and replaces sensitive leaf values.
        Returns two outputs via a [hashtable]:
            .Object    - the sanitized object (same shape as input)
            .Findings  - [System.Collections.Generic.List[PSCustomObject]] of every replacement made
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $InputObject,

        [Parameter()]
        [string] $KeyPath = ''
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $result = Invoke-WalkNode -Node $InputObject -KeyPath $KeyPath -Findings $findings

    return @{
        Object   = $result
        Findings = $findings
    }
}

function Invoke-WalkNode {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $Node,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $KeyPath,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[PSCustomObject]] $Findings
    )

    if ($null -eq $Node -or $Node -is [bool]) {
        return $Node
    }

    # PowerShell 5 deserialises JSON objects as PSCustomObject
    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        $clone = [System.Management.Automation.PSObject]::new()
        foreach ($prop in $Node.PSObject.Properties) {
            $childPath = if ($KeyPath) { '{0}.{1}' -f $KeyPath, $prop.Name } else { $prop.Name }
            $sanitized = Invoke-WalkNode -Node $prop.Value -KeyPath $childPath -Findings $Findings
            $clone | Add-Member -MemberType NoteProperty -Name $prop.Name -Value $sanitized -Force
        }
        return $clone
    }

    # Arrays (PS 5: Object[], PS 7: also JsonElement arrays via ConvertFrom-Json)
    if ($Node -is [System.Array] -or $Node -is [System.Collections.IList]) {
        $output = [System.Collections.Generic.List[object]]::new()
        $index  = 0
        foreach ($item in $Node) {
            $childPath = '{0}[{1}]' -f $KeyPath, $index
            $output.Add((Invoke-WalkNode -Node $item -KeyPath $childPath -Findings $Findings))
            $index++
        }
        return $output.ToArray()
    }

    # Scalar — run detection
    $keyName = if ($KeyPath -match '\.?([^.\[\]]+)(\[\d+\])*$') { $Matches[1] } else { $KeyPath }
    $finding = Find-SensitiveValue -Value $Node -KeyName $keyName

    if ($null -ne $finding) {
        $original    = [string]$Node
        $replacement = New-FakeReplacement -DetectedType $finding.DetectedType -OriginalValue $original

        $Findings.Add([PSCustomObject]@{
            KeyPath            = $KeyPath
            DetectedType       = $finding.DetectedType
            OriginalValue      = if ($original.Length -gt 40) { $original.Substring(0, 37) + '...' } else { $original }
            ProposedReplacement = $replacement
        })

        return $replacement
    }

    return $Node
}
