function Invoke-JsonSanitize {
    <#
    .SYNOPSIS
        Sanitize sensitive values from a JSON payload before sharing it with AI tools.

    .DESCRIPTION
        Invoke-JsonSanitize parses a JSON string or file, detects sensitive values
        (API keys, tokens, email addresses, IP addresses, phone numbers, SSNs, credit
        card numbers, credentials in URLs, and hostnames), replaces each with a
        realistic-looking fake equivalent, and returns valid JSON with the original
        structure intact.

        Everything runs locally. No data is sent over the network.

    .PARAMETER InputObject
        A JSON string to sanitize. Accepts pipeline input.

    .PARAMETER Path
        Path to a JSON file to read and sanitize.

    .PARAMETER DryRun
        Display a table of detected values and their proposed replacements without
        modifying anything. Nothing is written to stdout or OutFile.

    .PARAMETER OutFile
        Write the sanitized JSON to this file path instead of stdout.

    .EXAMPLE
        Invoke-JsonSanitize -Path ./response.json

        Reads response.json, sanitizes it, and prints the result to stdout.

    .EXAMPLE
        Get-Content ./payload.json -Raw | Invoke-JsonSanitize

        Pipes raw JSON text through the sanitizer and prints the result to stdout.

    .EXAMPLE
        Invoke-JsonSanitize -Path ./payload.json -DryRun

        Shows a preview table of every replacement that would be made — no changes applied.

    .EXAMPLE
        Invoke-JsonSanitize -Path ./payload.json -OutFile ./payload.sanitized.json

        Writes the sanitized payload to a new file instead of printing to stdout.

    .EXAMPLE
        $json = '{"email":"alice@example.com","apiKey":"sk-abc123def456ghi789jkl0"}' | Invoke-JsonSanitize

        Sanitizes a JSON string stored in a variable.

    .INPUTS
        System.String

    .OUTPUTS
        System.String. Sanitized JSON (unless -DryRun is specified, in which case
        nothing is written to the output stream).

    .NOTES
        Install from PSGallery:
            Install-Module PeachSanitize
            Import-Module PeachSanitize

        Detection covers: email, API keys/tokens (Shannon entropy), OAuth/JWT tokens,
        Bearer tokens, IPv4 addresses, URLs with embedded credentials, US phone numbers,
        SSNs, credit card numbers (Luhn-validated), hostnames/FQDNs, and any value
        whose key name contains a sensitive keyword (password, secret, token, key, etc.).

        This is the manual, local equivalent of what Peach Security does automatically
        at the browser layer across all your clients. Learn more at peachsecurity.io.
    #>
    [CmdletBinding(DefaultParameterSetName = 'String', SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'String', ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string] $InputObject,

        [Parameter(Mandatory, ParameterSetName = 'File')]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [Parameter()]
        [switch] $DryRun,

        [Parameter()]
        [string] $OutFile
    )

    begin {
        $jsonChunks = [System.Collections.Generic.List[string]]::new()
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'String') {
            $jsonChunks.Add($InputObject)
        }
    }

    end {
        try {
            # Resolve the raw JSON string
            if ($PSCmdlet.ParameterSetName -eq 'File') {
                $fullPath = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

                if (-not [System.IO.File]::Exists($fullPath)) {
                    $ex = [System.IO.FileNotFoundException]::new(
                        "File not found: '$fullPath'.")
                    $PSCmdlet.ThrowTerminatingError(
                        [System.Management.Automation.ErrorRecord]::new(
                            $ex, 'FileNotFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $fullPath))
                }

                $fileInfo = [System.IO.FileInfo]::new($fullPath)
                if ($fileInfo.Length -gt 1MB) {
                    $PSCmdlet.WriteWarning('Large file detected - processing may be slow.')
                }

                $rawJson = [System.IO.File]::ReadAllText($fullPath, [System.Text.Encoding]::UTF8)
            }
            else {
                $rawJson = $jsonChunks -join ''
            }

            # Validate JSON
            $parsed = $null
            try {
                $parsed = $rawJson | ConvertFrom-Json
            }
            catch {
                $ex = [System.ArgumentException]::new(
                    'Input is not valid JSON. Verify with ConvertFrom-Json before running.')
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::new(
                        $ex, 'InvalidJson', [System.Management.Automation.ErrorCategory]::InvalidData, $rawJson))
            }

            # Walk the object tree
            $walkResult = Invoke-ValueReplacement -InputObject $parsed -KeyPath ''
            $findings   = $walkResult.Findings
            $sanitized  = $walkResult.Object

            Write-Verbose ('{0} sensitive value(s) detected across {1} type(s).' -f
                $findings.Count,
                ($findings | Select-Object -ExpandProperty DetectedType -Unique | Measure-Object).Count)

            # DryRun — table only, no output
            if ($DryRun) {
                if ($findings.Count -eq 0) {
                    Write-Host 'No sensitive values detected.'
                    return
                }
                $findings | Format-Table -Property KeyPath, DetectedType, OriginalValue, ProposedReplacement -AutoSize | Out-Host
                return
            }

            $outputJson = $sanitized | ConvertTo-Json -Depth 100

            if ($OutFile) {
                if ($PSCmdlet.ShouldProcess($OutFile, 'Write sanitized JSON')) {
                    $outResolved = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
                    try {
                        [System.IO.File]::WriteAllText($outResolved, $outputJson, [System.Text.Encoding]::UTF8)
                        Write-Verbose "Sanitized JSON written to: $outResolved"
                    }
                    catch [System.UnauthorizedAccessException] {
                        $ex = [System.UnauthorizedAccessException]::new(
                            "Cannot write to '$outResolved' - access denied.")
                        $PSCmdlet.ThrowTerminatingError(
                            [System.Management.Automation.ErrorRecord]::new(
                                $ex, 'OutFileAccessDenied', [System.Management.Automation.ErrorCategory]::PermissionDenied, $outResolved))
                    }
                    catch [System.IO.IOException] {
                        $ex = [System.IO.IOException]::new(
                            "Failed to write output file '$outResolved': $($_.Exception.Message)")
                        $PSCmdlet.ThrowTerminatingError(
                            [System.Management.Automation.ErrorRecord]::new(
                                $ex, 'OutFileWriteError', [System.Management.Automation.ErrorCategory]::WriteError, $outResolved))
                    }
                }
            }
            else {
                $outputJson
            }
        }
        catch {
            throw
        }
    }
}
