@{
    ModuleVersion        = '1.0.0'
    GUID                 = '39291151-df9e-49e7-b9b5-ffb18b230518'
    Author               = 'Peach Security'
    CompanyName          = 'Peach Security'
    Copyright            = '(c) 2026 Peach Security. All rights reserved.'
    Description          = 'Sanitize sensitive data from JSON before pasting into AI tools. Runs entirely locally — no network calls, no cloud upload.'
    PowerShellVersion    = '5.1'

    RootModule           = 'PeachSanitize.psm1'
    FunctionsToExport    = @('Invoke-JsonSanitize')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    ScriptsToProcess     = @()
    TypesToProcess       = @()
    FormatsToProcess     = @()
    NestedModules        = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('JSON', 'Security', 'Sanitize', 'MSP', 'AI', 'DLP', 'Privacy', 'PII')
            LicenseUri   = 'https://github.com/Peach-Security/PeachSanitize/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/Peach-Security/PeachSanitize'
            ReleaseNotes = 'Initial release. Detects and replaces emails, API keys, tokens, IP addresses, phone numbers, SSNs, credit card numbers, and credentials embedded in JSON before the payload is shared with AI tools.'
        }
    }
}
