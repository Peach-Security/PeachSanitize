BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    . "$moduleRoot\Private\Find-SensitiveValue.ps1"
}

Describe 'Find-SensitiveValue' {

    Context 'Passthrough — values that should never be flagged' {
        It 'returns $null for a null value' {
            Find-SensitiveValue -Value $null -KeyName 'field' | Should -BeNullOrEmpty
        }

        It 'returns $null for a boolean true' {
            Find-SensitiveValue -Value $true -KeyName 'enabled' | Should -BeNullOrEmpty
        }

        It 'returns $null for a boolean false' {
            Find-SensitiveValue -Value $false -KeyName 'active' | Should -BeNullOrEmpty
        }

        It 'returns $null for a plain short string' {
            Find-SensitiveValue -Value 'hello' -KeyName 'label' | Should -BeNullOrEmpty
        }

        It 'returns $null for an empty string' {
            Find-SensitiveValue -Value '' -KeyName 'notes' | Should -BeNullOrEmpty
        }
    }

    Context 'Key-name heuristic' {
        It 'flags a value when key contains "password"' {
            $r = Find-SensitiveValue -Value 'N/A' -KeyName 'password'
            $r.DetectedType | Should -Be 'KeyNameMatch'
        }

        It 'flags a value when key contains "secret" (case-insensitive)' {
            $r = Find-SensitiveValue -Value 'some-value' -KeyName 'ClientSecret'
            $r.DetectedType | Should -Be 'KeyNameMatch'
        }

        It 'flags a value when key contains "api_key"' {
            $r = Find-SensitiveValue -Value 'anything' -KeyName 'api_key'
            $r.DetectedType | Should -Be 'KeyNameMatch'
        }

        It 'flags a value when key contains "credential"' {
            $r = Find-SensitiveValue -Value 'anything' -KeyName 'storedCredential'
            $r.DetectedType | Should -Be 'KeyNameMatch'
        }

        It 'does not flag a value whose key is unrelated' {
            Find-SensitiveValue -Value 'N/A' -KeyName 'status' | Should -BeNullOrEmpty
        }
    }

    Context 'Email detection' {
        It 'detects a simple email address' {
            $r = Find-SensitiveValue -Value 'alice@example.com' -KeyName 'field'
            $r.DetectedType | Should -Be 'Email'
        }

        It 'detects an email with plus addressing' {
            $r = Find-SensitiveValue -Value 'user+tag@corp.io' -KeyName 'field'
            $r.DetectedType | Should -Be 'Email'
        }

        It 'does not flag a plain hostname as an email' {
            $result = Find-SensitiveValue -Value 'server.corp.local' -KeyName 'field'
            $result.DetectedType | Should -Not -Be 'Email'
        }
    }

    Context 'Bearer / JWT token detection' {
        It 'detects a Bearer token string when key name is neutral' {
            # Use a neutral key name; 'authorization' would trigger KeyNameMatch first
            $r = Find-SensitiveValue -Value 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig' -KeyName 'httpHeader'
            $r.DetectedType | Should -Be 'BearerToken'
        }

        It 'detects a raw JWT (ey... format) when key name is neutral' {
            $r = Find-SensitiveValue -Value 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.abc123DEF456' -KeyName 'jwtData'
            $r.DetectedType | Should -Be 'BearerToken'
        }

        It 'returns KeyNameMatch (not BearerToken) when key contains "auth"' {
            $r = Find-SensitiveValue -Value 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig' -KeyName 'authorization'
            $r.DetectedType | Should -Be 'KeyNameMatch'
        }
    }

    Context 'IPv4 detection' {
        It 'detects a private IP address' {
            $r = Find-SensitiveValue -Value '10.0.0.1' -KeyName 'field'
            $r.DetectedType | Should -Be 'IpAddress'
        }

        It 'detects a public IP address' {
            $r = Find-SensitiveValue -Value '203.0.113.5' -KeyName 'field'
            $r.DetectedType | Should -Be 'IpAddress'
        }
    }

    Context 'Phone number detection' {
        It 'detects US phone in (xxx) xxx-xxxx format' {
            $r = Find-SensitiveValue -Value '(212) 555-1234' -KeyName 'phone'
            $r.DetectedType | Should -Be 'PhoneNumber'
        }

        It 'detects US phone in xxx-xxx-xxxx format' {
            $r = Find-SensitiveValue -Value '212-555-1234' -KeyName 'phone'
            $r.DetectedType | Should -Be 'PhoneNumber'
        }

        It 'detects US phone with +1 prefix' {
            $r = Find-SensitiveValue -Value '+12125551234' -KeyName 'phone'
            $r.DetectedType | Should -Be 'PhoneNumber'
        }
    }

    Context 'SSN detection' {
        It 'detects a social security number' {
            $r = Find-SensitiveValue -Value '123-45-6789' -KeyName 'field'
            $r.DetectedType | Should -Be 'SSN'
        }
    }

    Context 'Credit card detection' {
        It 'detects a valid Visa card number' {
            # 4111111111111111 passes Luhn
            $r = Find-SensitiveValue -Value '4111111111111111' -KeyName 'field'
            $r.DetectedType | Should -Be 'CreditCard'
        }

        It 'does not flag a number that fails Luhn' {
            # 4111111111111112 is one digit off from the valid 4111111111111111 — fails Luhn
            Find-SensitiveValue -Value '4111111111111112' -KeyName 'field' | Should -BeNullOrEmpty
        }
    }

    Context 'URL with embedded credentials' {
        It 'detects credentials in a connection string' {
            $r = Find-SensitiveValue -Value 'postgres://dbuser:s3cr3t@db.internal.example.com/mydb' -KeyName 'dsn'
            $r.DetectedType | Should -Be 'CredentialUrl'
        }
    }

    Context 'Hostname / FQDN detection' {
        It 'detects an internal multi-label hostname' {
            $r = Find-SensitiveValue -Value 'fileserver01.corp.contoso.local' -KeyName 'target'
            $r.DetectedType | Should -Be 'Hostname'
        }
    }

    Context 'High-entropy string (API key) detection' {
        It 'detects a high-entropy hex string >= 20 chars' {
            $r = Find-SensitiveValue -Value 'a3f8c1e9d4b720e6f5a1' -KeyName 'field'
            $r.DetectedType | Should -Be 'HighEntropyString'
        }

        It 'does not flag a low-entropy string of the same length' {
            Find-SensitiveValue -Value 'aaaaaaaaaabbbbbbbbbb' -KeyName 'field' | Should -BeNullOrEmpty
        }

        It 'does not flag a string shorter than 20 chars' {
            Find-SensitiveValue -Value 'abc123XYZ9' -KeyName 'field' | Should -BeNullOrEmpty
        }
    }
}

Describe 'Test-LuhnChecksum' {
    It 'returns true for 4111111111111111' {
        Test-LuhnChecksum -Number '4111111111111111' | Should -BeTrue
    }

    It 'returns false for 4111111111111112' {
        Test-LuhnChecksum -Number '4111111111111112' | Should -BeFalse
    }
}

Describe 'Get-ShannonEntropy' {
    It 'returns 0 for a single-character string' {
        Get-ShannonEntropy -InputString 'aaaaaaaaaa' | Should -Be 0.0
    }

    It 'returns a value > 3.5 for a random hex string' {
        Get-ShannonEntropy -InputString 'a3f8c1e9d4b720e6f5a1' | Should -BeGreaterThan 3.5
    }
}
