BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    . "$moduleRoot\Private\New-FakeReplacement.ps1"
}

Describe 'New-FakeReplacement' {

    Context 'Email' {
        It 'returns a string that looks like an email' {
            $r = New-FakeReplacement -DetectedType 'Email' -OriginalValue 'alice@example.com'
            $r | Should -Match '^[a-z]+\d+@[a-z]+\.(io|net|org|dev)$'
        }

        It 'output is different from the input' {
            $r = New-FakeReplacement -DetectedType 'Email' -OriginalValue 'alice@example.com'
            $r | Should -Not -Be 'alice@example.com'
        }

        It 'does not use a real domain name' {
            $r = New-FakeReplacement -DetectedType 'Email' -OriginalValue 'user@gmail.com'
            $r | Should -Not -Match '@gmail\.com$'
            $r | Should -Not -Match '@microsoft\.com$'
        }
    }

    Context 'IpAddress' {
        It 'returns an IP in the 192.168.x.x range' {
            $r = New-FakeReplacement -DetectedType 'IpAddress' -OriginalValue '203.0.113.5'
            $r | Should -Match '^192\.168\.\d{1,3}\.\d{1,3}$'
        }

        It 'output differs from a public IP' {
            $r = New-FakeReplacement -DetectedType 'IpAddress' -OriginalValue '203.0.113.5'
            $r | Should -Not -Be '203.0.113.5'
        }
    }

    Context 'PhoneNumber' {
        It 'returns a 555 phone number' {
            $r = New-FakeReplacement -DetectedType 'PhoneNumber' -OriginalValue '(212) 555-1234'
            $r | Should -Match '^\(555\) 000-\d{4}$'
        }
    }

    Context 'SSN' {
        It 'returns a redacted SSN pattern' {
            $r = New-FakeReplacement -DetectedType 'SSN' -OriginalValue '123-45-6789'
            $r | Should -Match '^000-00-\d{4}$'
        }
    }

    Context 'CreditCard' {
        It 'returns a test card number starting with 411111111111' {
            $r = New-FakeReplacement -DetectedType 'CreditCard' -OriginalValue '4111111111111111'
            $r | Should -Match '^4111111111111\d{4}$'
        }
    }

    Context 'BearerToken' {
        It 'returns a REDACTED-TOKEN placeholder with 8-char hex suffix' {
            $r = New-FakeReplacement -DetectedType 'BearerToken' -OriginalValue 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
            $r | Should -Match '^\[REDACTED-TOKEN-[0-9a-f]{8}\]$'
        }
    }

    Context 'CredentialUrl' {
        It 'preserves the scheme and host' {
            $r = New-FakeReplacement -DetectedType 'CredentialUrl' -OriginalValue 'postgres://dbuser:s3cr3t@db.internal.example.com/mydb'
            $r | Should -Match '^postgres://'
            $r | Should -Match '@db\.internal\.example\.com/mydb$'
        }

        It 'replaces the credentials portion' {
            $r = New-FakeReplacement -DetectedType 'CredentialUrl' -OriginalValue 'postgres://dbuser:s3cr3t@host/db'
            $r | Should -Not -Match 'dbuser:s3cr3t'
        }
    }

    Context 'Hostname' {
        It 'returns an internal-host placeholder' {
            $r = New-FakeReplacement -DetectedType 'Hostname' -OriginalValue 'fileserver01.corp.local'
            $r | Should -Match '^internal-host-[a-z0-9]{6}\.local$'
        }
    }

    Context 'HighEntropyString (API key)' {
        It 'returns a string of the same length as the original' {
            $original = 'a3f8c1e9d4b720e6f5a1'
            $r = New-FakeReplacement -DetectedType 'HighEntropyString' -OriginalValue $original
            $r.Length | Should -Be $original.Length
        }

        It 'returns a hex string when the original is hex' {
            $original = 'a3f8c1e9d4b720e6f5a1'
            $r = New-FakeReplacement -DetectedType 'HighEntropyString' -OriginalValue $original
            $r | Should -Match '^[0-9a-f]+$'
        }

        It 'output differs from the original' {
            $original = 'a3f8c1e9d4b720e6f5a1'
            $r = New-FakeReplacement -DetectedType 'HighEntropyString' -OriginalValue $original
            # Statistically near-impossible to collide; run a few times
            $results = 1..5 | ForEach-Object {
                New-FakeReplacement -DetectedType 'HighEntropyString' -OriginalValue $original
            }
            $results | Should -Not -Contain $original
        }
    }

    Context 'KeyNameMatch' {
        It 'returns a REDACTED-KEYNAME placeholder with a 32-char suffix' {
            $r = New-FakeReplacement -DetectedType 'KeyNameMatch' -OriginalValue 'supersecret'
            $r | Should -Match '^\[REDACTED-KEYNAME-[A-Za-z0-9]{32}\]$'
        }
    }

    Context 'Unknown type fallback' {
        It 'returns [REDACTED] for an unrecognised type' {
            $r = New-FakeReplacement -DetectedType 'UnknownFutureType' -OriginalValue 'somevalue'
            $r | Should -Be '[REDACTED]'
        }
    }
}

Describe 'Resolve-ApiKeyCharset' {
    It 'returns lowercase hex charset for a lowercase hex string' {
        Resolve-ApiKeyCharset -Sample 'deadbeef01234567' | Should -Be '0123456789abcdef'
    }

    It 'returns alphanumeric charset for a mixed-case alphanumeric string' {
        Resolve-ApiKeyCharset -Sample 'AbCdEf12XyZ98QrSt' | Should -Match '[A-Za-z0-9]'
    }
}
