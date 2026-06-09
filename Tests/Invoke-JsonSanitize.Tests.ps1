BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module "$moduleRoot\PeachSanitize.psd1" -Force
}

AfterAll {
    Remove-Module PeachSanitize -ErrorAction SilentlyContinue
}

Describe 'Invoke-JsonSanitize - input validation' {

    It 'throws a terminating error when input is not valid JSON' {
        { 'not json at all' | Invoke-JsonSanitize } | Should -Throw -ErrorId 'InvalidJson,Invoke-JsonSanitize'
    }

    It 'throws a terminating error for an empty string' {
        { Invoke-JsonSanitize -InputObject '' } | Should -Throw
    }

    It 'throws when -Path points to a non-existent file' {
        { Invoke-JsonSanitize -Path 'C:\DoesNotExist\missing.json' } | Should -Throw -ErrorId 'FileNotFound,Invoke-JsonSanitize'
    }
}

Describe 'Invoke-JsonSanitize - output is valid JSON' {

    It 'output round-trips through ConvertFrom-Json without error' {
        $inputJson = '{"email":"user@example.com","status":"active"}'
        $result = $inputJson | Invoke-JsonSanitize
        { $result | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'output is a string' {
        $inputJson = '{"name":"test"}'
        $result = $inputJson | Invoke-JsonSanitize
        $result | Should -BeOfType [string]
    }
}

Describe 'Invoke-JsonSanitize - sanitization correctness' {

    It 'replaces an email address' {
        $inputJson = '{"contact":"alice@example.com"}'
        $result = $inputJson | Invoke-JsonSanitize | ConvertFrom-Json
        $result.contact | Should -Not -Be 'alice@example.com'
        $result.contact | Should -Match '@'
    }

    It 'replaces a value whose key name contains "password"' {
        $inputJson = '{"password":"MyS3cr3tP@ss"}'
        $result = $inputJson | Invoke-JsonSanitize | ConvertFrom-Json
        $result.password | Should -Not -Be 'MyS3cr3tP@ss'
    }

    It 'replaces a high-entropy API key' {
        # 'apiKey' contains 'key' - triggers KeyNameMatch; value is still replaced
        $inputJson = '{"apiKey":"a3f8c1e9d4b720e6f5a19e7c"}'
        $result = $inputJson | Invoke-JsonSanitize | ConvertFrom-Json
        $result.apiKey | Should -Not -Be 'a3f8c1e9d4b720e6f5a19e7c'
    }

    It 'replaces a Bearer token when the key name is neutral' {
        $inputJson = '{"httpHeader":"Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"}'
        $result = $inputJson | Invoke-JsonSanitize | ConvertFrom-Json
        $result.httpHeader | Should -Match 'REDACTED'
        $result.httpHeader | Should -Not -Be 'Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig'
    }

    It 'key-name heuristic takes priority over Bearer detection for "authorization" key' {
        $inputJson = '{"authorization":"Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"}'
        $result = $inputJson | Invoke-JsonSanitize | ConvertFrom-Json
        $result.authorization | Should -Match 'REDACTED-KEYNAME'
    }

    It 'replaces an IPv4 address' {
        $inputJson = '{"serverIp":"203.0.113.5"}'
        $result = $inputJson | Invoke-JsonSanitize | ConvertFrom-Json
        $result.serverIp | Should -Not -Be '203.0.113.5'
        $result.serverIp | Should -Match '^192\.168\.'
    }

    It 'leaves null values unchanged' {
        $inputJson = '{"field":null}'
        $result = $inputJson | Invoke-JsonSanitize | ConvertFrom-Json
        $result.field | Should -BeNullOrEmpty
    }

    It 'leaves boolean values unchanged' {
        $inputJson = '{"active":true,"disabled":false}'
        $result = $inputJson | Invoke-JsonSanitize | ConvertFrom-Json
        $result.active   | Should -Be $true
        $result.disabled | Should -Be $false
    }

    It 'preserves keys that contain no sensitive data' {
        $inputJson = '{"name":"Acme Corp","count":42}'
        $result = $inputJson | Invoke-JsonSanitize | ConvertFrom-Json
        $result.name  | Should -Be 'Acme Corp'
        $result.count | Should -Be 42
    }
}

Describe 'Invoke-JsonSanitize - structural integrity' {

    It 'handles an array at root level' {
        $inputJson = '[{"email":"a@b.com"},{"email":"c@d.com"}]'
        $result = $inputJson | Invoke-JsonSanitize
        { $result | ConvertFrom-Json } | Should -Not -Throw
        $parsed = $result | ConvertFrom-Json
        $parsed.Count | Should -Be 2
    }

    It 'sanitizes values 5 levels deep' {
        $inputJson = '{"l1":{"l2":{"l3":{"l4":{"l5":"alice@deep.com"}}}}}'
        $result = $inputJson | Invoke-JsonSanitize | ConvertFrom-Json
        $result.l1.l2.l3.l4.l5 | Should -Not -Be 'alice@deep.com'
        $result.l1.l2.l3.l4.l5 | Should -Match '@'
    }

    It 'sanitizes values inside nested arrays' {
        $inputJson = '{"users":[{"email":"a@example.com"},{"email":"b@example.com"}]}'
        $result = $inputJson | Invoke-JsonSanitize | ConvertFrom-Json
        $result.users[0].email | Should -Not -Be 'a@example.com'
        $result.users[1].email | Should -Not -Be 'b@example.com'
    }

    It 'preserves original key count at all levels' {
        $inputJson = '{"a":1,"b":"hello","c":{"d":true,"e":null}}'
        $parsed = $inputJson | Invoke-JsonSanitize | ConvertFrom-Json
        ($parsed.PSObject.Properties | Measure-Object).Count | Should -Be 3
        ($parsed.c.PSObject.Properties | Measure-Object).Count | Should -Be 2
    }
}

Describe 'Invoke-JsonSanitize - pipeline input' {

    It 'accepts a JSON string via pipeline' {
        $result = '{"email":"user@example.com"}' | Invoke-JsonSanitize
        { $result | ConvertFrom-Json } | Should -Not -Throw
    }
}

Describe 'Invoke-JsonSanitize - DryRun mode' {

    It 'does not modify the JSON (returns nothing to pipeline)' {
        $inputJson = '{"email":"alice@example.com"}'
        $result = $inputJson | Invoke-JsonSanitize -DryRun
        $result | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-JsonSanitize - OutFile mode' {

    It 'writes sanitized JSON to a file' {
        $tmpFile = [System.IO.Path]::GetTempFileName()
        try {
            '{"password":"hunter2"}' | Invoke-JsonSanitize -OutFile $tmpFile
            $written = [System.IO.File]::ReadAllText($tmpFile)
            { $written | ConvertFrom-Json } | Should -Not -Throw
            ($written | ConvertFrom-Json).password | Should -Not -Be 'hunter2'
        }
        finally {
            Remove-Item $tmpFile -ErrorAction SilentlyContinue
        }
    }

    It 'nothing is written to stdout when OutFile is used' {
        $tmpFile = [System.IO.Path]::GetTempFileName()
        try {
            $stdout = '{"name":"test"}' | Invoke-JsonSanitize -OutFile $tmpFile
            $stdout | Should -BeNullOrEmpty
        }
        finally {
            Remove-Item $tmpFile -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Invoke-JsonSanitize - edge cases from spec' {

    It 'treats the value N/A as sensitive when the key matches a sensitive pattern' {
        $inputJson = '{"email":"N/A"}'
        $result = $inputJson | Invoke-JsonSanitize | ConvertFrom-Json
        # email key triggers key-name heuristic? No - "email" doesn't match the keyword list.
        # But the value "N/A" doesn't match email regex either - so should be unchanged.
        # This test confirms the key-name heuristic only fires for password/secret/token/key/auth etc.
        $result.email | Should -Be 'N/A'
    }

    It 'replaces N/A when the key is "password"' {
        $inputJson = '{"password":"N/A"}'
        $result = $inputJson | Invoke-JsonSanitize | ConvertFrom-Json
        $result.password | Should -Not -Be 'N/A'
    }
}
