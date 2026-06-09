Set-StrictMode -Version Latest

foreach ($file in Get-ChildItem -Path "$PSScriptRoot\Private" -Filter '*.ps1' -ErrorAction SilentlyContinue) {
    . $file.FullName
}

foreach ($file in Get-ChildItem -Path "$PSScriptRoot\Public" -Filter '*.ps1' -ErrorAction SilentlyContinue) {
    . $file.FullName
}
