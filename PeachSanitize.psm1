Set-StrictMode -Version Latest

# Join-Path keeps loading correct on PowerShell 7 for Linux/macOS, where '\' is not a path separator.
foreach ($folder in @('Private', 'Public')) {
    $folderPath = Join-Path -Path $PSScriptRoot -ChildPath $folder
    foreach ($file in Get-ChildItem -Path $folderPath -Filter '*.ps1' -ErrorAction SilentlyContinue) {
        . $file.FullName
    }
}
