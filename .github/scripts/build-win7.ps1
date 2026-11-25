# Requires MSVC x64 build tools and llvm-readobj on PATH.
$ErrorActionPreference = 'Stop'
$toolchain = 'nightly-2026-06-12'
$target = 'x86_64-win7-windows-msvc'
$binaries = @('vnt2_cli', 'vnt2_ctrl', 'vnt2_web')
$llvm = Get-Command llvm-readobj -CommandType Application | Select-Object -First 1
$previousSkipUiBuild = $env:VNT_WEB_SKIP_UI_BUILD

Push-Location (Join-Path $PSScriptRoot '../..')
try {
    if (!(Test-Path 'vnt-web/static/index.html' -PathType Leaf) -or
        !(Get-ChildItem 'vnt-web/static/assets' -Filter '*.js' -File -ErrorAction SilentlyContinue)) {
        throw 'Build the Web frontend with pnpm build:web or restore its build artifact first.'
    }

    rustup toolchain install $toolchain --profile minimal --component rust-src --no-self-update
    if ($LASTEXITCODE -ne 0) { throw 'Could not install the Windows 7 Rust toolchain.' }

    $env:VNT_WEB_SKIP_UI_BUILD = '1'
    $binArgs = foreach ($binary in $binaries) { '--bin'; $binary }
    cargo "+$toolchain" build --locked --release -p vnt2 --target $target --target-dir target `
        -Z build-std=std,panic_abort --features vnt-ipc,vnt-web @binArgs
    if ($LASTEXITCODE -ne 0) { throw 'Windows 7 build failed.' }

    $images = @($binaries | ForEach-Object { "target/$target/release/$_.exe" })
    $images += 'dll/amd64/wintun.dll'
    foreach ($image in $images) {
        $report = & $llvm.Source --file-headers --coff-imports $image | Out-String
        if ($LASTEXITCODE -ne 0) { throw "Could not inspect $image." }
        if ($report -notmatch '(?m)^  Machine: IMAGE_FILE_MACHINE_AMD64\b') {
            throw "$image is not an x64 PE image."
        }
        if ($image.EndsWith('.exe') -and
            ($report -notmatch '(?m)^  MajorSubsystemVersion: 6\s*$' -or
             $report -notmatch '(?m)^  MinorSubsystemVersion: 1\s*$' -or
             $report -notmatch '(?m)^  Subsystem: IMAGE_SUBSYSTEM_WINDOWS_CUI\b')) {
            throw "$image must use the Windows console subsystem version 6.01."
        }

        # Wintun delay-loads APIs used by its newer Windows paths. Inspect them
        # in the report, while checking eager imports for loader failures.
        Write-Output $report
        $eagerImports = [regex]::Matches($report, '(?m)^Import \{\r?\n[\s\S]*?^\}')
        if ($eagerImports.Count -eq 0) { throw "Could not find the import table for $image." }
        foreach ($entry in $eagerImports) {
            if ($entry.Value -match '(?im)^  Name: (?:api-ms-win-|ext-ms-win-|bcryptprimitives\.dll|ucrtbase\.dll|vcruntime\d|msvcp\d)' -or
                $entry.Value -match '(?m)^  Symbol: (?:GetSystemTimePreciseAsFileTime|GetOverlappedResultEx|SetThreadDescription|WaitOnAddress|WakeByAddressAll|WakeByAddressSingle|ProcessPrng) \(') {
                throw "$image eagerly imports a DLL or API outside the Windows 7 baseline:`n$($entry.Value)"
            }
        }
    }
}
finally {
    $env:VNT_WEB_SKIP_UI_BUILD = $previousSkipUiBuild
    Pop-Location
}
