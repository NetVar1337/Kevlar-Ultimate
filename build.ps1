param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"

if (-not (Test-Path $vswhere)) {
    throw "Visual Studio Installer was not found. Install Visual Studio 2022 Build Tools with the C++ workload."
}

$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) {
    throw "Visual Studio 2022 C++ build tools were not found."
}

$vcpkg = Join-Path $vsPath "VC\vcpkg\vcpkg.exe"
$msbuild = Join-Path $vsPath "MSBuild\Current\Bin\amd64\MSBuild.exe"
$cmake = "$env:USERPROFILE\Tools\cmake\bin\cmake.exe"
$vtilBridge = Join-Path $root "extern\vtil-bridge"
$vtilBuild = Join-Path $root "builds\vtil-bridge"

if (-not (Test-Path $cmake)) {
    throw "Portable CMake was not found at $cmake."
}

& $cmake -S $vtilBridge -B $vtilBuild -G "Visual Studio 17 2022" -A x64 `
    "-DNATIVELIFTERS_BUILD_TESTS=OFF" `
    "-DFETCHCONTENT_SOURCE_DIR_VTIL-CORE=$(Join-Path $root 'extern\VTIL-Core')" `
    "-DFETCHCONTENT_SOURCE_DIR_CAPSTONE=$(Join-Path $root 'extern\VTIL-Capstone')" `
    "-DFETCHCONTENT_SOURCE_DIR_KEYSTONE=$(Join-Path $root 'extern\VTIL-Keystone')" `
    "-DVTIL_BUILD_TESTS=OFF" `
    "-DVTIL_UNITY_BUILD=ON"
if ($LASTEXITCODE) { throw "VTIL bridge CMake configuration failed with exit code $LASTEXITCODE" }

& $cmake --build $vtilBuild --config $Configuration --parallel
if ($LASTEXITCODE) { throw "VTIL bridge build failed with exit code $LASTEXITCODE" }


Push-Location $root
try {
    & $vcpkg install --triplet x64-windows-static
    if ($LASTEXITCODE) { throw "vcpkg failed with exit code $LASTEXITCODE" }

    & $msbuild "KEVLAR.sln" -m -restore "/p:Configuration=$Configuration" "/p:Platform=x64" "/p:VcpkgEnableManifest=true" "/p:VcpkgManifestRoot=$root" "/p:VcpkgTriplet=x64-windows-static"
    if ($LASTEXITCODE) { throw "MSBuild failed with exit code $LASTEXITCODE" }
    Copy-Item (Join-Path $vtilBuild "$Configuration\kevlar-vtil.dll") (Join-Path $root "builds\$Configuration\kevlar-vtil.dll") -Force
    Copy-Item (Join-Path $vtilBridge "kevlar-vtil-host.ps1") (Join-Path $root "builds\$Configuration\kevlar-vtil-host.ps1") -Force
} finally {
    Pop-Location
}

Write-Host "Built: $root\builds\$Configuration\KEVLAR.exe"
