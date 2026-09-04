param(
    [Parameter(Mandatory = $true)][string]$InputPath,
    [Parameter(Mandatory = $true)][UInt64]$Rva,
    [Parameter(Mandatory = $true)][UInt64]$Size,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class KevlarVtil {
    [DllImport(@"kevlar-vtil.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern int kevlar_vtil_lift(byte[] image, UIntPtr imageSize, UInt64 rva, UIntPtr size, string outputPath, byte[] error, UIntPtr errorCapacity);
}
'@

$image = [IO.File]::ReadAllBytes($InputPath)
$errorBuffer = New-Object byte[] 512
$result = [KevlarVtil]::kevlar_vtil_lift(
    $image,
    [UIntPtr]::new([UInt64]$image.Length),
    $Rva,
    [UIntPtr]::new($Size),
    $OutputPath,
    $errorBuffer,
    [UIntPtr]::new([UInt64]$errorBuffer.Length))
if ($result -ne 1) {
    throw [Text.Encoding]::ASCII.GetString($errorBuffer).Trim([char]0)
}
