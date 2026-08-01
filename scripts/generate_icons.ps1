[CmdletBinding()]
param(
    [string]$Source = "assets/veloguard.png"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$sourcePath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Source))

if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    throw "Icon source not found: $sourcePath"
}

Add-Type -AssemblyName System.Drawing

function Resolve-RepoPath([string]$RelativePath) {
    $path = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $RelativePath))
    if (-not $path.StartsWith($repoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to write outside repository: $path"
    }
    return $path
}

function New-IconBitmap([System.Drawing.Image]$Image, [int]$Size) {
    $bitmap = [System.Drawing.Bitmap]::new($Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
        $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
        $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $graphics.DrawImage($Image, 0, 0, $Size, $Size)
    } finally {
        $graphics.Dispose()
    }
    return $bitmap
}

function Write-Png([System.Drawing.Image]$Image, [int]$Size, [string]$RelativePath) {
    $path = Resolve-RepoPath $RelativePath
    [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($path)) | Out-Null
    $bitmap = New-IconBitmap $Image $Size
    try {
        $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    } finally {
        $bitmap.Dispose()
    }
}

function Get-PngBytes([System.Drawing.Image]$Image, [int]$Size) {
    $bitmap = New-IconBitmap $Image $Size
    $stream = [System.IO.MemoryStream]::new()
    try {
        $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
        return $stream.ToArray()
    } finally {
        $stream.Dispose()
        $bitmap.Dispose()
    }
}

function Write-Ico([System.Drawing.Image]$Image, [int[]]$Sizes, [string]$RelativePath) {
    $images = @($Sizes | ForEach-Object { Get-PngBytes $Image $_ })
    $path = Resolve-RepoPath $RelativePath
    [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($path)) | Out-Null
    $stream = [System.IO.File]::Create($path)
    $writer = [System.IO.BinaryWriter]::new($stream)
    try {
        $writer.Write([uint16]0)
        $writer.Write([uint16]1)
        $writer.Write([uint16]$Sizes.Count)
        $offset = 6 + (16 * $Sizes.Count)
        for ($index = 0; $index -lt $Sizes.Count; $index++) {
            $sizeByte = if ($Sizes[$index] -eq 256) { 0 } else { $Sizes[$index] }
            $writer.Write([byte]$sizeByte)
            $writer.Write([byte]$sizeByte)
            $writer.Write([byte]0)
            $writer.Write([byte]0)
            $writer.Write([uint16]1)
            $writer.Write([uint16]32)
            $writer.Write([uint32]$images[$index].Length)
            $writer.Write([uint32]$offset)
            $offset += $images[$index].Length
        }
        foreach ($bytes in $images) {
            $writer.Write($bytes)
        }
    } finally {
        $writer.Dispose()
        $stream.Dispose()
    }
}

function Write-AppleIconSet([System.Drawing.Image]$Image, [string]$RelativeDirectory) {
    $directory = Resolve-RepoPath $RelativeDirectory
    $manifest = Get-Content -LiteralPath (Join-Path $directory "Contents.json") -Raw | ConvertFrom-Json
    foreach ($entry in $manifest.images) {
        if (-not $entry.filename) { continue }
        $points = [double]($entry.size -split 'x')[0]
        $scale = [int]($entry.scale.TrimEnd('x'))
        $pixels = [int][Math]::Round($points * $scale)
        Write-Png $Image $pixels (Join-Path $RelativeDirectory $entry.filename)
    }
}

$image = [System.Drawing.Image]::FromFile($sourcePath)
try {
    if ($image.Width -ne $image.Height -or $image.Width -lt 1024) {
        throw "Icon source must be square and at least 1024x1024; got $($image.Width)x$($image.Height)"
    }

    $android = @{
        "mdpi" = 48; "hdpi" = 72; "xhdpi" = 96; "xxhdpi" = 144; "xxxhdpi" = 192
    }
    foreach ($density in $android.Keys) {
        Write-Png $image $android[$density] "android/app/src/main/res/mipmap-$density/ic_launcher.png"
        Write-Png $image ([int]($android[$density] * 2.25)) "android/app/src/main/res/drawable-$density/ic_launcher_foreground.png"
    }

    Write-AppleIconSet $image "ios/Runner/Assets.xcassets/AppIcon.appiconset"
    Write-AppleIconSet $image "macos/Runner/Assets.xcassets/AppIcon.appiconset"

    Write-Ico $image @(16, 24, 32, 48, 64, 128, 256) "windows/runner/resources/app_icon.ico"
    Write-Png $image 256 "linux/runner/resources/app_icon.png"

    Write-Png $image 32 "web/favicon.png"
    Write-Png $image 192 "web/icons/Icon-192.png"
    Write-Png $image 512 "web/icons/Icon-512.png"
    Write-Png $image 192 "web/icons/Icon-maskable-192.png"
    Write-Png $image 512 "web/icons/Icon-maskable-512.png"

    Write-Png $image 1024 "ohos/AppScope/resources/base/media/app_icon.png"
    Write-Png $image 1024 "ohos/entry/src/main/resources/base/media/icon.png"
    Write-Png $image 1024 "ohos/entry/src/main/resources/base/media/startIcon.png"
} finally {
    $image.Dispose()
}

Write-Host "Generated VeloGuard icons for Android, iOS, macOS, Windows, Linux, Web, and HarmonyOS."
