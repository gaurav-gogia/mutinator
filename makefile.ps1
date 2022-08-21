# use garble

[string]$BUILD_DIR_x64 = ".\bin\x64"
[string]$BUILD_DIR_x86 = ".\bin\x86"
[string]$B64_DIR = ".\bin\b64"
[string]$windows = "windows"
[string]$linux = "linux"
[string]$darwin = "darwin"
[string]$amd64 = "amd64"
[string]$arm64 = "arm64"
[string]$x86 = "386"
[string]$arm = "arm"

function build([string]$path) {
    Write-Host -ForegroundColor Yellow "Working On: $path"
    garble build -o $path .
    $content = Get-Content $path
    $contentBytes = [System.Text.Encoding]::UTF8.GetBytes($content)
    $encoded = [System.Convert]::ToBase64String($contentBytes)
    $filename = $path.Split("\")[-1]
    $encoded | Set-Content $B64_DIR\$filename.b64
    Write-Host -ForegroundColor Green "Wrote: $B64_DIR\$filename.b64"
}

$env:GOOS = $windows
$env:GOARCH = $amd64
$path = "$BUILD_DIR_x64\win_x64.exe"
build($path)
$env:GOOS = $linux
$path = "$BUILD_DIR_x64\linux_x64"
build($path)
$env:GOOS = $darwin
$path = "$BUILD_DIR_x64\darwin_x64"
build($path)

$env:GOOS = $windows
$env:GOARCH = $arm64
$path = "$BUILD_DIR_x64\win_arm64.exe"
build($path)
$env:GOOS = $linux
$path = "$BUILD_DIR_x64\linux_arm64"
build($path)
$env:GOOS = $darwin
$path = "$BUILD_DIR_x64\darwin_arm64"
build($path)

$env:GOOS = $windows
$env:GOARCH = $x86
$path = "$BUILD_DIR_x86\win_x86.exe"
build($path)
$env:GOOS = $linux
$path = "$BUILD_DIR_x86\linux_x86"
build($path)

$env:GOOS = $windows
$env:GOARCH = $arm
$path = "$BUILD_DIR_x86\win_arm.exe"
build($path)
$env:GOOS = $linux
$path = "$BUILD_DIR_x86\win_arm.exe"
build($path)