$ErrorActionPreference = "Stop"

$client = New-Object System.Net.WebClient

$ARCHIVE_DOWNLOAD_BASE_URL="https://archive.org/download"
$DX8_FILE_NAME="dx8sdk.exe"
$DX8_URL="$ARCHIVE_DOWNLOAD_BASE_URL/dx8sdk/$DX8_FILE_NAME"

$VS_02_FILE_NAME="en_vs.net_pro_full.exe"
$VS_02_URL="$ARCHIVE_DOWNLOAD_BASE_URL/en_vs.net_pro_full/$VS_02_FILE_NAME"

$PYTHON_FILE_NAME="python-3.4.4.msi"
$PYTHON_URL="https://www.python.org/ftp/python/3.4.4/$PYTHON_FILE_NAME"

$MSVCR100_FILE_NAME="vcredist_x86.exe"
$MSVCR100_URL="https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/$MSVCR100_FILE_NAME"

$SCRIPT_DIR=$PSScriptRoot
$DL_PATH="$SCRIPT_DIR/dls"

New-Item -ItemType Directory -Force -Path $DL_PATH

if (!(Test-Path "$DL_PATH/$DX8_FILE_NAME")) {
    Write-Host "Downloading Direct X 8.0"
    $client.DownloadFile($DX8_URL, "$DL_PATH/$DX8_FILE_NAME")
}

if (!(Test-Path "$DL_PATH/$VS_02_FILE_NAME")) {
    Write-Host "Downloading Visual Studio 2002"
    $client.DownloadFile($VS_02_URL, "$DL_PATH/$VS_02_FILE_NAME")
}
if (!(Test-Path "$DL_PATH/$PYTHON_FILE_NAME")) {
    Write-Host "Downloading Python 3.4.4"
    $client.DownloadFile($PYTHON_URL, "$DL_PATH/$PYTHON_FILE_NAME")
}
if (!(Test-Path "$DL_PATH/$MSVCR100_FILE_NAME")) {
    Write-Host "Downloading Visual C++ 10.0 Runtime"
    $client.DownloadFile($MSVCR100_URL, "$DL_PATH/$MSVCR100_FILE_NAME")
}
