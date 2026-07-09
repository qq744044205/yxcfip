param(
  [Parameter(Mandatory = $true)]
  [string]$SourceFile,

  [Parameter(Mandatory = $true)]
  [string]$RepoPath,

  [string]$TargetFile = "preferred-addresses.txt",

  [string]$DefaultRemark = "",

  [switch]$NoPush
)

$ErrorActionPreference = "Stop"

function Normalize-Remark {
  param([string]$Remark)

  $value = $Remark.Trim()
  if (-not $value) { return "" }

  $value = $value -replace "\s*[\[\(].*$", ""
  $value = $value.Trim()
  if (-not $value) { return "" }

  return ($value -split "\s+", 2)[0].Trim()
}

function Normalize-Line {
  param([string]$Line)

  $value = $Line.Trim()
  if (-not $value) { return $null }
  if ($value.StartsWith("#") -or $value.StartsWith("//") -or $value.StartsWith(";")) { return $null }

  $parts = $value -split "#", 2
  $left = $parts[0].Trim()
  $remark = if ($parts.Count -gt 1) { Normalize-Remark $parts[1] } else { Normalize-Remark $DefaultRemark }

  $match = [regex]::Match($left, "(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?")
  if (-not $match.Success) { return $null }

  $ip = $match.Groups[1].Value
  $octets = $ip.Split(".") | ForEach-Object { [int]$_ }
  if (($octets | Where-Object { $_ -lt 0 -or $_ -gt 255 }).Count -gt 0) { return $null }

  if ($remark) { return "$ip#$remark" }
  return $ip
}

$sourcePath = Resolve-Path -LiteralPath $SourceFile
$repoRoot = Resolve-Path -LiteralPath $RepoPath
$targetPath = Join-Path $repoRoot $TargetFile

$lines = Get-Content -LiteralPath $sourcePath -Encoding UTF8 |
  ForEach-Object { Normalize-Line $_ } |
  Where-Object { $_ } |
  Select-Object -Unique

if (-not $lines -or $lines.Count -eq 0) {
  throw "No usable IPv4 addresses were parsed from the source file."
}

Set-Content -LiteralPath $targetPath -Value $lines -Encoding UTF8

Push-Location $repoRoot
try {
  git status --short
  git add -- $TargetFile

  $changes = git diff --cached --name-only
  if (-not $changes) {
    Write-Host "preferred-addresses.txt has no changes."
    return
  }

  git commit -m "Update preferred Cloudflare addresses"

  if (-not $NoPush) {
    git push
  }
} finally {
  Pop-Location
}
