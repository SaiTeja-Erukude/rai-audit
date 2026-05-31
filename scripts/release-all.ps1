# Bump each package version and push release tags.
#
# Usage:
#   .\scripts\release-all.ps1                          # patch bump (0.1.0 -> 0.1.1)
#   .\scripts\release-all.ps1 -Bump minor              # minor bump (0.1.0 -> 0.2.0)
#   .\scripts\release-all.ps1 -Bump major              # major bump (0.1.0 -> 1.0.0)
#   .\scripts\release-all.ps1 -m "my commit message"
param(
    [ValidateSet("patch","minor","major")]
    [string]$Bump = "patch",
    [Alias("m")]
    [string]$Message = ""
)

$ErrorActionPreference = "Stop"

$Packages = @(
    "rai-audit-core"
    "rai-audit-ml"
    "rai-audit-dl"
    "rai-audit-llm"
    "rai-audit-agents"
    "rai-audit-kit"
)

function Bump-Version($version, $bump) {
    $parts = $version -split '\.'
    switch ($bump) {
        "major" { return "$([int]$parts[0] + 1).0.0" }
        "minor" { return "$($parts[0]).$([int]$parts[1] + 1).0" }
        "patch" { return "$($parts[0]).$($parts[1]).$([int]$parts[2] + 1)" }
    }
}

$NewVersions = @{}

Write-Host "Bumping versions ($Bump):"
foreach ($pkg in $Packages) {
    $toml = "packages/$pkg/pyproject.toml"
    $content = Get-Content $toml -Raw
    if ($content -match 'version = "([^"]+)"') {
        $current = $Matches[1]
    } else {
        Write-Error "Could not find version in $toml"
    }
    $new = Bump-Version $current $Bump
    $NewVersions[$pkg] = $new
    $content = $content -replace "version = `"$current`"", "version = `"$new`""
    Set-Content $toml $content -NoNewline
    Write-Host "  $pkg`: $current -> $new"
}

$commitMsg = if ($Message) { $Message } else { "chore: bump versions ($Bump)" }

Write-Host ""
Write-Host "Committing..."
git add -A
git commit -m $commitMsg

Write-Host "Tagging..."
foreach ($pkg in $Packages) {
    $tag = "$pkg-v$($NewVersions[$pkg])"
    git tag $tag
    Write-Host "  Tagged $tag"
}

git push origin main --tags
Write-Host ""
Write-Host "Done - $($Packages.Count) publish workflows triggered."
