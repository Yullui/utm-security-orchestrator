#!/usr/bin/env pwsh
# UTM PC Test Runner (Windows PowerShell)
# Run this to test UTM on your Windows 11 system

param(
    [switch]$Quick = $false,
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Continue"

function Print-Header ([string]$Text) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Print-Pass ([string]$Text) {
    Write-Host "  ✓ [PASS] $Text" -ForegroundColor Green
}

function Print-Fail ([string]$Text) {
    Write-Host "  ✗ [FAIL] $Text" -ForegroundColor Red
}

function Print-Info ([string]$Text) {
    Write-Host "  ℹ [INFO] $Text" -ForegroundColor Yellow
}

Print-Header "UTM SECURITY ORCHESTRATOR - PC TEST SUITE"
Print-Info "Platform: $([System.Environment]::OSVersion.VersionString)"
Print-Info "PowerShell: $($PSVersionTable.PSVersion)"

# Check Python
Print-Header "1. Checking Python Installation"
try {
    $pyVersion = python --version 2>&1
    Print-Pass "Python found: $pyVersion"
} catch {
    Print-Fail "Python not found. Install from https://python.org"
    exit 1
}

# Check dependencies
Print-Header "2. Checking Dependencies"
$deps = @("yaml", "requests", "pytest")
foreach ($dep in $deps) {
    try {
        python -c "import $dep" 2>&1 | Out-Null
        Print-Pass "Module '$dep' installed"
    } catch {
        Print-Info "Module '$dep' not installed. Run: pip install -r requirements.txt"
    }
}

# Run comprehensive test if not quick mode
if (-not $Quick) {
    Print-Header "3. Running Comprehensive PC Tests"
    python test_pc.py
    $testResult = $LASTEXITCODE
} else {
    Print-Header "3. Running Quick Tests (unit tests only)"
    python -m pytest -q
    $testResult = $LASTEXITCODE
}

# Run linters if not quick
if (-not $Quick) {
    Print-Header "4. Running Linters"
    
    Print-Info "Running ruff..."
    python -m ruff check . 2>&1 | Select-Object -First 5
    
    Print-Info "Running mypy..."
    python -m mypy . --no-error-summary 2>&1 | Select-Object -First 5
}

# Summarize
Print-Header "TEST SUMMARY"
if ($testResult -eq 0) {
    Write-Host "  🎉 All tests passed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor Cyan
    Write-Host "    1. Review help desk playbooks: playbooks/helpdesk_playbook.md"
    Write-Host "    2. Generate SBOM: python generate_sbom.py"
    Write-Host "    3. Run orchestrator: python utm.py"
    Write-Host "    4. Check logs: cat utm.log"
    Write-Host ""
} else {
    Write-Host "  ⚠️  Some tests failed. Review output above." -ForegroundColor Red
    Write-Host ""
}

exit $testResult
