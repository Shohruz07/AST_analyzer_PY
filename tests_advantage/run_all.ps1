# run_all.ps1
$ErrorActionPreference = "Continue"

$files = @("test_oop.py", "test_dict.py", "test_sanitize.py")

foreach ($file in $files) {
    Write-Host ""
    Write-Host "=== $file ===" -ForegroundColor Green
    
    # Наш
    python cli.py --file "tests_advantage\$file" --output "tests_advantage\${file}_our.json" --quiet
    
    # Bandit
    python -m bandit "tests_advantage\$file" -f json -o "tests_advantage\${file}_bandit.json" -q
    
    # Semgrep
    semgrep --config=auto "tests_advantage\$file" --json -o "tests_advantage\${file}_semgrep.json" -q
    
    Write-Host "Готово: $file" -ForegroundColor Yellow
}