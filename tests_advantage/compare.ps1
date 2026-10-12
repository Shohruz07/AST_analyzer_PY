$files = @("test_oop", "test_dict", "test_sanitize")

foreach ($file in $files) {
    Write-Host ""
    Write-Host "=== $file ===" -ForegroundColor Green
    
    $our = (Get-Content "tests_advantage\${file}.py_our.json" | ConvertFrom-Json)
    $our_count = ($our.PSObject.Properties | ForEach-Object { $_.Value.Count } | Measure-Object -Sum).Sum
    
    $bandit = (Get-Content "tests_advantage\${file}.py_bandit.json" | ConvertFrom-Json)
    $bandit_count = $bandit.results.Count
    
    $semgrep = (Get-Content "tests_advantage\${file}.py_semgrep.json" | ConvertFrom-Json)
    $semgrep_count = $semgrep.results.Count
    
    Write-Host "Наш:     $our_count"
    Write-Host "Bandit:  $bandit_count"
    Write-Host "Semgrep: $semgrep_count"
}