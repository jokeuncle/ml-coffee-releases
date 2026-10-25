param([ValidateSet('unpack','test','cleanup')][string]$Phase)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$descriptor = Get-Content native/input.json -Raw | ConvertFrom-Json
$sealed = Join-Path $env:RUNNER_TEMP 'native-sealed'
$private = Join-Path $env:RUNNER_TEMP 'native-private'
$evidence = Join-Path $env:RUNNER_TEMP 'native-evidence'
New-Item -ItemType Directory -Force $private,$evidence | Out-Null
$openssl = (Get-Command openssl.exe -ErrorAction SilentlyContinue).Source
if (-not $openssl) { $openssl = 'C:\Program Files\Git\usr\bin\openssl.exe' }
if (-not (Test-Path -LiteralPath $openssl)) { throw 'OpenSSL unavailable on native runner' }
$runtime = $descriptor.payload_kind -eq 'cli_e2e_zip'
$exe = Join-Path $private $(if ($runtime) { 'runtime.zip' } else { 'installer-tests.exe' })
$log = Join-Path $private 'unit-tests.log'
$certificate = Join-Path $sealed $descriptor.certificate_asset
if ($Phase -eq 'unpack') {
  $cipher = Join-Path $sealed $descriptor.cipher_asset
  if ((Get-FileHash $cipher -Algorithm SHA256).Hash.ToLowerInvariant() -ne $descriptor.cipher_sha256) { throw 'Ciphertext digest mismatch' }
  if ((Get-FileHash $certificate -Algorithm SHA256).Hash.ToLowerInvariant() -ne $descriptor.certificate_sha256) { throw 'Recipient digest mismatch' }
  $key = Join-Path $private 'ephemeral-key.pem'
  try {
    [System.IO.File]::WriteAllText($key, $env:MLC_NATIVE_DECRYPTION_KEY)
    & $openssl cms -decrypt -binary -inform DER -in $cipher -recip $certificate -inkey $key -out $exe *> (Join-Path $private 'decrypt.log')
    if ($LASTEXITCODE -ne 0) { throw 'Native input decryption failed' }
    $expected = if ($runtime) { $descriptor.payload_sha256 } else { $descriptor.executable_sha256 }
    if ((Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'Native payload digest mismatch' }
    if ($runtime) {
      $packet = Join-Path $private 'packet'
      New-Item -ItemType Directory $packet | Out-Null
      $archive = [IO.Compression.ZipFile]::OpenRead($exe)
      try {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $archive.Entries) {
          if ($entry.FullName -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$' -or -not $names.Add($entry.FullName) -or $entry.Length -gt 104857600) { throw 'Unsafe native archive entry' }
          $property = $descriptor.package_files.PSObject.Properties[$entry.FullName]
          if (-not $property) { throw 'Unexpected native archive file' }
          $target = Join-Path $packet $entry.FullName
          [IO.Compression.ZipFileExtensions]::ExtractToFile($entry,$target,$false)
          if ((Get-FileHash $target -Algorithm SHA256).Hash.ToLowerInvariant() -ne $property.Value) { throw 'Native package file digest mismatch' }
        }
        if ($names.Count -ne @($descriptor.package_files.PSObject.Properties).Count) { throw 'Incomplete native package' }
      } finally { $archive.Dispose() }
    }
  } finally {
    Remove-Item -LiteralPath $key -Force -ErrorAction SilentlyContinue
    Remove-Item Env:\MLC_NATIVE_DECRYPTION_KEY -ErrorAction SilentlyContinue
  }
} elseif ($Phase -eq 'test') {
  if ($runtime) {
    $packet = Join-Path $private 'packet'
    & python (Join-Path $packet 'native_driver.py') *> $log
    $code = $LASTEXITCODE
    $summaryPath = Join-Path $packet 'runtime-summary.json'
    if (Test-Path $summaryPath) {
      $summary = Get-Content $summaryPath -Raw | ConvertFrom-Json
      $summary | Add-Member -NotePropertyName payload_sha256 -NotePropertyValue $descriptor.payload_sha256
      $summary | Add-Member -NotePropertyName source_sha256 -NotePropertyValue $descriptor.source_sha256
      $summary | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $evidence 'summary.json')
    }
    if ($code -ne 0) { throw 'Native CLI runtime acceptance failed; private diagnostics are sealed' }
    if (-not (Test-Path $summaryPath) -or $summary.status -ne 'passed') { throw 'Native CLI acceptance result missing' }
    return
  }
  & $exe '-test.run' $descriptor.test_filter '-test.v' *> $log
  $code = $LASTEXITCODE
  $text = Get-Content $log -Raw
  $passed = ([regex]::Matches($text, '(?m)^--- PASS:')).Count
  $skipped = ([regex]::Matches($text, '(?m)^--- SKIP:')).Count
  $failed = ([regex]::Matches($text, '(?m)^--- FAIL:')).Count
  $status = if ($code -eq 0 -and $passed -gt 0) { 'passed' } else { 'failed' }
  @{status=$status; exit_code=$code; passed=$passed; skipped=$skipped; failed=$failed; evidence_class='Windows-native-Go-unit'; executable_sha256=$descriptor.executable_sha256; source_sha256=$descriptor.source_sha256; public_installation_proven=$false; windows_arm64_executed=$false} | ConvertTo-Json | Set-Content (Join-Path $evidence 'summary.json')
  if ($status -ne 'passed') { throw 'Native unit boundary tests failed; private log is encrypted' }
} else {
  try {
    if (Test-Path $log) {
      & $openssl cms -encrypt -binary -aes-256-cbc -in $log -outform DER -out (Join-Path $evidence 'unit-tests.cms') $certificate *> (Join-Path $private 'seal.log')
      if ($LASTEXITCODE -ne 0) { throw 'Private native diagnostics could not be sealed' }
    }
  } finally {
    if (Test-Path $private) { Remove-Item $private -Recurse -Force }
  }
}
