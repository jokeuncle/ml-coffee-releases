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
$exe = Join-Path $private 'installer-tests.exe'
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
    if ((Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant() -ne $descriptor.executable_sha256) { throw 'Native executable digest mismatch' }
  } finally {
    Remove-Item -LiteralPath $key -Force -ErrorAction SilentlyContinue
    Remove-Item Env:\MLC_NATIVE_DECRYPTION_KEY -ErrorAction SilentlyContinue
  }
} elseif ($Phase -eq 'test') {
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
