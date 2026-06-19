$ErrorActionPreference = "Stop"

# --- manifest から version を取得 ---
$manifest = Get-Content "manifest.json" -Raw | ConvertFrom-Json
$version = $manifest.version

if (-not $version) {
    Write-Error "manifest.json に version がありません"
    exit 1
}

# --- 出力パス定義 ---
$outDir = ".release"
$fileName = "DMARCReportAnalyzer-$version.xpi"
$outFile = Join-Path $outDir $fileName
$stageDir = Join-Path $outDir "_stage"

# --- クリーンアップ ---
New-Item -ItemType Directory -Force $outDir | Out-Null
if (Test-Path $outFile)  { Remove-Item -Force $outFile }
if (Test-Path $stageDir) { Remove-Item -Recurse -Force $stageDir }

# --- ステージング（階層維持） ---
New-Item -ItemType Directory -Force (Join-Path $stageDir "images")    | Out-Null
New-Item -ItemType Directory -Force (Join-Path $stageDir "dashboard") | Out-Null
New-Item -ItemType Directory -Force (Join-Path $stageDir "options")   | Out-Null
New-Item -ItemType Directory -Force (Join-Path $stageDir "parser")    | Out-Null
New-Item -ItemType Directory -Force (Join-Path $stageDir "lib")       | Out-Null

Copy-Item -Force "manifest.json"              $stageDir
Copy-Item -Force "background.js"              $stageDir
Copy-Item -Force "LICENSE"                    $stageDir
# サードパーティライブラリの情報ファイル
Copy-Item -Force "VENDOR.md"                 $stageDir
Copy-Item -Force "images/icon.svg"           (Join-Path $stageDir "images")
Copy-Item -Force "dashboard/dashboard.html"  (Join-Path $stageDir "dashboard")
Copy-Item -Force "dashboard/dashboard.css"   (Join-Path $stageDir "dashboard")
Copy-Item -Force "dashboard/dashboard.js"    (Join-Path $stageDir "dashboard")
Copy-Item -Force "options/options.html"      (Join-Path $stageDir "options")
Copy-Item -Force "options/options.js"        (Join-Path $stageDir "options")
Copy-Item -Force "parser/ar_parser.js"       (Join-Path $stageDir "parser")
Copy-Item -Force "parser/fr_parser.js"       (Join-Path $stageDir "parser")
Copy-Item -Force "parser/analysis.js"        (Join-Path $stageDir "parser")

# --- lib ディレクトリ (存在する場合のみ) ---
$libFiles = Get-ChildItem "lib/*.js" -ErrorAction SilentlyContinue
if ($libFiles) {
    foreach ($f in $libFiles) {
        Copy-Item -Force $f.FullName (Join-Path $stageDir "lib")
    }
}

# --- _locales ディレクトリをコピー ---
Copy-Item -Recurse -Force "_locales" (Join-Path $stageDir "_locales")

# --- 圧縮 ---
Compress-Archive -Path (Join-Path $stageDir "*") -DestinationPath $outFile -Force

# --- ステージ削除 ---
Remove-Item -Recurse -Force $stageDir

# --- SHA256 生成 ---
$hash = Get-FileHash $outFile -Algorithm SHA256
$hashFile = "$outFile.sha256"
"$($hash.Hash.ToLower())  $fileName" | Out-File -Encoding ascii $hashFile

# --- 出力 ---
Write-Host "Created: $outFile"
Write-Host "SHA256: $($hash.Hash)"
Write-Host "Checksum file created: $hashFile"
