# NetWatch SOC — Localhost Static Web Server (PowerShell .NET HttpListener)
# Runs without external runtime dependencies (Python/Node not required)

param(
    [int]$Port = 8501,
    [string]$WebRoot = $PSScriptRoot
)

if (-not $WebRoot) { $WebRoot = (Get-Location).Path }

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Prefixes.Add("http://127.0.0.1:$Port/")

try {
    $listener.Start()
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host " NetWatch SOC Localhost Server Running" -ForegroundColor Green
    Write-Host " URL: http://localhost:$Port/" -ForegroundColor Yellow
    Write-Host " WebRoot: $WebRoot" -ForegroundColor DarkGray
    Write-Host " Press Ctrl+C to stop server" -ForegroundColor DarkGray
    Write-Host "==========================================================" -ForegroundColor Cyan
} catch {
    Write-Host "Failed to start listener on port $Port : $_" -ForegroundColor Red
    exit 1
}

$mimeTypes = @{
    ".html" = "text/html; charset=utf-8"
    ".htm"  = "text/html; charset=utf-8"
    ".css"  = "text/css; charset=utf-8"
    ".js"   = "application/javascript; charset=utf-8"
    ".json" = "application/json; charset=utf-8"
    ".png"  = "image/png"
    ".jpg"  = "image/jpeg"
    ".svg"  = "image/svg+xml"
    ".pcap" = "application/vnd.tcpdump.pcap"
    ".txt"  = "text/plain; charset=utf-8"
}

while ($listener.IsListening) {
    try {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response

        $urlPath = $request.Url.LocalPath
        if ($urlPath -eq "/" -or $urlPath -eq "") {
            $urlPath = "/index.html"
        }

        # Normalize relative path
        $cleanPath = $urlPath.TrimStart('/').Replace('/', [System.IO.Path]::DirectorySeparatorChar)
        $filePath = [System.IO.Path]::Combine($WebRoot, $cleanPath)

        if ([System.IO.File]::Exists($filePath)) {
            $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
            $mime = $mimeTypes[$ext]
            if (-not $mime) { $mime = "application/octet-stream" }

            $response.ContentType = $mime
            $bytes = [System.IO.File]::ReadAllBytes($filePath)
            $response.ContentLength64 = $bytes.Length
            $response.StatusCode = 200
            $response.OutputStream.Write($bytes, 0, $bytes.Length)
        } else {
            $response.StatusCode = 404
            $msg = [System.Text.Encoding]::UTF8.GetBytes("404 Not Found: $urlPath")
            $response.ContentLength64 = $msg.Length
            $response.OutputStream.Write($msg, 0, $msg.Length)
        }
        $response.Close()
    } catch {
        # Catch individual request exceptions without crashing the loop
    }
}
