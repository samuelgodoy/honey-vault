#justfile version 1.25.2
set shell := ["powershell", "-c"]


build:
    $env:GOOS="windows"; $env:GOARCH="386"; go build -o ./bin/honey_windows-x86.exe
    $env:GOOS="windows"; $env:GOARCH="amd64"; go build -o ./bin/honey_windows-amd64.exe
    $env:GOOS="linux"; $env:GOARCH="amd64"; go build -o ./bin/honey_linux-amd64
    $env:GOOS="linux"; $env:GOARCH="arm"; $env:GOARM="6"; go build -o ./bin/honey_linux-arm6
    $env:GOOS="linux"; $env:GOARCH="arm"; $env:GOARM="7"; go build -o ./bin/honey_linux-arm7
    $env:GOOS="darwin"; $env:GOARCH="amd64"; go build -o ./bin/honey_macos-amd64
    $env:GOOS="darwin"; $env:GOARCH="arm64"; go build -o ./bin/honey_macos-arm64
