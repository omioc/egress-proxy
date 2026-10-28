#Requires -Version 7.0
<#
.SYNOPSIS
    在本地构建 egress-proxy 的两个镜像，并导出成两个 tar 包（用于离线分发到集群节点）

.DESCRIPTION
    * 镜像名不带仓库前缀、不带项目名：redirect-agent:<Tag>、tcp-forwarder:<Tag>
    * 两个 tar 包输出到 deploy/ 目录：deploy/redirect-agent-<Tag>.tar、deploy/tcp-forwarder-<Tag>.tar
    * 构建上下文为项目根目录，复用 Dockerfile.agent / Dockerfile.proxy

.PARAMETER Tag
    镜像 tag，默认 0.1.0

.PARAMETER OutputDir
    tar 包输出目录，默认 <项目根>/deploy

.PARAMETER Platform
    构建目标平台，默认 linux/amd64（K8s 节点绝大多数为 amd64）
    传空字符串（-Platform ''）表示使用 Docker 的默认平台

.PARAMETER GoProxy
    容器内 go mod download 使用的模块代理，默认 https://goproxy.cn,direct

.PARAMETER NoCache
    构建时加 --no-cache

.PARAMETER SkipBuild
    跳过构建，仅导出本地已存在的镜像（离线重新打包时使用）

.EXAMPLE
    pwsh ./scripts/build-images.ps1

.EXAMPLE
    pwsh ./scripts/build-images.ps1 -Tag 0.2.0 -Platform linux/arm64 -NoCache

.EXAMPLE
    pwsh ./scripts/build-images.ps1 -SkipBuild -OutputDir D:\transfer

.NOTES
    必须在 PowerShell 7（pwsh）下运行；Windows PowerShell 5.1 不支持本脚本的语法
#>
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$')]
    [string]$Tag = '0.1.0',

    [string]$OutputDir,

    [string]$Platform = 'linux/amd64',

    [string]$GoProxy = 'https://goproxy.cn,direct',

    [switch]$NoCache,

    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $ProjectRoot 'deploy'
}

$Images = @(
    [pscustomobject]@{ Name = 'redirect-agent'; Dockerfile = 'Dockerfile.agent' }
    [pscustomobject]@{ Name = 'tcp-forwarder'; Dockerfile = 'Dockerfile.proxy' }
    [pscustomobject]@{ Name = 'controller'; Dockerfile = 'Dockerfile.controller' }
)

function Invoke-Docker {
    param([Parameter(Mandatory)][string[]]$Arguments)

    Write-Host ("    `$ docker " + ($Arguments -join ' ')) -ForegroundColor DarkGray
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw ("docker 命令执行失败（退出码 {0}）：docker {1}" -f $LASTEXITCODE, ($Arguments -join ' '))
    }
}

function Get-DockerServerVersion {
    $version = & docker version --format '{{.Server.Version}}' 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace([string]$version)) {
        return $null
    }
    return ([string]$version).Trim()
}

function Test-ImageExists {
    param([Parameter(Mandatory)][string]$Image)

    & docker image inspect $Image *> $null
    return ($LASTEXITCODE -eq 0)
}

function Format-FileSize {
    param([Parameter(Mandatory)][long]$Bytes)

    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    return ('{0:N0} KB' -f ($Bytes / 1KB))
}

# 返回 $true/$false；没有 tar 命令可校验时返回 $null
function Test-TarArchive {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Get-Command tar -ErrorAction SilentlyContinue)) {
        return $null
    }
    $entries = & tar -tf $Path 2>$null
    if ($LASTEXITCODE -ne 0) { return $false }
    return [bool]($entries | Where-Object { $_ -match '^manifest\.json$' })
}

$startTime = Get-Date

try {
    Write-Host '=== egress-proxy 本地镜像打包 ===' -ForegroundColor Cyan
    Write-Host ("    项目根目录 : {0}" -f $ProjectRoot)
    Write-Host ("    输出目录   : {0}" -f $OutputDir)
    Write-Host ("    镜像 tag   : {0}" -f $Tag)
    Write-Host ("    目标平台   : {0}" -f ($(if ($Platform) { $Platform } else { '（Docker 默认）' })))
    Write-Host ("    Go 模块代理 : {0}" -f $GoProxy)

    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw '未找到 docker 命令，请先安装 Docker 并确保 docker 在 PATH 中'
    }
    $serverVersion = Get-DockerServerVersion
    if (-not $serverVersion) {
        throw 'Docker 守护进程不可用（docker version 失败）；请先启动 Docker Desktop / dockerd'
    }
    Write-Host ("    Docker 服务端版本 : {0}" -f $serverVersion)

    foreach ($item in $Images) {
        $dockerfilePath = Join-Path $ProjectRoot $item.Dockerfile
        if (-not (Test-Path -LiteralPath $dockerfilePath)) {
            throw ("缺少 {0}，请确认脚本位于 {1}\scripts 目录下" -f $item.Dockerfile, $ProjectRoot)
        }
    }

    if (-not (Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
        Write-Host ("    已创建输出目录 : {0}" -f $OutputDir)
    }

    $summary = @()
    $index = 0

    foreach ($item in $Images) {
        $index++
        $image = '{0}:{1}' -f $item.Name, $Tag
        $tarPath = Join-Path $OutputDir ('{0}-{1}.tar' -f $item.Name, $Tag)

        Write-Host ''
        Write-Host ("==> [{0}/{1}] 构建镜像 {2}" -f $index, $Images.Count, $image) -ForegroundColor Cyan

        if ($SkipBuild) {
            Write-Host '    （-SkipBuild：跳过构建）'
            if (-not (Test-ImageExists $image)) {
                throw ("本地不存在镜像 {0}，无法导出；请去掉 -SkipBuild 先构建，或检查 -Tag 是否正确" -f $image)
            }
        }
        else {
            $buildArgs = @('build', '-f', (Join-Path $ProjectRoot $item.Dockerfile), '-t', $image)
            if ($Platform) { $buildArgs += @('--platform', $Platform) }
            if ($GoProxy) { $buildArgs += @('--build-arg', ('GOPROXY={0}' -f $GoProxy)) }
            $buildArgs += @('--build-arg', ('VERSION={0}' -f $Tag))
            if ($NoCache) { $buildArgs += '--no-cache' }
            $buildArgs += $ProjectRoot
            Invoke-Docker -Arguments $buildArgs
        }

        Write-Host ''
        Write-Host ("==> [{0}/{1}] 导出 tar 包 {2}" -f $index, $Images.Count, $tarPath) -ForegroundColor Cyan
        if (Test-Path -LiteralPath $tarPath) {
            Remove-Item -LiteralPath $tarPath -Force
        }
        Invoke-Docker -Arguments @('save', '-o', $tarPath, $image)

        $file = Get-Item -LiteralPath $tarPath
        if ($file.Length -le 0) {
            throw ("导出的 tar 包为空：{0}" -f $tarPath)
        }
        $tarCheck = Test-TarArchive $tarPath
        if ($tarCheck -eq $false) {
            throw ("tar 包内容校验失败（未找到 manifest.json）：{0}" -f $tarPath)
        }

        $verifyText = if ($null -eq $tarCheck) { '未校验（无 tar 命令）' } else { 'manifest.json 已确认' }
        $summary += [pscustomobject]@{
            Image = $image
            Tar   = $tarPath
            Size  = Format-FileSize $file.Length
            Check = $verifyText
        }
    }

    Write-Host ''
    Write-Host '=== 完成 ===' -ForegroundColor Green
    foreach ($row in $summary) {
        Write-Host ("    镜像 : {0}" -f $row.Image)
        Write-Host ("    文件 : {0}  ({1}, {2})" -f $row.Tar, $row.Size, $row.Check)
        Write-Host ''
    }
    Write-Host ("    耗时 : {0:N1} 秒" -f ((Get-Date) - $startTime).TotalSeconds)

    $agentTar = Join-Path $OutputDir ('redirect-agent-{0}.tar' -f $Tag)
    Write-Host ''
    Write-Host '下一步：把 tar 包拷到节点后导入（镜像名不带前缀，默认已在 deploy/kustomization.yaml 的 images 段指定）：'
    Write-Host ("    Docker 运行时     : docker load -i {0}" -f $agentTar)
    Write-Host ("    containerd 运行时 : ctr -n k8s.io images import {0}" -f $agentTar)
    Write-Host ("    （nerdctl 亦可    : nerdctl -n k8s.io load -i <tar>）")
    Write-Host ''
    Write-Host ("提示：镜像地址只在 deploy/kustomization.yaml 的 images 段维护（newName / newTag），")
    Write-Host ("      用 kubectl apply -k deploy/ 应用时会同时作用于 DaemonSet 与 Deployment")
    exit 0
}
catch {
    Write-Host ''
    Write-Host ("打包失败：{0}" -f $_.Exception.Message) -ForegroundColor Red
    exit 1
}
