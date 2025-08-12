# Netstat-Who.ps1 (v1.4.0)
# Fixes: proper Point/Size constructors; no inline "if" assignments; UI layout tidied; PS 5.1-safe.
# Features: dark theme default + toggle, CSV export, sort, search, process quick filter,
# expand/collapse all details, port research links, parallel RDAP with cache,
# Owner/Net columns, and a selectable "Show full process path" option.

[CmdletBinding()]
param()

### ---------- UI: Option Picker ----------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function New-Point([int]$x,[int]$y) { New-Object System.Drawing.Point -ArgumentList $x, $y }
function New-Size ([int]$w,[int]$h) { New-Object System.Drawing.Size  -ArgumentList $w, $h }

$form               = New-Object System.Windows.Forms.Form
$form.Text          = "Netstat-Who Options"
$form.StartPosition = "CenterScreen"
$form.Size          = New-Size 620 500
$form.Topmost       = $true

$y = 15
function Add-Check([string]$text,[bool]$checked=$false) {
  $cb = New-Object System.Windows.Forms.CheckBox
  $cb.Text     = $text
  $cb.Location = New-Point 15 $script:y
  $cb.AutoSize = $true
  $cb.Checked  = $checked
  $form.Controls.Add($cb)
  $script:y += 25
  $cb
}

$lblLocalCIDR              = New-Object System.Windows.Forms.Label
$lblLocalCIDR.Text         = "Local CIDR(s) to treat as LAN (comma-separated):"
$lblLocalCIDR.Location     = New-Point 15 ($y + 5)
$lblLocalCIDR.AutoSize     = $true
$form.Controls.Add($lblLocalCIDR)

$txtLocalCIDR              = New-Object System.Windows.Forms.TextBox
$txtLocalCIDR.Location     = New-Point 18 ($y + 25)
$txtLocalCIDR.Size         = New-Size 565 22
$txtLocalCIDR.Text         = ""   # e.g. 192.168.2.0/23
$form.Controls.Add($txtLocalCIDR)

$y += 65

$chkEstablished   = Add-Check "Include ESTABLISHED connections" $true
$chkListening     = Add-Check "Show LISTENING sockets" $false
$chkIncludeLocal  = Add-Check "Include Local/LAN/Loopback peers" $false
$chkResolveDNS    = Add-Check "Resolve reverse DNS for remote IPs" $false
$chkDoRDAP        = Add-Check "Do RDAP owner lookups for remote IPs" $true
$chkUseCache      = Add-Check "Use RDAP cache (faster repeat runs)" $true
$chkClearCache    = Add-Check "Clear RDAP cache now" $false
$chkShowProcPath  = Add-Check "Show full process path" $false

$lblHtml              = New-Object System.Windows.Forms.Label
$lblHtml.Text         = "Export HTML report:"
$lblHtml.Location     = New-Point 15 $y
$lblHtml.AutoSize     = $true
$form.Controls.Add($lblHtml)

$txtHtml              = New-Object System.Windows.Forms.TextBox
$txtHtml.Location     = New-Point 18 ($y + 20)
$txtHtml.Size         = New-Size 470 22
$txtHtml.Text         = ""
$form.Controls.Add($txtHtml)

$btnBrowseHtml              = New-Object System.Windows.Forms.Button
$btnBrowseHtml.Text         = "Browse…"
$btnBrowseHtml.Location     = New-Point 495 ($y + 18)
$btnBrowseHtml.Size         = New-Size 88 26
$btnBrowseHtml.Add_Click({
  $sfd = New-Object System.Windows.Forms.SaveFileDialog
  $sfd.Filter = "HTML files (*.html)|*.html|All files (*.*)|*.*"
  $sfd.FileName = "netstat_who_report.html"
  if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    $txtHtml.Text = $sfd.FileName
  }
})
$form.Controls.Add($btnBrowseHtml)

$y += 56
$chkOpenWhenDone = Add-Check "Open report when done" $true

$btnOK                = New-Object System.Windows.Forms.Button
$btnOK.Text           = "OK"
$btnOK.Size           = New-Size 120 30
$btnOK.Location       = New-Point 330 410
$btnOK.DialogResult   = [System.Windows.Forms.DialogResult]::OK
$form.Controls.Add($btnOK)

$btnCancel            = New-Object System.Windows.Forms.Button
$btnCancel.Text       = "Cancel"
$btnCancel.Size       = New-Size 120 30
$btnCancel.Location   = New-Point 465 410
$btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.Controls.Add($btnCancel)

$form.AcceptButton = $btnOK
$form.CancelButton = $btnCancel

$dialogResult = $form.ShowDialog()
if ($dialogResult -ne [System.Windows.Forms.DialogResult]::OK) { return }

# Selections
$IncludeEstablished = $chkEstablished.Checked
$ShowListening      = $chkListening.Checked
$IncludeLocal       = $chkIncludeLocal.Checked
$ResolveDNS         = $chkResolveDNS.Checked
$DoRDAP             = $chkDoRDAP.Checked
$UseCache           = $chkUseCache.Checked
$ClearCache         = $chkClearCache.Checked
$ShowProcPath       = $chkShowProcPath.Checked
$OpenWhenDone       = $chkOpenWhenDone.Checked

$ReportPath = if ($txtHtml.Text) { $txtHtml.Text } else { Join-Path $env:USERPROFILE "Desktop\netstat_who_report.html" }
$LocalCIDR  = @()
if ($txtLocalCIDR.Text -and $txtLocalCIDR.Text.Trim().Length -gt 0) {
  $LocalCIDR = $txtLocalCIDR.Text.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

### ---------- Helpers ----------
function Encode-Html([string]$s) { try { [System.Web.HttpUtility]::HtmlEncode($s) } catch { [System.Net.WebUtility]::HtmlEncode($s) } }

function Test-PrivateIP {
  param([string]$IP)
  if (-not [System.Net.IPAddress]::TryParse($IP, [ref]([System.Net.IPAddress]$null))) { return $false }
  $ipObj = [System.Net.IPAddress]::Parse($IP)
  if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
    if ($IP -like "fe80*") { return $true }
    if ($IP -like "fc*") { return $true }
    if ($IP -like "fd*") { return $true }
    if ($IP -eq "::1") { return $true }
    return $false
  }
  $b = $ipObj.GetAddressBytes()
  switch ($b[0]) {
    10 { return $true }
    172 { return ($b[1] -ge 16 -and $b[1] -le 31) }
    192 { return ($b[1] -eq 168) }
    169 { return ($b[1] -eq 254) }
    127 { return $true }
    default { return $false }
  }
}

function ConvertFrom-Cidr {
  param([Parameter(Mandatory)][string]$Cidr)
  if ($Cidr -notmatch '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') { return $null }
  $parts = $Cidr -split '/'
  $ipStr = $parts[0]; $plen = [int]$parts[1]
  if ($plen -lt 0 -or $plen -gt 32) { return $null }
  $ipObj = [System.Net.IPAddress]::Parse($ipStr)
  $mask  = [uint32]((0xFFFFFFFF -shl (32 - $plen)) -band 0xFFFFFFFF)
  $maskBytes = [BitConverter]::GetBytes($mask); [Array]::Reverse($maskBytes)
  $maskIp = [System.Net.IPAddress]::Parse(($maskBytes -join '.'))
  $ipBytes = $ipObj.GetAddressBytes()
  $netBytes = for ($i=0; $i -lt 4; $i++) { $ipBytes[$i] -band $maskBytes[$i] }
  $netIp = [System.Net.IPAddress]::Parse(($netBytes -join '.'))
  [pscustomobject]@{ Network = $netIp; Mask = $maskIp; Prefix = $plen }
}

function Get-LocalSubnets {
  $subnets = @()
  Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Manual, Dhcp -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -and $_.PrefixLength -ge 1 -and $_.PrefixLength -le 32 } |
    ForEach-Object {
      try {
        $cidr = "$($_.IPAddress)/$($_.PrefixLength)"
        $o = ConvertFrom-Cidr -Cidr $cidr
        if ($o) { $subnets += $o }
      } catch {}
    }
  if ($LocalCIDR) {
    foreach ($c in $LocalCIDR) { $o = ConvertFrom-Cidr -Cidr $c; if ($o) { $subnets += $o } }
  }
  $subnets | Sort-Object Network,Prefix -Unique
}

function Test-LocalSubnet {
  param([string]$IP)
  if (-not [System.Net.IPAddress]::TryParse($IP, [ref]([System.Net.IPAddress]$null))) { return $false }
  $ipObj = [System.Net.IPAddress]::Parse($IP)
  if ($ipObj.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
  foreach ($net in $script:LocalSubnets) {
    $maskBytes = $net.Mask.GetAddressBytes()
    $ipBytes   = $ipObj.GetAddressBytes()
    $netBytes  = $net.Network.GetAddressBytes()
    $match = $true
    for ($i=0; $i -lt 4; $i++) {
      if (($ipBytes[$i] -band $maskBytes[$i]) -ne $netBytes[$i]) { $match = $false; break }
    }
    if ($match) { return $true }
  }
  return $false
}

function ShouldExcludeIP {
  param([string]$IP, [bool]$IncludeLocalFlag)
  if ([string]::IsNullOrWhiteSpace($IP)) { return $false }
  if ($IncludeLocalFlag) { return $false }
  if (Test-PrivateIP $IP) { return $true }
  if (Test-LocalSubnet $IP) { return $true }
  return $false
}

# ---------- Port name lookup (services file + friendly overrides) ----------
$PortOverrides = @{
  "20/tcp"="ftp-data"; "21/tcp"="ftp"; "22/tcp"="ssh"; "23/tcp"="telnet"; "25/tcp"="smtp"
  "53/tcp"="dns"; "53/udp"="dns"
  "67/udp"="dhcp-server"; "68/udp"="dhcp-client"
  "80/tcp"="http"; "110/tcp"="pop3"; "123/udp"="ntp"
  "135/tcp"="epmap"; "137/udp"="netbios-ns"; "138/udp"="netbios-dgm"; "139/tcp"="netbios-ssn"
  "143/tcp"="imap"; "161/udp"="snmp"; "389/tcp"="ldap"; "443/tcp"="https"; "445/tcp"="smb"
  "465/tcp"="smtps"; "587/tcp"="submission"; "993/tcp"="imaps"; "995/tcp"="pop3s"
  "1194/udp"="openvpn"; "1433/tcp"="mssql"; "1521/tcp"="oracle"; "2049/tcp"="nfs"
  "2379/tcp"="etcd"; "2380/tcp"="etcd-peer"; "2483/tcp"="oracle"
  "27017/tcp"="mongodb"; "3000/tcp"="http-alt"; "3306/tcp"="mysql"; "3389/tcp"="rdp"
  "4369/tcp"="epmd"; "5000/tcp"="http-alt"; "5040/tcp"="unknown"
  "5060/tcp"="sip"; "5060/udp"="sip"; "5432/tcp"="postgres"; "5601/tcp"="kibana"; "5672/tcp"="amqp"
  "5900/tcp"="vnc"; "5985/tcp"="winrm"; "5986/tcp"="winrm-https"; "6379/tcp"="redis"
  "6443/tcp"="kube-apiserver"; "8000/tcp"="http-alt"; "8080/tcp"="http-alt"; "8443/tcp"="https-alt"
  "8883/tcp"="mqtts"; "9000/tcp"="minio-ui"; "9042/tcp"="cassandra"; "9200/tcp"="elasticsearch"
}

$script:ServicesIndex = $null
function Get-ServicesIndex {
  if ($script:ServicesIndex) { return $script:ServicesIndex }
  $idx = @{}
  $svcPath = Join-Path $env:SystemRoot "System32\drivers\etc\services"
  if (-not (Test-Path $svcPath)) { $script:ServicesIndex = @{}; return $script:ServicesIndex }

  $lines = Get-Content -LiteralPath $svcPath -Encoding ascii
  foreach ($line in $lines) {
    if ($line -match '^\s*#') { continue }
    if ($line -match '^\s*([A-Za-z0-9\.\-_]+)\s+(\d+)\/(tcp|udp)\s*([^#]*)') {
      $name  = $matches[1]
      $port  = [int]$matches[2]
      $proto = $matches[3].ToLower()
      $aliases = @()
      if ($matches[4]) {
        $aliases = ($matches[4] -split '\s+') | Where-Object { $_ -and $_ -notmatch '^\s*$' }
      }
      if (-not $idx.ContainsKey($port)) { $idx[$port] = @{ tcp = @(); udp = @() } }
      if ($idx[$port][$proto] -notcontains $name)   { $idx[$port][$proto] += $name }
      foreach ($a in $aliases) {
        if ($a -and $idx[$port][$proto] -notcontains $a) { $idx[$port][$proto] += $a }
      }
    }
  }
  $script:ServicesIndex = $idx
  return $script:ServicesIndex
}

function Get-PortName {
  param(
    [Parameter(Mandatory)] [int]$Port,
    [ValidateSet('tcp','udp')] [string]$Protocol = 'tcp'
  )
  $keyProto = "$Port/$Protocol"
  if ($PortOverrides.ContainsKey($keyProto)) { return $PortOverrides[$keyProto] }
  if ($PortOverrides.ContainsKey("$Port"))   { return $PortOverrides["$Port"] }

  $idx = Get-ServicesIndex
  if ($idx.ContainsKey($Port)) {
    $names = $idx[$Port][$Protocol]
    if ($names -and $names.Count -gt 0) { return $names[0] }
    $other = @{ 'tcp'='udp'; 'udp'='tcp' }[$Protocol]
    $namesOther = $idx[$Port][$other]
    if ($namesOther -and $namesOther.Count -gt 0) { return $namesOther[0] }
  }

  if     ($Port -le 1023)  { return "well-known" }
  elseif ($Port -le 49151) { return "registered" }
  else                     { return "dynamic/private" }
}

function Get-PortLinksHtml { param([int]$Port)
  if ($Port -lt 1 -or $Port -gt 65535) { return "" }
  $p = [uri]::EscapeDataString($Port)
  $links = @(
    @{n="IANA";       u="https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=$p"},
    @{n="SpeedGuide"; u="https://www.speedguide.net/port.php?port=$p"},
    @{n="SANS ISC";   u="https://isc.sans.edu/port.html?port=$p"},
    @{n="Wikipedia";  u="https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"}
  )
  ($links | ForEach-Object { "<a href='$($_.u)' target='_blank' rel='noopener'>$($_.n)</a>" }) -join " &middot; "
}

# ---------- RDAP cache (PS 5.1-safe) ----------
$CacheDir  = Join-Path $env:LOCALAPPDATA "NetstatWho"
$CacheFile = Join-Path $CacheDir "rdap_cache.json"
$RdapCache = @{}

if ($ClearCache -and (Test-Path $CacheFile)) {
  Remove-Item $CacheFile -Force -ErrorAction SilentlyContinue
}

if ($UseCache -and (Test-Path $CacheFile)) {
  try {
    $json = Get-Content -LiteralPath $CacheFile -Raw -ErrorAction Stop
    if ($json) {
      $tmp = ConvertFrom-Json $json
      $RdapCache = @{}
      if ($tmp -is [System.Management.Automation.PSCustomObject]) {
        foreach ($p in $tmp.PSObject.Properties) { $RdapCache[$p.Name] = $p.Value }
      } elseif ($tmp -is [System.Collections.IEnumerable] -and $tmp -isnot [string]) {
        foreach ($item in $tmp) { if ($item.IP) { $RdapCache[$item.IP] = $item } }
      }
    }
  } catch { $RdapCache = @{} }
}

### ---------- Begin Work ----------
$script:LocalSubnets = Get-LocalSubnets

$rows = @()
$remoteIps = [System.Collections.Generic.HashSet[string]]::new()

# Gather connections
$allTCP  = Get-NetTCPConnection -ErrorAction SilentlyContinue
$allUDP  = Get-NetUDPEndpoint   -ErrorAction SilentlyContinue

# Build PID -> @{ Name; Path }
$pids = @($allTCP.OwningProcess + $allUDP.OwningProcess) | Where-Object { $_ } | Sort-Object -Unique
$procMap = @{}
try {
  if ($pids.Count -gt 0) {
    $filter = ($pids | ForEach-Object { "ProcessId=$_" }) -join ' OR '
    $procs = Get-CimInstance Win32_Process -Filter $filter -ErrorAction Stop
    foreach ($p in $procs) {
      $procMap[[int]$p.ProcessId] = @{ Name = $p.Name; Path = $p.ExecutablePath }
    }
  }
} catch {
  foreach ($procId in $pids) {
    try {
      $gp = Get-Process -Id $procId -ErrorAction Stop
      $path = $null; try { $path = $gp.Path } catch {}
      $procMap[$procId] = @{ Name = $gp.ProcessName; Path = $path }
    } catch {}
  }
}

# Listening rows
if ($ShowListening) {
  $rows += ($allTCP | Where-Object { $_.State -eq 'Listen' } | ForEach-Object {
    $pname = $null; if ($procMap.ContainsKey($_.OwningProcess)) { $pname = $procMap[$_.OwningProcess].Name }
    [pscustomobject]@{
      Protocol="TCP"; State="LISTEN"; Process=$pname; PID=$_.OwningProcess
      Local="$($_.LocalAddress):$($_.LocalPort)"; Remote=""; RemoteIP=$null
      LocalPort=$_.LocalPort; RemotePort=$null
      RemoteHost=$null; RemoteOwner=$null; RemoteNet=$null; RemoteCIDR=$null; RemoteCountry=$null
    }
  })
  $rows += ($allUDP | ForEach-Object {
    $pname = $null; if ($procMap.ContainsKey($_.OwningProcess)) { $pname = $procMap[$_.OwningProcess].Name }
    [pscustomobject]@{
      Protocol="UDP"; State="LISTEN"; Process=$pname; PID=$_.OwningProcess
      Local="$($_.LocalAddress):$($_.LocalPort)"; Remote=""; RemoteIP=$null
      LocalPort=$_.LocalPort; RemotePort=$null
      RemoteHost=$null; RemoteOwner=$null; RemoteNet=$null; RemoteCIDR=$null; RemoteCountry=$null
    }
  })
}

# Established rows
if ($IncludeEstablished) {
  $rows += ($allTCP | Where-Object { $_.State -eq 'Established' } | ForEach-Object {
    $rip = $_.RemoteAddress
    if (ShouldExcludeIP -IP $rip -IncludeLocalFlag:$IncludeLocal) { return }
    $remoteEP = "${rip}:$($_.RemotePort)"
    [void]$remoteIps.Add($rip)
    $pname = $null; if ($procMap.ContainsKey($_.OwningProcess)) { $pname = $procMap[$_.OwningProcess].Name }
    [pscustomobject]@{
      Protocol="TCP"; State="ESTABLISHED"; Process=$pname; PID=$_.OwningProcess
      Local="$($_.LocalAddress):$($_.LocalPort)"; Remote=$remoteEP; RemoteIP=$rip
      LocalPort=$_.LocalPort; RemotePort=$_.RemotePort
      RemoteHost=$null; RemoteOwner=$null; RemoteNet=$null; RemoteCIDR=$null; RemoteCountry=$null
    }
  })
}

# RDAP (parallel) for public IPs
$rdapResults = @{}
$rdapCacheOutChanged = $false
if ($DoRDAP) {
  $ips = @()
  foreach ($ip in $remoteIps) {
    if ([string]::IsNullOrWhiteSpace($ip)) { continue }
    if (Test-PrivateIP $ip) { continue }
    if (Test-LocalSubnet $ip) { continue }
    if ($UseCache -and $RdapCache.ContainsKey($ip)) { $rdapResults[$ip] = $RdapCache[$ip] } else { $ips += $ip }
  }

  if ($ips.Count -gt 0) {
    $maxThreads = [Math]::Max(4, [Environment]::ProcessorCount * 2)
    $pool = [RunspaceFactory]::CreateRunspacePool(1, $maxThreads)
    $pool.ApartmentState = 'MTA'
    $pool.Open()
    $jobs = @()
    foreach ($ip in $ips) {
      $ps = [PowerShell]::Create()
      $null = $ps.AddScript({
        param($ip)
        $ErrorActionPreference = 'Stop'
        try {
          $rdap = Invoke-RestMethod -Method GET -Uri ("https://rdap.org/ip/" + $ip) -TimeoutSec 8
          $org = ""
          if ($rdap.entities) {
            foreach ($e in $rdap.entities) {
              if ($e.vcardArray -and $e.vcardArray.Count -ge 2) {
                foreach ($entry in $e.vcardArray[1]) {
                  if ($entry[0] -eq "fn"  -and $entry[3]) { $org = $entry[3]; break }
                  if ($entry[0] -eq "org" -and $entry[3]) { $org = ($entry[3] -join " "); break }
                }
              }
              if ($org) { break }
            }
          }
          if (-not $org) { $org = $rdap.name }
          $cidr = $null
          if ($rdap.cidr0_cidrs -and $rdap.cidr0_cidrs.Count -gt 0) {
            $c = $rdap.cidr0_cidrs | Select-Object -First 1
            $cidr = "$($c.v4prefix)/$($c.length)"
          } elseif ($rdap.startAddress -and $rdap.endAddress) {
            $cidr = "$($rdap.startAddress) - $($rdap.endAddress)"
          }
          [pscustomobject]@{ IP=$ip; Org=$org; Network=$rdap.name; Country=$rdap.country; ASN=""; CIDR=$cidr }
        } catch {
          [pscustomobject]@{ IP=$ip; Org="(lookup failed)"; Network=""; Country=""; ASN=""; CIDR="" }
        }
      }).AddArgument($ip)
      $ps.RunspacePool = $pool
      $jobs += [pscustomobject]@{ PS=$ps; Handle=$ps.BeginInvoke(); IP=$ip }
    }
    foreach ($j in $jobs) {
      try {
        $out = $j.PS.EndInvoke($j.Handle)
        if ($out) {
          $obj = $out[0]
          $rdapResults[$j.IP] = $obj
          if ($UseCache) { $RdapCache[$j.IP] = $obj; $rdapCacheOutChanged = $true }
        }
      } catch {
        $obj = [pscustomobject]@{ IP=$j.IP; Org="(lookup failed)"; Network=""; Country=""; ASN=""; CIDR="" }
        $rdapResults[$j.IP] = $obj
        if ($UseCache) { $RdapCache[$j.IP] = $obj; $rdapCacheOutChanged = $true }
      } finally { $j.PS.Dispose() }
    }
    $pool.Close(); $pool.Dispose()
  }
}

# reverse DNS (optional)
$ptrCache = @{}
if ($ResolveDNS) {
  foreach ($ip in $remoteIps) {
    if ([string]::IsNullOrWhiteSpace($ip)) { continue }
    try { $ptr = [System.Net.Dns]::GetHostEntry($ip).HostName } catch { $ptr = $null }
    $ptrCache[$ip] = $ptr
  }
}

# Final dataset enriched
$result = $rows | Sort-Object Protocol, State, Process, Local | ForEach-Object {
  $ip  = $_.RemoteIP
  $rd  = $null
  if ($ip -and $rdapResults.ContainsKey($ip)) { $rd = $rdapResults[$ip] }
  $ptr = $null
  if ($ip -and $ptrCache.ContainsKey($ip)) { $ptr = $ptrCache[$ip] }

  [pscustomobject]@{
    Protocol      = $_.Protocol
    State         = $_.State
    Process       = $_.Process
    PID           = $_.PID
    Local         = $_.Local
    Remote        = $_.Remote
    RemoteIP      = $ip
    LocalPort     = $_.LocalPort
    RemotePort    = $_.RemotePort
    RemoteHost    = $ptr
    RemoteOwner   = if ($rd) { $rd.Org } else { $null }
    RemoteNet     = if ($rd) { $rd.Network } else { $null }
    RemoteCIDR    = if ($rd) { $rd.CIDR } else { $null }
    RemoteCountry = if ($rd) { $rd.Country } else { $null }
  }
}

### ---------- Build Process Filter options (name vs path, based on toggle) ----------
$procFilterSet = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($r in $result) {
  $disp = $r.Process
  if ($ShowProcPath -and $procMap.ContainsKey([int]$r.PID)) {
    $pp = $procMap[[int]$r.PID].Path
    if ($pp) { $disp = $pp }
  }
  if ($disp) { [void]$procFilterSet.Add($disp) }
}

$procOptions = New-Object System.Text.StringBuilder
[void]$procOptions.AppendLine("<option value='ALL'>All processes</option>")

# HashSet is enumerable; no ToArray() needed
$procList = $procFilterSet | Sort-Object
foreach ($p in $procList) {
  $enc = Encode-Html $p
  [void]$procOptions.AppendLine("<option value='$enc'>$enc</option>")
}

### ---------- HTML/JS (dark default + theme toggle etc.) ----------
$style = @"
<style>
:root { color-scheme: dark light; --bg:#0f1115; --fg:#e6e6e6; --muted:#9aa0a6; --border:#2a2f39; --row:#151924; --th:#161b26; --btn-bg:#1b2230; --btn-border:#2a2f39; --link:#8ab4f8; }
body.light { --bg:#ffffff; --fg:#111; --muted:#555; --border:#e6e6e6; --row:#fafafa; --th:#f3f3f3; --btn-bg:#f6f6f6; --btn-border:#ccc; --link:#1a73e8; }
body { background:var(--bg); color:var(--fg); font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }
h1 { font-size: 22px; margin: 0 0 6px 0; }
.sub { color: var(--muted); margin-bottom: 16px; }
.controls { margin: 10px 0 16px 0; display: flex; gap: 8px; flex-wrap: wrap; align-items:center; }
input, select { padding: 6px 8px; border: 1px solid var(--btn-border); border-radius: 6px; background: var(--bg); color: var(--fg); }
#filter { width: 280px; }
button { padding: 6px 10px; border: 1px solid var(--btn-border); border-radius: 6px; background: var(--btn-bg); color: var(--fg); cursor:pointer; }
a { color: var(--link); }
table { border-collapse: collapse; width: 100%; }
th, td { padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { text-align: left; background: var(--th); position: sticky; top: 0; z-index: 1; cursor: pointer; user-select: none; }
tr:hover { background: var(--row); }
.badge { display:inline-block; padding:2px 6px; border-radius:6px; font-size:12px; background:#39465e; color:#dfe7ff; }
body.light .badge { background:#eef; color:#334; }
.details { font-size: 12px; color: var(--fg); }
.details summary { cursor:pointer; }
.links a { margin-right: 10px; }
.small { color:var(--muted); font-size:12px; }
footer { color:var(--muted); font-size:12px; margin-top:18px; }
.sort-ind { font-size: 11px; opacity: .7; }
.theme-note { color: var(--muted); font-size: 12px; margin-left: 6px; }
label { color: var(--muted); font-size: 12px; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }
</style>
"@

$scriptJs = @"
<script>
(function initTheme(){
  const saved = localStorage.getItem('netstatwho-theme') || 'dark';
  if(saved === 'light') document.body.classList.add('light');
})();
function postInit(){
  const label = document.getElementById('themeLabel');
  if (label) { label.innerText = document.body.classList.contains('light') ? 'Light' : 'Dark'; }
}
function toggleTheme(){
  document.body.classList.toggle('light');
  const mode = document.body.classList.contains('light') ? 'light' : 'dark';
  localStorage.setItem('netstatwho-theme', mode);
  document.getElementById('themeLabel').innerText = mode === 'light' ? 'Light' : 'Dark';
}
function applyFilters() {
  const q = document.getElementById('filter').value.toLowerCase();
  const sel = document.getElementById('procFilter').value;
  const rows = document.querySelectorAll('#data tbody tr');
  rows.forEach(r => {
    const txt = r.innerText.toLowerCase();
    const proc = (r.children[2] && r.children[2].innerText.trim()) || '';
    let ok = true;
    if (q) ok = txt.indexOf(q) >= 0;
    if (ok && sel !== 'ALL') ok = (proc === sel);
    r.style.display = ok ? '' : 'none';
  });
}
function toCSV() {
  const rows = [...document.querySelectorAll('#data tbody tr')].filter(r => r.style.display !== 'none');
  const header = [...document.querySelectorAll('#data thead th')].map(th => th.innerText.replace(/,|\\n/g,' ').trim());
  const data = rows.map(r => [...r.querySelectorAll('td')].map(td => td.innerText.replace(/,|\\n/g,' ').trim()));
  const lines = [header.join(',')].concat(data.map(a => a.join(',')));
  const blob = new Blob([lines.join('\\n')], {type:'text/csv'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'netstat_who.csv'; a.click();
}
let sortState = { idx: 0, dir: 1 };
function sortTable(idx) {
  const tb = document.querySelector('#data tbody');
  const rows = [...tb.querySelectorAll('tr')];
  if (sortState.idx === idx) { sortState.dir = -sortState.dir; } else { sortState.idx = idx; sortState.dir = 1; }
  const numCols = new Set([3]); // PID numeric
  const cmp = (a,b) => {
    const ta = a.children[idx].innerText.trim();
    const tbv = b.children[idx].innerText.trim();
    if (numCols.has(idx)) { return (parseInt(ta)||0) - (parseInt(tbv)||0); }
    return ta.localeCompare(tbv, undefined, {numeric:true, sensitivity:'base'});
  };
  rows.sort((r1,r2) => sortState.dir * cmp(r1,r2)).forEach(r => tb.appendChild(r));
  document.querySelectorAll('#data thead th .sort-ind').forEach(s => s.innerText = '');
  const th = document.querySelectorAll('#data thead th')[idx];
  const ind = th.querySelector('.sort-ind'); if (ind) ind.innerText = sortState.dir===1 ? '▲' : '▼';
}
function expandAllDetails() { document.querySelectorAll('#data details').forEach(d => d.open = true); }
function collapseAllDetails(){ document.querySelectorAll('#data details').forEach(d => d.open = false); }
</script>
"@

# Build table rows (process column respects toggle) + details
$rowsHtml = New-Object System.Text.StringBuilder
foreach ($r in $result) {
  $ip = $r.RemoteIP

  # IP research links
  $linksHtml = ""
  if ($ip) {
    $linksHtml = @(
      "<div class='links'>",
      (@(
        "<a href='https://rdap.org/ip/$ip' target='_blank' rel='noopener'>RDAP</a>",
        "<a href='https://search.arin.net/rdap/?query=$ip' target='_blank' rel='noopener'>ARIN RDAP</a>",
        "<a href='https://www.virustotal.com/gui/ip-address/$ip' target='_blank' rel='noopener'>VirusTotal</a>",
        "<a href='https://www.abuseipdb.com/check/$ip' target='_blank' rel='noopener'>AbuseIPDB</a>",
        "<a href='https://www.shodan.io/host/$ip' target='_blank' rel='noopener'>Shodan</a>",
        "<a href='https://search.censys.io/hosts/$ip' target='_blank' rel='noopener'>Censys</a>",
        "<a href='https://viz.greynoise.io/ip/$ip' target='_blank' rel='noopener'>GreyNoise</a>",
        "<a href='https://talosintelligence.com/reputation_center/lookup?search=$ip' target='_blank' rel='noopener'>Talos</a>",
        "<a href='https://securitytrails.com/list/ip/$ip' target='_blank' rel='noopener'>SecurityTrails</a>",
        "<a href='https://bgp.he.net/ip/$ip' target='_blank' rel='noopener'>BGP.he.net</a>",
        "<a href='https://mxtoolbox.com/SuperTool.aspx?action=ptr:$ip' target='_blank' rel='noopener'>MXToolbox PTR</a>",
        "<a href='https://ipinfo.io/$ip' target='_blank' rel='noopener'>IPinfo</a>"
      ) -join " &middot; "),
      "</div>"
    ) -join ""
  }

  # Ports block
  $lp = 0; if ($r.LocalPort)  { $lp = [int]$r.LocalPort }
  $rp = 0; if ($r.RemotePort) { $rp = [int]$r.RemotePort }

  $proto = 'tcp'
  if ($r.Protocol) { try { $proto = $r.Protocol.ToString().ToLower() } catch {} }

  $lpName = $null
  if ($lp -gt 0) { $lpName = Get-PortName -Port $lp -Protocol $proto }
  $rpName = $null
  if ($rp -gt 0) { $rpName = Get-PortName -Port $rp -Protocol $proto }
  $lpLinks = ""; if ($lp -gt 0) { $lpLinks = Get-PortLinksHtml -Port $lp }
  $rpLinks = ""; if ($rp -gt 0) { $rpLinks = Get-PortLinksHtml -Port $rp }

  $portParts = @()
  if ($lp -gt 0) {
    $p = "local $lp"; if ($lpName) { $p += " ($lpName)" }; if ($lpLinks) { $p += " — $lpLinks" }
    $portParts += $p
  }
  if ($rp -gt 0) {
    $p = "remote $rp"; if ($rpName) { $p += " ($rpName)" }; if ($rpLinks) { $p += " — $rpLinks" }
    $portParts += $p
  }
  $portsHtml = ""
  if ($portParts.Count -gt 0) { $portsHtml = "<div class='small'><strong>Ports:</strong> " + ($portParts -join " &nbsp;/&nbsp; ") + "</div>" }

  # Owner/Net as columns
  $ownerText = $r.RemoteOwner
  $netText   = $r.RemoteNet

  # Details (CIDR/Country/rDNS/ports/links)
  $cidrHtml    = "<div class='small'><strong>CIDR:</strong> $($r.RemoteCIDR)</div>"
  $countryHtml = "<div class='small'><strong>Country:</strong> $($r.RemoteCountry)</div>"
  $rdnsHtml    = ""; if ($r.RemoteHost) { $rdnsHtml = "<div class='small'><strong>Reverse DNS:</strong> $($r.RemoteHost)</div>" }

  $detailBlock = ""
  if ($ip) {
    $detailBlock = "<details class='details'><summary>$ip</summary>$cidrHtml$countryHtml$rdnsHtml$portsHtml$linksHtml</details>"
  }

  # Process display (name vs path) + tooltip with the alternate
  $procCell = ""
  $disp = $r.Process
  $tooltip = ""
  if ($procMap.ContainsKey([int]$r.PID)) {
    $pinfo = $procMap[[int]$r.PID]
    $pname = $pinfo.Name
    $ppath = $pinfo.Path
    if ($ShowProcPath -and $ppath) {
      $disp = $ppath
      if ($pname) { $tooltip = $pname }
    } else {
      $disp = $pname
      if ($ppath) { $tooltip = $ppath }
    }
  }
  if (-not $disp) { $disp = $r.Process }
  if ($tooltip) {
    $procCell = "<td title='$(Encode-Html $tooltip)'><code>$(Encode-Html $disp)</code></td>"
  } else {
    $procCell = "<td><code>$(Encode-Html $disp)</code></td>"
  }

  [void]$rowsHtml.AppendLine(@"
  <tr>
    <td>$($r.Protocol)</td>
    <td><span class='badge'>$($r.State)</span></td>
    $procCell
    <td>$($r.PID)</td>
    <td>$(Encode-Html $r.Local)</td>
    <td>$(Encode-Html $r.Remote)</td>
    <td>$(Encode-Html $ownerText)</td>
    <td>$(Encode-Html $netText)</td>
    <td>$detailBlock</td>
  </tr>
"@)
}

# Header subtext (precomputed to avoid inline-if surprises)
$txtEstablished = "(no Established)"; if ($IncludeEstablished) { $txtEstablished = "Established" }
$txtListening   = ""; if ($ShowListening) { $txtListening = " + Listening" }
$txtLocal       = " + Public only"; if ($IncludeLocal) { $txtLocal = " + Local/LAN" }
$txtRdns        = ""; if ($ResolveDNS) { $txtRdns = " + rDNS" }
$txtRdap        = " + (RDAP off)"; if ($DoRDAP) { $txtRdap = " + RDAP" }

$colProcessHeader = "Process"
if ($ShowProcPath) { $colProcessHeader = "Process (Path)" }

$themeLabel = "Dark"

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Netstat-Who Report</title>
$style
$scriptJs
</head>
<body onload="postInit()">
  <h1>Netstat-Who Report</h1>
  <div class="sub">
    Generated: $((Get-Date).ToString("yyyy-MM-dd HH:mm:ss")) &middot;
    $txtEstablished$txtListening$txtLocal$txtRdns$txtRdap
  </div>

  <div class="controls">
    <input id="filter" type="text" placeholder="Search rows (process, IP, owner, etc.)" onkeyup="applyFilters()" />
    <label for="procFilter">Process:</label>
    <select id="procFilter" onchange="applyFilters()">
      $procOptions
    </select>
    <button onclick="toCSV()">Export CSV</button>
    <button onclick="expandAllDetails()">Expand all details</button>
    <button onclick="collapseAllDetails()">Collapse all</button>
    <button onclick="toggleTheme()">Toggle Theme</button>
    <span id="themeLabel" class="theme-note">$themeLabel</span>
  </div>

  <table id="data">
    <thead>
        <tr>
            <th onclick="sortTable(0)">Proto <span class="sort-ind"></span></th>
            <th onclick="sortTable(1)">State <span class="sort-ind"></span></th>
            <th onclick="sortTable(2)">$colProcessHeader <span class="sort-ind"></span></th>
            <th onclick="sortTable(3)">PID <span class="sort-ind"></span></th>
            <th onclick="sortTable(4)">Local <span class="sort-ind"></span></th>
            <th onclick="sortTable(5)">Remote <span class="sort-ind"></span></th>
            <th onclick="sortTable(6)">Owner <span class="sort-ind"></span></th>
            <th onclick="sortTable(7)">Net <span class="sort-ind"></span></th>
            <th onclick="sortTable(8)">Remote IP &amp; Research <span class="sort-ind"></span></th>
        </tr>
    </thead>
    <tbody>
      $rowsHtml
    </tbody>
  </table>

  <footer>
    Tip: use the Process dropdown for quick filtering, the search box for text filtering, click headers to sort, and “Expand all details” to open all IP panels.
  </footer>
</body>
</html>
"@

try {
  $dir = Split-Path -Parent $ReportPath
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $html | Out-File -FilePath $ReportPath -Encoding utf8
  Write-Host "Report written to: $ReportPath"
  if ($OpenWhenDone) { Start-Process $ReportPath }
} catch {
  Write-Warning "Failed to write HTML report: $($_.Exception.Message)"
}

if ($DoRDAP -and $UseCache) {
  try {
    if (-not (Test-Path $CacheDir)) { New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null }
    $RdapCache | ConvertTo-Json -Depth 8 | Out-File -FilePath $CacheFile -Encoding utf8
  } catch {
    Write-Warning "Failed to save RDAP cache: $($_.Exception.Message)"
  }
}
