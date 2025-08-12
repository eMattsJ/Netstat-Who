# Netstat-Who.ps1
# Windows PowerShell 5.1+ | Creates an HTML report with drill-down research links for remote IPs

[CmdletBinding()]
param()

### ---------- UI: Option Picker ----------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form                = New-Object System.Windows.Forms.Form
$form.Text           = "Netstat-Who Options"
$form.StartPosition  = "CenterScreen"
$form.Size           = New-Object System.Drawing.Size(560, 360)
$form.Topmost        = $true

$chkEstablished      = New-Object System.Windows.Forms.CheckBox
$chkEstablished.Text = "Include ESTABLISHED connections"
$chkEstablished.Location = New-Object System.Drawing.Point(15, 15)
$chkEstablished.AutoSize = $true
$chkEstablished.Checked  = $true

$chkListening      = New-Object System.Windows.Forms.CheckBox
$chkListening.Text = "Show LISTENING sockets"
$chkListening.Location = New-Object System.Drawing.Point(15, 40)
$chkListening.AutoSize = $true
$chkListening.Checked  = $false

$chkIncludeLocal      = New-Object System.Windows.Forms.CheckBox
$chkIncludeLocal.Text = "Include Local/LAN/Loopback peers"
$chkIncludeLocal.Location = New-Object System.Drawing.Point(15, 65)
$chkIncludeLocal.AutoSize = $true
$chkIncludeLocal.Checked  = $false

$chkResolveDNS      = New-Object System.Windows.Forms.CheckBox
$chkResolveDNS.Text = "Resolve reverse DNS for remote IPs"
$chkResolveDNS.Location = New-Object System.Drawing.Point(15, 90)
$chkResolveDNS.AutoSize = $true
$chkResolveDNS.Checked  = $false

$lblLocalCIDR      = New-Object System.Windows.Forms.Label
$lblLocalCIDR.Text = "Local CIDR(s) to treat as LAN (comma-separated):"
$lblLocalCIDR.Location = New-Object System.Drawing.Point(15, 125)
$lblLocalCIDR.AutoSize = $true

$txtLocalCIDR      = New-Object System.Windows.Forms.TextBox
$txtLocalCIDR.Location = New-Object System.Drawing.Point(18, 145)
$txtLocalCIDR.Size      = New-Object System.Drawing.Size(510, 22)
$txtLocalCIDR.Text      = ""   # e.g. "192.168.2.0/23"

$lblHtml      = New-Object System.Windows.Forms.Label
$lblHtml.Text = "Export HTML report:"
$lblHtml.Location = New-Object System.Drawing.Point(15, 180)
$lblHtml.AutoSize = $true

$txtHtml      = New-Object System.Windows.Forms.TextBox
$txtHtml.Location = New-Object System.Drawing.Point(18, 200)
$txtHtml.Size      = New-Object System.Drawing.Size(425, 22)
$txtHtml.Text      = ""

$btnBrowseHtml          = New-Object System.Windows.Forms.Button
$btnBrowseHtml.Text     = "Browse…"
$btnBrowseHtml.Location = New-Object System.Drawing.Point(450, 198)
$btnBrowseHtml.Add_Click({
  $sfd = New-Object System.Windows.Forms.SaveFileDialog
  $sfd.Filter = "HTML files (*.html)|*.html|All files (*.*)|*.*"
  $sfd.FileName = "netstat_who_report.html"
  if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    $txtHtml.Text = $sfd.FileName
  }
})

$chkOpenWhenDone      = New-Object System.Windows.Forms.CheckBox
$chkOpenWhenDone.Text = "Open report when done"
$chkOpenWhenDone.Location = New-Object System.Drawing.Point(15, 235)
$chkOpenWhenDone.AutoSize = $true
$chkOpenWhenDone.Checked  = $true

$btnOK                = New-Object System.Windows.Forms.Button
$btnOK.Text           = "OK"
$btnOK.Width          = 110
$btnOK.Location       = New-Object System.Drawing.Point(298, 270)
$btnOK.DialogResult   = [System.Windows.Forms.DialogResult]::OK

$btnCancel            = New-Object System.Windows.Forms.Button
$btnCancel.Text       = "Cancel"
$btnCancel.Width      = 110
$btnCancel.Location   = New-Object System.Drawing.Point(418, 270)
$btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

$form.AcceptButton = $btnOK
$form.CancelButton = $btnCancel

$form.Controls.AddRange(@(
  $chkEstablished, $chkListening, $chkIncludeLocal, $chkResolveDNS,
  $lblLocalCIDR, $txtLocalCIDR, $lblHtml, $txtHtml, $btnBrowseHtml,
  $chkOpenWhenDone, $btnOK, $btnCancel
))

$dialogResult = $form.ShowDialog()
if ($dialogResult -ne [System.Windows.Forms.DialogResult]::OK) { return }

# Capture selections
$IncludeEstablished = $chkEstablished.Checked
$ShowListening      = $chkListening.Checked
$IncludeLocal       = $chkIncludeLocal.Checked
$ResolveDNS         = $chkResolveDNS.Checked
$OpenWhenDone       = $chkOpenWhenDone.Checked

$ReportPath = $txtHtml.Text
if (-not $ReportPath) {
  $ReportPath = Join-Path -Path $env:USERPROFILE -ChildPath "Desktop\netstat_who_report.html"
}

$LocalCIDR = @()
if ($txtLocalCIDR.Text -and $txtLocalCIDR.Text.Trim().Length -gt 0) {
  $LocalCIDR = $txtLocalCIDR.Text.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

### ---------- Helpers ----------
function Test-PrivateIP {
  param([string]$IP)
  if (-not [System.Net.IPAddress]::TryParse($IP, [ref]([System.Net.IPAddress]$null))) { return $false }
  $ipObj = [System.Net.IPAddress]::Parse($IP)
  if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
    if ($IP -like "fe80*") { return $true }  # link-local
    if ($IP -like "fc*")   { return $true }  # ULA
    if ($IP -like "fd*")   { return $true }  # ULA
    if ($IP -eq "::1")     { return $true }  # loopback
    return $false
  }
  $bytes = $ipObj.GetAddressBytes()
  switch ($bytes[0]) {
    10      { return $true }
    172     { return ($bytes[1] -ge 16 -and $bytes[1] -le 31) }
    192     { return ($bytes[1] -eq 168) }
    169     { return ($bytes[1] -eq 254) }  # link-local
    127     { return $true }                # loopback
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
    foreach ($c in $LocalCIDR) {
      $o = ConvertFrom-Cidr -Cidr $c
      if ($o) { $subnets += $o }
    }
  }
  $subnets | Sort-Object Network,Prefix -Unique
}

function Test-LocalSubnet {
  param([string]$IP)
  if (-not [System.Net.IPAddress]::TryParse($IP, [ref]([System.Net.IPAddress]$null))) { return $false }
  $ipObj = [System.Net.IPAddress]::Parse($IP)
  if ($ipObj.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false } # IPv4 only
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

function Get-RdapInfo {
  param([Parameter(Mandatory=$true)][string]$IP)
  $url = "https://rdap.org/ip/$IP"
  try {
    $rdap = Invoke-RestMethod -Method GET -Uri $url -TimeoutSec 8
  } catch {
    return [pscustomobject]@{
      IP=$IP; Org="(lookup failed)"; Network=""; Country=""; ASN=""; CIDR=""
    }
  }
  $org = ""
  $asn = ""
  $country = ""
  $netName = $rdap.name
  $cidr = $null

  if ($rdap.cidr0_cidrs -and $rdap.cidr0_cidrs.Count -gt 0) {
    $cidrObj = $rdap.cidr0_cidrs | Select-Object -First 1
    $cidr = "$($cidrObj.v4prefix)/$($cidrObj.length)"
  } elseif ($rdap.startAddress -and $rdap.endAddress) {
    $cidr = "$($rdap.startAddress) - $($rdap.endAddress)"
  }
  if ($rdap.country) { $country = $rdap.country }

  if ($rdap.entities) {
    foreach ($e in $rdap.entities) {
      if ($e.vcardArray -and $e.vcardArray.Count -ge 2) {
        foreach ($entry in $e.vcardArray[1]) {
          if ($entry[0] -eq "fn"  -and $entry[3]) { $org = $entry[3]; break }
          if ($entry[0] -eq "org" -and $entry[3]) { $org = ($entry[3] -join " "); break }
        }
      }
      if ($e.roles -and ($e.roles -contains "registrant" -or $e.roles -contains "administrative" -or $e.roles -contains "technical") -and [string]::IsNullOrWhiteSpace($org) -eq $false) {
        break
      }
    }
  }
  if (-not $org) { $org = $rdap.name }

  [pscustomobject]@{
    IP       = $IP
    Org      = $org
    Network  = $netName
    Country  = $country
    ASN      = $asn
    CIDR     = $cidr
  }
}

function Get-ResearchLinksHtml {
  param([string]$IP)
  $q = [uri]::EscapeDataString($IP)
  $links = @(
    @{n="RDAP";         u="https://rdap.org/ip/$q"},
    @{n="ARIN RDAP";    u="https://search.arin.net/rdap/?query=$q"},
    @{n="VirusTotal";   u="https://www.virustotal.com/gui/ip-address/$q"},
    @{n="AbuseIPDB";    u="https://www.abuseipdb.com/check/$q"},
    @{n="Shodan";       u="https://www.shodan.io/host/$q"},
    @{n="Censys";       u="https://search.censys.io/hosts/$q"},
    @{n="GreyNoise";    u="https://viz.greynoise.io/ip/$q"},
    @{n="Talos";        u="https://talosintelligence.com/reputation_center/lookup?search=$q"},
    @{n="SecurityTrails";u="https://securitytrails.com/list/ip/$q"},
    @{n="BGP.he.net";   u="https://bgp.he.net/ip/$q"},
    @{n="MXToolbox PTR";u="https://mxtoolbox.com/SuperTool.aspx?action=ptr:$q"},
    @{n="IPinfo";       u="https://ipinfo.io/$q"}
  )
  ($links | ForEach-Object { "<a href='$($_.u)' target='_blank' rel='noopener'>$($_.n)</a>" }) -join " &middot; "
}

### ---------- Begin Work ----------
$script:LocalSubnets = Get-LocalSubnets

$rows = @()
$remoteIps = [System.Collections.Generic.HashSet[string]]::new()

# LISTEN rows (optional)
if ($ShowListening) {
  $tcpListen = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
      [pscustomobject]@{
        Protocol    = "TCP"
        State       = "LISTEN"
        Process     = $p.Name
        PID         = $_.OwningProcess
        Local       = "$($_.LocalAddress):$($_.LocalPort)"
        Remote      = ""
        RemoteIP    = $null
        RemoteHost  = $null
        RemoteOwner = $null
        RemoteNet   = $null
        RemoteCIDR  = $null
        RemoteCountry = $null
      }
    } catch {}
  }

  $udpListen = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
      [pscustomobject]@{
        Protocol    = "UDP"
        State       = "LISTEN"
        Process     = $p.Name
        PID         = $_.OwningProcess
        Local       = "$($_.LocalAddress):$($_.LocalPort)"
        Remote      = ""
        RemoteIP    = $null
        RemoteHost  = $null
        RemoteOwner = $null
        RemoteNet   = $null
        RemoteCIDR  = $null
        RemoteCountry = $null
      }
    } catch {}
  }
  $rows += $tcpListen
  $rows += $udpListen
}

# ESTABLISHED rows (optional)
if ($IncludeEstablished) {
  $tcpEstablished = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      $rip = $_.RemoteAddress
      if (ShouldExcludeIP -IP $rip -IncludeLocalFlag:$IncludeLocal) { return }

      $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
      $remoteEP = "${rip}:$($_.RemotePort)"

      [void]$remoteIps.Add($rip)
      [pscustomobject]@{
        Protocol    = "TCP"
        State       = "ESTABLISHED"
        Process     = $p.Name
        PID         = $_.OwningProcess
        Local       = "$($_.LocalAddress):$($_.LocalPort)"
        Remote      = $remoteEP
        RemoteIP    = $rip
        RemoteHost  = $null
        RemoteOwner = $null
        RemoteNet   = $null
        RemoteCIDR  = $null
        RemoteCountry = $null
      }
    } catch {}
  }
  $rows += $tcpEstablished
}

# RDAP lookups (publics only)
$rdapCache = @{}
foreach ($ip in $remoteIps) {
  if ([string]::IsNullOrWhiteSpace($ip)) { continue }
  if (Test-PrivateIP $ip) { continue }
  if (Test-LocalSubnet $ip) { continue }
  $rdapCache[$ip] = Get-RdapInfo -IP $ip
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
  $ip = $_.RemoteIP
  $rd = $null
  $ptr = $null
  if ($ip -and $rdapCache.ContainsKey($ip)) { $rd = $rdapCache[$ip] }
  if ($ip -and $ptrCache.ContainsKey($ip)) { $ptr = $ptrCache[$ip] }

  [pscustomobject]@{
    Protocol      = $_.Protocol
    State         = $_.State
    Process       = $_.Process
    PID           = $_.PID
    Local         = $_.Local
    Remote        = $_.Remote
    RemoteIP      = $ip
    RemoteHost    = $ptr
    RemoteOwner   = if ($rd) { $rd.Org } else { $null }
    RemoteNet     = if ($rd) { $rd.Network } else { $null }
    RemoteCIDR    = if ($rd) { $rd.CIDR } else { $null }
    RemoteCountry = if ($rd) { $rd.Country } else { $null }
  }
}

### ---------- HTML Report ----------
$now = Get-Date
$style = @"
<style>
body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }
h1 { font-size: 22px; margin: 0 0 6px 0; }
.sub { color: #555; margin-bottom: 16px; }
input#filter { width: 360px; padding: 6px 8px; margin: 12px 0 18px 0; border: 1px solid #ccc; border-radius: 6px; }
table { border-collapse: collapse; width: 100%; }
th, td { padding: 8px 10px; border-bottom: 1px solid #eee; vertical-align: top; }
th { text-align: left; background: #fafafa; position: sticky; top: 0; z-index: 1; }
tr:hover { background: #fcfcfc; }
.badge { display:inline-block; padding:2px 6px; border-radius:6px; font-size:12px; background:#eef; color:#334; }
.details { font-size: 12px; color: #333; }
.details summary { cursor:pointer; }
.links a { margin-right: 10px; }
.small { color:#666; font-size:12px; }
footer { color:#666; font-size:12px; margin-top:18px; }
</style>
"@

$scriptJs = @"
<script>
function filterTable() {
  const q = document.getElementById('filter').value.toLowerCase();
  const rows = document.querySelectorAll('#data tbody tr');
  rows.forEach(r => {
    const txt = r.innerText.toLowerCase();
    r.style.display = txt.indexOf(q) >= 0 ? '' : 'none';
  });
}
</script>
"@

$rowsHtml = New-Object System.Text.StringBuilder
foreach ($r in $result) {
  $ip = $r.RemoteIP
  $linksHtml = ""
  if ($ip) { $linksHtml = Get-ResearchLinksHtml -IP $ip }
  $detailsHtml = ""
  $detailsHtml += "<div class='small'><strong>Owner:</strong> $($r.RemoteOwner)</div>"
  $detailsHtml += "<div class='small'><strong>Net:</strong> $($r.RemoteNet)</div>"
  $detailsHtml += "<div class='small'><strong>CIDR:</strong> $($r.RemoteCIDR)</div>"
  $detailsHtml += "<div class='small'><strong>Country:</strong> $($r.RemoteCountry)</div>"
  if ($r.RemoteHost) { $detailsHtml += "<div class='small'><strong>Reverse DNS:</strong> $($r.RemoteHost)</div>" }

  $null = $rowsHtml.AppendLine(@"
  <tr>
    <td>$($r.Protocol)</td>
    <td><span class='badge'>$($r.State)</span></td>
    <td>$([System.Web.HttpUtility]::HtmlEncode($r.Process))</td>
    <td>$($r.PID)</td>
    <td>$([System.Web.HttpUtility]::HtmlEncode($r.Local))</td>
    <td>$([System.Web.HttpUtility]::HtmlEncode($r.Remote))</td>
    <td>
      $( if ($ip) { "<details class='details'><summary>$ip</summary>$detailsHtml<div class='links'>$linksHtml</div></details>" } else { "" } )
    </td>
  </tr>
"@)
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Netstat-Who Report</title>
$style
$scriptJs
</head>
<body>
  <h1>Netstat‑Who Report</h1>
  <div class="sub">
    Generated: $($now.ToString("yyyy-MM-dd HH:mm:ss")) &middot;
    Filters: $(if($IncludeEstablished){"Established"}else{"(no Established)"})
    $(if($ShowListening){" + Listening"}else{""})
    $(if($IncludeLocal){" + Local/LAN"}else{" + Public only"})
    $(if($ResolveDNS){" + rDNS"}else{""})
  </div>

  <input id="filter" type="text" placeholder="Type to filter rows (process, IP, owner, etc.)" onkeyup="filterTable()" />

  <table id="data">
    <thead>
      <tr>
        <th>Proto</th>
        <th>State</th>
        <th>Process</th>
        <th>PID</th>
        <th>Local</th>
        <th>Remote</th>
        <th>Remote IP &amp; Research</th>
      </tr>
    </thead>
    <tbody>
      $rowsHtml
    </tbody>
  </table>

  <footer>
    Tip: Click a Remote IP to expand details and jump into research links (RDAP, VirusTotal, Shodan, etc.).
  </footer>
</body>
</html>
"@

# Write file
try {
  $dir = Split-Path -Parent $ReportPath
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $html | Out-File -FilePath $ReportPath -Encoding utf8
  Write-Host "Report written to: $ReportPath"
  if ($OpenWhenDone) { Start-Process $ReportPath }
} catch {
  Write-Warning "Failed to write HTML report: $($_.Exception.Message)"
}
