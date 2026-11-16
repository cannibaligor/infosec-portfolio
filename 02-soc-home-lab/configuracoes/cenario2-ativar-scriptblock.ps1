# Cenario 2 - Ativa o Script Block Logging (evento 4104) e faz o agente Wazuh ler o canal.
# Script escrito com apoio de IA. Rodar no PowerShell como ADMINISTRADOR na VM SOC-Win11.

# 1) Ativa o log de Script Block do PowerShell (evento 4104)
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $k -Force | Out-Null
Set-ItemProperty -Path $k -Name EnableScriptBlockLogging -Value 1 -Type DWord

# 2) Faz o agente do Wazuh ler o canal PowerShell/Operational (com backup antes)
$conf = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
Copy-Item $conf "$conf.bak-cenario2" -Force
$xml = [IO.File]::ReadAllText($conf)
if ($xml -notmatch 'PowerShell/Operational') {
  $bloco = "  <localfile>`r`n    <location>Microsoft-Windows-PowerShell/Operational</location>`r`n    <log_format>eventchannel</log_format>`r`n  </localfile>`r`n`r`n</ossec_config>"
  $i = $xml.LastIndexOf('</ossec_config>')
  $xml = $xml.Substring(0, $i) + $bloco + $xml.Substring($i + 15)
  [IO.File]::WriteAllText($conf, $xml)
}

# 3) Reinicia o agente e confere tudo
Restart-Service WazuhSvc
Get-ItemProperty $k | Select-Object EnableScriptBlockLogging
Select-String -Path $conf -Pattern 'PowerShell/Operational'
Get-Service WazuhSvc | Select-Object Status, Name
