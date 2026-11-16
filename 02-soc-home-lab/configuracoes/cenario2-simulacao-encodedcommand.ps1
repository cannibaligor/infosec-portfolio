# Cenario 2 - Simulacao BENIGNA de PowerShell codificado (T1059.001 / T1027).
# Escrito com apoio de IA. Rodar no PowerShell (usuario comum) na VM SOC-Win11.
# O comando escondido so escreve uma frase verde na tela: nada e baixado nem alterado.

$cmd = 'Write-Host "LAB-SOC Cenario 2 - PowerShell codificado (T1059.001) executado em $(Get-Date -Format o)" -ForegroundColor Green'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))   # Base64 de UTF-16LE
powershell.exe -EncodedCommand $enc

# Para o analista decodificar o Base64 copiado do alerta:
# [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('COLE_O_BASE64_AQUI'))
