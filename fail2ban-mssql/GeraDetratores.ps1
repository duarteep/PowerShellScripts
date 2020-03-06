#   __      _ _ ___  _                                               _ 
#  / _|    (_) |__ \| |                                             | |
# | |_ __ _ _| |  ) | |__   __ _ _ __ ______ _ __ ___  ___ ___  __ _| |
# |  _/ _` | | | / /| '_ \ / _` | '_ \______| '_ ` _ \/ __/ __|/ _` | |
# | || (_| | | |/ /_| |_) | (_| | | | |     | | | | | \__ \__ \ (_| | |
# |_| \__,_|_|_|____|_.__/ \__,_|_| |_|     |_| |_| |_|___/___/\__, |_|
#                                                                 | |  
#                                                                 |_|  

# Script desenvolvidor por Paulo Duarte - https://www.linkedin.com/in/duarteep/

# Atualizado em: 05/03/2020

# Script utilizado para mitigar ataques bruteforce no MSSQL com porta aberta ao mundo.                             

#### INICIO PARAMETROS ####

# Quantas tentativas de login serão consideradas bruteforce?
$qtdeTentativa = 10;

# Caminhos absolutos do ERRORLOG do MSSQL
$logAtual = Get-Content "C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Log\ERRORLOG" 
$logAposRotate = "C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Log\ERRORLOG.1"

# Instância do SQL a ser feito rotate do ERRORLOG
$instanciaSql = "MSSQLDATABASE"

#### FIM PARAMETROS ####

# Filtrar apenas tentativas de login
$logAtual = $logAtual | Select-String -Pattern 'Login failed for user'

ForEach ($linha in $logAtual){
    # Converter objeto em string
    $linha = $linha | Out-String

    # Filtrar apenas endereço IP
    $tamanho = $linha.IndexOf("]") - $linha.IndexOf("[CLIENT:");
    $tamanho = $tamanho - 9;
    $ip = $linha.Substring($linha.IndexOf("[CLIENT:")+9,$tamanho)

    # Lista de IPs que geraram log são salvos em um arquivo de texto temporário
    $ip >> iplist_temp.txt
}

# Filtrar arquivo temporário de IPs (remover itens duplicados + apenas IPs detratores)
$ipsDetratores = Get-Content iplist_temp.txt | Group-Object | Where-Object { $_.Count -gt $qtdeTentativa } | Select -ExpandProperty Name

# Inserir IPs no arquivo de blacklist
ForEach ($linha in $ipsDetratores){
    # Converter objeto em string
    $linha = $linha | Out-String

    # Salvar IPs em blacklist (mesmo que duplicado)
    $linha.TrimStart().TrimEnd() >> blacklist.txt
}

# Limpa arquivo temporário
Remove-Item iplist_temp.txt

# Remover duplicatas do arquivo de blacklist
$blacklist = Get-Content blacklist.txt | Group-Object | Select -ExpandProperty Name
$blacklist > blacklist.txt

# Criar regra de firewall bloqueando todo o tráfego de IPs detratores
$blacklist = Get-Content "C:\fail2ban-mssql\blacklist.txt"

if (Get-NetFirewallRule -DisplayName "MSSQL Fail2Ban" 2> Null){ 
    Remove-NetFirewallRule -DisplayName "MSSQL Fail2Ban"
}
New-NetFirewallRule -DisplayName "MSSQL Fail2Ban" -Name "MSSQL Fail2Ban" -Direction Inbound -Enabled True -Profile Any -Protocol Any -Action Block -RemoteAddress $blacklist

# Rotate do ERRORLOG
Invoke-Sqlcmd -Query "sp_cycle_errorlog" -ServerInstance "CD115391APP01"

# Delete OLD ERRORLOG FILES
Remove-Item $logAposRotate