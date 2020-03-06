#########################################

  #     #                               
  ##   ##   ##   #    # #####  #  ####  
  # # # #  #  #  ##   # #    # # #    # 
  #  #  # #    # # #  # #    # # #      
  #     # ###### #  # # #    # # #      
  #     # #    # #   ## #    # # #    # 
  #     # #    # #    # #####  #  ####  

#########################################
# Script desenvolvidor por Paulo Duarte #
#########################################
#      Atualizado em: 24/02/2020        #
#########################################
# Script utilizado para mitigar ataques #
# bruteforce no MSSQL com porta aberta  #
# ao mundo.                             #
#########################################

# Quantas tentativas de login serão consideradas bruteforce?
$qtdeTentativa = 10;

# Caminho absoluto do ERRORLOG do MSSQL
$logAtual = Get-Content "C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Log\ERRORLOG" 

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
Remove-Item "C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Log\ERRORLOG.1"