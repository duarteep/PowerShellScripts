# PowerShellScripts
Scripts PowerShell diversos para administradores de sistemas Windows

###fail2ban-mssql
Script desenvolvido para mitigar ataques bruteforce em servidores MSSQL que tenham como premissa ter portas de acesso abertas ao mundo.

Como usar:
1) Criar diretório "C:\fail2ban-mssql"
2) Inserir arquivo "GeraDetratores.ps1" no diretório criado acima
3) Alterar parâmetros do arquivo inserido acima:
-qtdeTentativa
-logAtual
-logAposRotate
-instanciaSql
4) Crie uma tarefa agendada para executar o script PowerShell com a frequência que for interessante para o seu cenário

Observações:
- A frequência da tarefa agendada em conjunto com o parâmetro "qtdeTentativa" trabalham em conjunto: qtdeTentativa x periodoTempo
