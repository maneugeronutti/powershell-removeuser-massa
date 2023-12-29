function LogElastic {
    $username = "elastic"
    $password = "PASSWORD"

    $pair = "$($username):$($password)"
    $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
    $basicAuthValue = "Basic $encodedCreds"
    $Headers = @{ Authorization = $basicAuthValue }

    $yearIndex = $(Get-Date).ToString('yyyy')
    $monthIndex = $(Get-Date).ToString('MM')
    $timeStamp = Get-Date (Get-Date).ToUniversalTime() -UFormat '+%Y-%m-%dT%H:%M:%S.000Z'

    $whoExecute = Get-Date -Format "dd/MM/yyyy HH:mm"

    $response = Invoke-RestMethod -Uri "http://172.16.1.87:9200/grupocaio_removedusers.$yearIndex.$monthIndex/_doc" -Headers $Headers `
    -Credential $credential -ContentType "application/json" -Method POST `
    -Body "{ ""@timestamp"": ""$timeStamp"", ""domainUser"": ""$($isUserDomainName)"", ""removedUser"": ""$informedUser"", ""removedNameUser"": ""$($isNameUser)"", ""createdUser"": ""$($isUserCreated.whenCreated)"", `
    ""userLastLogon"": ""$($isUserLastLogon.lastLogonDate)"", ""sdiUser"": ""$($isUserSID.SID)"", ""runDomain"": ""$Env:UserDomain"", ""runUserName"": ""$([Environment]::UserName)"", ""runComputerName"": ""$($env:COMPUTERNAME)"", ""logDate"":""$whoExecute"" }"

}

Write-Host " "
Write-Host "                   .-''-.             ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" 
Write-Host "                  {  }  e'._          ~~~~~~~~~~~~~~~~~~~~    THOR!    ~~~~~~~~~~~~~~~~~~~~"
Write-Host "                  {  }    __/         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
Write-Host "                   ;-'  .--'          Efetue consultas e deleção de usuários desativados "
Write-Host "                  /`===;               no Active Directory"
Write-Host "                .'     |              Os logs da deleção serão armazenadas no Elastic"
Write-Host "             .-'       /"
Write-Host "           /`  __   ; ||               Use com muito cuidado, pois usuários serão REMOVIDOS!"
Write-Host "          |   `  `\ | ||                Sujeito a latidos e mordidas!!!"
Write-Host "          \       /`| ||               ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
Write-Host "         (''._.--'-.\__}}"
Write-Host "          ')  )''''"
Write-Host "          ----"

$loop = $true
while ($loop){
    Write-Host ""
    Write-Host "1. Listar/Exportar usuários desativados"
    Write-Host "2. Remover usuário específico"
    Write-Host "3. Remover todos os usuários listados"
    Write-Host ""
    Write-Host 'q. Sair'
    Write-Host '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
    $optionSelected = Read-Host -Prompt "Selecione a opção (ou 'q' para sair)"

    switch ($optionSelected) {
        '1' {
            Write-Host ""
            $yearActual = Get-Date -Format yyyy
            Write-Host "Informe o ANO de corte (Ex.: 2023)"
            $yearsSolicited = Read-Host -Prompt "O ano deve ser menor que o ano anterior"
            $yearsSelected = $yearActual - $yearsSolicited

            if ($yearsSelected -le 1) { 
                Write-Host ""; Write-Host ""
                Write-Host "O ano de corte deve ser menor que o ano anterior!" 
                Write-Host ""; Write-Host ""
                Write-Host "Tchauzinho!"
                exit 0
            }


            $isExport = Read-host -Prompt "Deseja exportar esta consulta? (S/N)"
            Write-Host ""

            if ($isExport -eq 'S'){
                $fileExport = Read-host -Prompt "Informe o local e nome do arquivo (Default: C:\Temp\consultDeletedUsers.csv)"

                if ($fileExport -eq '') { $fileExport = "C:\Temp\consultDeletedUsers.csv"}
                
                try {
                    
                    Get-ADUser -Filter {Enabled -eq $False} -Properties name,sAMAccountName,SID,lastLogonDate,DistinguishedName | Where-Object {$_.DistinguishedName -notlike "*OU=Colaboradores Afastados,*" -and $_.lastLogonDate -ne $null -and $_.lastLogonDate -le "$yearsSolicited-01-01T00:00:00.000Z"} | Select Name,sAMAccountName,lastLogonDate | Export-Csv $fileExport -NoTypeInformation

                    Write-Host ""; Write-Host ""
                    Write-Host "Arquivo exportado em: $fileExport"

                    Write-Host ""; Write-Host ""
                    $returnMenu = Read-Host -Prompt "Desejar retornar ao menu principal? (S/N)"
                    if ($returnMenu -eq 'S') { $loop = $true } elseif ($returnMenu -eq 'N') { Write-Host "Tchauzinho!"; exit 0 } else { Write-Host "Opção inválida!"; exit 0 }
                } catch {
                    Write-Host ""; Write-Host ""
                    Write-Host "Problemas na execução do comando."
                    $loop = $false
                }

            } elseif ($isExport -eq 'N') {
                try {
                    Get-ADUser -Filter {Enabled -eq $False} -Properties name,sAMAccountName,SID,lastLogonDate,DistinguishedName | Where-Object { $_.DistinguishedName -notlike "*OU=Colaboradores Afastados,*" -and $_.lastLogonDate -ne $null -and $_.lastLogonDate -le "$yearsSolicited-01-01T00:00:00.000Z"} | Select Name,sAMAccountName,SID,lastLogonDate

                    Write-Host ""; Write-Host ""
                    $returnMenu = Read-Host -Prompt "Desejar retornar ao menu principal? (S/N)"
                    if ($returnMenu -eq 'S') { $loop = $true } elseif ($returnMenu -eq 'N') { Write-Host "Tchauzinho!"; exit 0 } else { Write-Host "Opção inválida!"; exit 0 }

                }catch{
                    Write-Host ""; Write-Host ""
                    Write-Host "ERRO! Problemas na execução do comando."
                    $loop = $false
                } 
            }           
        }

        '2' {
            Write-Host "";Write-Host ""
            Write-Host "Informe o usuário que deseja remover"
            $informedUser = Read-Host -Prompt "ATENÇÃO! Esta opção não faz destinção de data de logon"
            
            $isEnabledUser = Get-ADUser -Filter "sAMAccountName -eq '$informedUser'" | Select Enabled
            $isNameUser = Get-ADUser -Filter "sAMAccountName -eq '$informedUser'" | Select Name
            $isUserCreated = Get-ADUser -Filter "sAMAccountName -eq '$informedUser'" -Properties whenCreated | Select whenCreated
            $isUserLastLogon = Get-ADUser -Filter "sAMAccountName -eq '$informedUser'" -Properties lastLogonDate | Select lastLogonDate
            $isUserSID= Get-ADUser -Filter "sAMAccountName -eq '$informedUser'" -Properties SID | Select SID
            
            $domainName = Get-ADUser -Filter {sAMAccountName -eq $informedUser}
            $isUserDomainName = $domainName.UserPrincipalName -split '@' | Select-Object -Last 1

            $isNameUser = $isNameUser.Name -replace '[áäàãâ]', 'a' -replace '[éëèê]', 'e' -replace '[íïìî]', 'i' -replace '[óöòõô]', 'o' -replace '[úüùû]', 'u' -replace 'ç', 'c'

            $validacaoOU = Get-ADUser -Filter "sAMAccountName -eq '$informedUser'" -Properties DistinguishedName | Select DistinguishedName

            if ($isEnabledUser.Enabled -eq $false -and $validacaoOU.DistinguishedName -notlike "*OU=Colaboradores Afastados,*") {
                try {
                    Remove-ADUser -Identity "$informedUser"
                    
                    Write-Host ""
                    Write-Host ""
                    Write-Host "Usuário $informedUser removido com sucesso!"

                    ###### LOGAR REMOCAO ELASTIC
                    LogElastic

                    Write-Host ""; Write-Host ""
                    $returnMenu = Read-Host -Prompt "Desejar retornar ao menu principal? (S/N)"
                    if ($returnMenu -eq 'S') { $loop = $true } elseif ($returnMenu -eq 'N') { Write-Host "Tchauzinho!"; exit 0 } else { Write-Host "Opção inválida!"; exit 0 }
                     
                } 
                catch {
                    Write-Host ""; Write-Host ""
                    Write-Host "Não foi possível remover o usuário $informedUser"
                    $loop = $false
                }
            } else {
                Write-Host ""; Write-Host ""
                Write-Host "O usuário $informedUser está 'ATIVO' ou me OU 'COLABORADORES AFASTADOS'. Tente novamente."
            }
            
        }

        '3' {
            Write-Host ""; Write-Host ""
            $yearActual = Get-Date -Format yyyy
            Write-Host "Informe o ANO de corte (Ex.: 2023)"
            $yearsSolicited = Read-Host -Prompt "O ano deve ser menor que o ano anterior"
            $yearsSelected = $yearActual - $yearsSolicited

            if ($yearsSelected -le 1) { 
                Write-Host ""; Write-Host ""
                Write-Host "O ano de corte deve ser menor que o ano anterior!" 
                Write-Host ""; Write-Host ""
                Write-Host "Tchauzinho!"
                exit 0
            }
                        
            $isValidate01 = Read-host -Prompt "Deseja realmente efetuar este procedimento? (S/N)"

            if ($isValidate01 -eq 'S') {
                $isValidate02 = Read-host -Prompt "O procedimento é irreversível, deseja presseguir? (S/N)"
                if ($isValidate02 -eq 'S') {
                    Write-Host 'Removendo usuários...'

                    $listDeleted = Get-ADUser -Filter {Enabled -eq $False} -Properties name,sAMAccountName,SID,lastLogonDate,DistinguishedName | Where-Object {$_.lastLogonDate -le "$yearsSolicited-01-01T00:00:00.000Z"} | Select Name,sAMAccountName,SID,lastLogonDate,DistinguishedName

                    foreach ($removedUser in $listDeleted) {
                        try {
                            $informedUser = $removedUser.sAMAccountName

                            $isEnabledUser = Get-ADUser -Filter "sAMAccountName -eq '$informedUser'" | Select Enabled
                            $isNameUser = Get-ADUser -Filter "sAMAccountName -eq '$informedUser'" | Select Name
                            $isUserCreated = Get-ADUser -Filter "sAMAccountName -eq '$informedUser'" -Properties whenCreated | Select whenCreated
                            $isUserLastLogon = Get-ADUser -Filter "sAMAccountName -eq '$informedUser'" -Properties lastLogonDate | Select lastLogonDate
                            $isUserSID = Get-ADUser -Filter "sAMAccountName -eq '$informedUser'" -Properties SID | Select SID
                            $isJustOU = Get-ADUser -Filter "sAMAccountName -eq '$informedUser'" -Properties DistinguishedName | Select DistinguishedName

                            $domainName = Get-ADUser -Filter {sAMAccountName -eq $informedUser}
                            $isUserDomainName = $domainName.UserPrincipalName -split '@' | Select-Object -Last 1

                            $isNameUser = $isNameUser.Name -replace '[áäàãâ]', 'a' -replace '[éëèê]', 'e' -replace '[íïìî]', 'i' -replace '[óöòõô]', 'o' -replace '[úüùû]', 'u' -replace 'ç', 'c'

                            if ($isUserLastLogon.lastLogonDate -ne $null -and $isJustOU.DistinguishedName -notlike "*OU=Colaboradores Afastados,*") { 
                                Remove-ADUser -Identity "$informedUser"
                                Get-ADUser -Identity $informedUser | Select sAMAccountName, Name

                                ###### LOGAR REMOCAO ELASTIC
                                LogElastic
                            }

                            

                        } catch {

                            Write-Host ""; Write-Host ""
                            Write-Host "ERRO! Problemas na execução do comando."
                            $loop = $false
                        }
                    } 
                    
                    Write-Host ""; Write-Host ""
                    $returnMenu = Read-Host -Prompt "Desejar retornar ao menu principal? (S/N)"
                    if ($returnMenu -eq 'S') { $loop = $true } elseif ($returnMenu -eq 'N') { Write-Host "Tchauzinho!"; exit 0 } else { Write-Host "Opção inválida!"; exit 0 }

                } else {
                    Write-Host ""; Write-Host ""
                    Write-Host 'Procedimento cancelado.'
                }    
            } else {
                Write-Host ""; Write-Host ""
                Write-Host 'Procedimento cancelado.'
            }

            Write-Host ""
        }    

        'q' {
            exit 0
        }

        default {
            Write-Host ''
            Write-Host "Opção '$optionSelected' inválida, tente novamente!"
        }
    }

}
