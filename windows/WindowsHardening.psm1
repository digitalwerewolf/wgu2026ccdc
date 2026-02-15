function Get-CCDCDomains {
    $Domains = @()
    $Domains += (Get-ADDomain).Forest
    $Domains += (Get-ADTrust -Filter *).Name
    return $Domains
}

function Get-CCDCForest {
    <#
        .DESCRIPTION
            Get-CCDCForest gets all of the domains and trust relationships in the forest and saves domains as the global variable $Domains
    #>
    Write-Host "[*] Getting domains"
    $Domains = Get-CCDCDomains
    if ($Domains.Count -gt 0) {
        Write-Host "[+] Found ${$Domains.Count} domains:"
        $Domains
        Write-Host "-----"
    }
    else {
        Write-Host "[-] No domains found"
    }

    Write-Host "[*] Enumerating domain trusts"
    $Trusts = Get-ADTrust -filter * | select Direction,Name
    if ($Trusts -ne $null) {
        Write-Host "[+] Trusts:"
        $Trusts | Format-Table -AutoSize
        Write-Host "-----"
    }
    else {
        Write-Host "[-] No trusts found"
    }
}

function Get-CCDCComputers {
    <#
        .DESCRIPTION
            Get-CCDCComputers gets all domain controllers and domain-joined computers
    #>
    $Domains = Get-CCDCDomains
    Write-Host "[*] Getting domain controllers"
    [array]$DomainControllers = $Domains | % { Get-ADDomainController -Filter * -Server $_  } | select HostName
    if ($DomainControllers.Count -gt 0) {
        Write-Host "[+] Domain conrollers:"
        $DomainControllers | Format-Table
        Write-Host "-----"
    }
    else {
        Write-Host "[-] No domain controllers found"
    }

    Write-Host "[*] Getting domain computers"
    [array]$Computers = $Domains | % { Get-ADComputer -Filter * -Server $_ -Properties DNSHostName,OperatingSystem } | select DNSHostName,OperatingSystem
    if ($Computers.Count -gt 0) {
        Write-Host "[+] Domain computers:"
        $Computers | Format-Table
        Write-Host "-----"
    }
    else {
        Write-Host "[-] No domain computers found"
    }
}

function Invoke-CCDCUserAuthChecks {
    <#
        .DESCRIPTION
            Invoke-CCDCUserAuthChecks checks various facets of authentication - Service Principal Names, Kerberos Pre-Auth Not Required,
                passwords stored with reversible encryption, Password Not Required, and credentials in LDAP fields
    #>
    $Domains = Get-CCDCDomains
    $Properties = @("Name", "Enabled", "SamAccountName", "DisplayName", "Enabled", "LastLogonDate",
        "PasswordLastSet", "PasswordNotRequired", "AdminCount", "LastBadPasswordAttempt", "badpwdcount",
        "ServicePrincipalName", "SIDHistory", "PrimaryGroupID", "UserAccountControl", "DoesNotRequirePreAuth",
        "Comment","Description","Info","userPassword","unixUserPassword","unicodePwd")
    
    Write-Host "[*] Getting domain users"
    $DomainUsers = $Domains | % { Get-ADUser -Filter *  -Properties $Properties -Server $_ }

    Write-Host "[*] Checking for enabled users with an SPN"
    $UsersWithSPN = $DomainUsers | where {$_.ServicePrincipalName -and $_.Enabled} | select Name,ServicePrincipalName
    if ($UsersWithSPN.Count -gt 0) {
        Write-Host "[+] Enabled Users with an SPN:"
        $UsersWithSPN | Format-Table
        Write-Host "-----"
    }
    else {
        Write-Host "[-] No enabled users with an SPN found"
    }

    Write-Host "[*] Checking for users with Kerberos Pre-Auth Not Required"
    $PreAuthNotRequired = ($DomainUsers | where {$_.DoesNotRequirePreAuth -eq $True }).DistinguishedName
    if ($PreAuthNotRequired.Count -gt 0) {
        Write-Host -ForegroundColor Red "[+] Users with Kerberos Pre-Auth Not Required:"
        $PreAuthNotRequired | Format-Table
        Write-Host "-----"
    }
    else {
        Write-Host -ForegroundColor Green "[-] No users with Kerberos Pre-Auth Not Required"
    }

    Write-Host "[*] Checking for users with passwords stored with reversible encryption"
    $ReversibleEncryption = $DomainUsers | where { $_.UserAccountControl -band 0x0080 }
    if ($ReversibleEncryption.Count -gt 0) {
        Write-Host -ForegroundColor Red "[+] Users with passwords stored with reversible encryption:"
        $ReversibleEncryption | Format-Table
        Write-Host "-----"
    }
    else {
        Write-Host -ForegroundColor Green "[-] No users with passwords stored with reversible encryption"
    }

    Write-Host "[*] Checking for users with Password Not Required"
    $PasswordNotReq = ($DomainUsers | where {$_.PasswordNotRequired -eq $True }).DistinguishedName
    if ($PasswordNotReq.Count -gt 0) {
        Write-Host -ForegroundColor Red "[+] Users with Password Not Required:"
        $PasswordNotReq | Format-Table
        Write-Host "-----"
    }
    else {
        Write-Host -ForegroundColor Green "[-] No users with Password Not Required"
    }

    Write-Host "[*] Checking for users with credentials in LDAP fields"
    $DomainUsers | select DistinguishedName,Comment,Description,Info,userPassword,unixUserPassword,unicodePwd | Format-Table -AutoSize
    Write-Host "-----"
}

function Get-CCDCPrivilegedUsers {
    <#
        .DESCRIPTION
            Get-CCDCPrivilegedUsers gets members of privileged groups and members of Protected Users
    #>
    $Domains = Get-CCDCDomains
    Write-Host "[*] Getting members of privileged groups"
    $PrivilegedGroups = @(
        'Administrators',
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Account Operators',
        'Server Operators',
        'Group Policy Creator Owners',
        'DNSAdmins',
        'Enterprise Key Admins',
        'Exchange Domain Servers',
        'Exchange Enterprise Servers',
        'Exchange Admins',
        'Organization Management',
        'Exchange Windows Permissions'
    )
    $PrivilegedGroupMembers = @()
    foreach ($Group in $PrivilegedGroups) {
        foreach ($Domain in $Domains) {
            try {
                $Members = Get-ADGroupMember $Group -Server $Domain
                $Members | % { $_ | Add-Member -MemberType NoteProperty -Name "Domain" -Value $Domain -Force }
                $Members | % { $_ | Add-Member -MemberType NoteProperty -Name "Group" -Value $Group -Force }
                $PrivilegedGroupMembers += $Members

            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                Write-Host "[*] The ${group} group does not exist"
            }
        }
    }
    if ($PrivilegedGroupMembers.Count -gt 0) {
        Write-Host "[+] Members of privileged groups:"
        $PrivilegedGroupMembers | select SamAccountName,Domain,Group | `
            Sort-Object @{Expression="Domain"},@{Expression="SamAccountName"} | Format-Table
        Write-Host "-----"
    }
    else {
        Write-Host "[-] No members of privileged groups found"
    }

    $ProtectedUsers = $Domains | % { Get-ADGroupMember "Protected Users" -Server $_ }
    Write-Host "[*] Getting members of Protected Users"
    if ($ProtectedUsers.Count -eq 0) {
        Write-Host "[+] Members of Protected Users:"
        $ProtectedUsers | Format-Table
        Write-Host "-----"
    }
    else {
        Write-Host -ForegroundColor Red "[-] No members of Protected Users found"
    }
    
}

function Get-CCDCDelegation {
    <#
        .DESCRIPTION
            Get-CCDCDelegation enumerates objects with delegation rights
    #>
    $Domains = Get-CCDCDomains
    $Properties = @("Name","ObjectClass","PrimaryGroupID","UserAccountControl","ServicePrincipalName","msDS-AllowedToDelegateTo","msDS-AllowedToActOnBehalfOfOtherIdentity")
    Write-Host "[*] Enumerating Kerberos delegation"
    [array]$KerberosDelegationObjects = $Domains | % { Get-ADObject -Filter { ((UserAccountControl -BAND 0x0080000) -OR (UserAccountControl -BAND 0x1000000) -OR (msDS-AllowedToDelegateTo -like '*') -OR (msDS-AllowedToActOnBehalfOfOtherIdentity -like '*')) -AND (PrimaryGroupID -ne '516') -AND (PrimaryGroupID -ne '521') } -Properties $Properties -Server $_ }
    [array]$KerberosDelegationArray = @()
    foreach ($KerberosDelegationObjectItem in $KerberosDelegationObjects) {
        if ($KerberosDelegationObjectItem.UserAccountControl -BAND 0x0080000) { 
            $KerberosDelegationServices = 'All Services'
            $KerberosType = 'Unconstrained' 
        } else { 
            $KerberosDelegationServices = 'Specific Services'
            $KerberosType = 'Constrained' 
        } 

        if ($KerberosDelegationObjectItem.UserAccountControl -BAND 0x1000000) { 
            $KerberosDelegationAllowedProtocols = 'Any (Protocol Transition)'
            $KerberosType = 'Constrained with Protocol Transition'
        } else { 
            $KerberosDelegationAllowedProtocols = 'Kerberos'
        }

        if ($KerberosDelegationObjectItem.'msDS-AllowedToActOnBehalfOfOtherIdentity') { 
            $KerberosType = 'Resource-Based Constrained Delegation'
        } 

        $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name Domain -Value $DomainName -Force
        $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name KerberosDelegationServices -Value $KerberosDelegationServices -Force
        $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name DelegationType -Value $KerberosType -Force
        $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name KerberosDelegationAllowedProtocols -Value $KerberosDelegationAllowedProtocols -Force

        $KerberosDelegationArray += $KerberosDelegationObjectItem
    }
    if ($KerberosDelegationArray.Count -gt 0) {
        Write-Host -ForegroundColor Red "[+] Objects with delegation rights:"
        $KerberosDelegationArray | Sort DelegationType | Select DistinguishedName,DelegationType,Name,ServicePrincipalName | Format-Table -AutoSize
        Write-Host "-----"
    }
    else {
        Write-Host -ForegroundColor Green "[-] No objects with delegation rights"
    }    
}

function Get-CCDCcpassword {
    <#
        .DESCRIPTION
            Get-CCDCcpassword checks for Group Policy Preference passwords
    #>
    $Domains = Get-CCDCDomains
    Write-Host "[*] Checking for GPP Passwords"
    [array]$GPP = $Domains | % { findstr /S /I cpassword "\\${_}\SYSVOL\${_}\Policies\*.xml" }
    if ($GPP.Count -gt 0) {
        Write-Host -ForegroundColor Red "[+] GPP cPasswords found:"
        $GPP
        Write-Host "-----"
    }
    else {
        Write-Host -ForegroundColor Green "[-] No GPP cPasswords found"
    }
}

function Get-CCDCGroupPolicyObjects {
    <#
        .DESCRIPTION
            Get-CCDCGroupPolicyObjects checks Group Policies and their permissions
    #>
    $Domains = Get-CCDCDomains
    Write-Host "[*] Getting Group Policies"
    [array]$DomainGPOs = $Domains | % { Get-GPO -All -Domain $_ }
    if ($DomainGPOs.Count -gt 0) {
        Write-Host "[+] Group Policies:"
        $DomainGPOs | select DisplayName,DomainName,GpoStatus,Owner | Format-Table
        Write-Host "-----"

        Write-Host "[*] Group Policy Object Permissions:"
        $GPOPermissions = foreach ($DomainGPO in $DomainGPOs)
        {
            Get-GPPermissions -Guid $DomainGPO.Id -DomainName $DomainGPO.DomainName -All | Where {$_.Trustee.SidType.ToString() -ne "WellKnownGroup"} | Select `
            @{n='GPOName';e={$DomainGPO.DisplayName}},
            @{n='AccountName';e={$_.Trustee.Name}},
            @{n='AccountType';e={$_.Trustee.SidType.ToString()}},
            @{n='Permissions';e={$_.Permission}}
        }
        $GPOPermissions | Format-Table
        Write-Host "-----"
    }
    else {
        Write-Host "[-] No Group Policies found"
    }
}

function Get-CCDCCertificateTemplates {
    <#
        .DESCRIPTION
            Get-CCDCCertificateTemplates gets all certificate templates
    #>
    Write-Host "[*] Getting certificate authority"
    $CA = certutil -ping
    if ($CA -ne $null) {
        Write-Host "[+] Certificate authority:"
        $CA
    
        Write-Host "[*] Getting certificate templates"
        $Templates = Get-CATemplate
        if ($Templates.Count -gt 0) {
            Write-Host "[+] Certificate templates:"
            $Templates | Format-Table
            Write-Host "-----"
        }
        else {
            Write-Host "[-] No certificate templates found"
        }
    }
    else {
        Write-Host "[-] No certificate authority found"
    }
}

function Invoke-CCDCAllChecks {
    Write-Host "[*] Running all checks"
    Get-CCDCForest
    Get-CCDCComputers
    Invoke-CCDCUserAuthChecks
    Get-CCDCPrivilegedUsers
    Get-CCDCDelegation
    Get-CCDCcpassword
    Get-CCDCGroupPolicyObjects
    Get-CCDCCertificateTemplates
}