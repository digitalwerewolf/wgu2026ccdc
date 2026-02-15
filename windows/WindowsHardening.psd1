@{

ModuleVersion = "1.0"
Author = "Echo"
Description = "This module performs Active Directory enumeration to inform defenders"
PowerShellVersion = '5.0'

RootModule           = 'WindowsHardening.psm1'
RequiredModules = @(
    @{ 
        ModuleName    = 'ActiveDirectory'
        ModuleVersion = '1.0.0.0'
        Guid          = '43c15630-959c-49e4-a977-758c5cc93408'
    },
)

FunctionsToExport = @(
    "Get-CCDCForest",
    "Get-CCDCComputers",
    "Invoke-CCDCUserAuthChecks",
    "Get-CCDCPrivilegedUsers",
    "Get-CCDCDelegation",
    "Get-CCDCcpassword",
    "Get-CCDCGroupPolicyObjects",
    "Get-CCDCCertificateTemplates",
    "Invoke-CCDCAllChecks"
)
}