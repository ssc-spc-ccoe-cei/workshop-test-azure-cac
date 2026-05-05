BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 2 MANAGE ACCESS\Audit\Check-PrivilegedExternalAccounts.psm1'
    Import-Module $modulePath -Force

    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'Check-PrivilegedExternalUsers' {
    BeforeEach {
        $script:commonParams = @{
            ControlName = 'GUARDRAIL 2'
            ItemName    = 'Privileged External Accounts'
            itsgcode    = 'AC-2'
            msgTable    = @{
                noGuestAccounts                    = 'No guest accounts found.'
                guestAssigned                      = 'Guest assigned role.'
                guestNotAssigned                   = 'Guest not assigned role.'
                guestAccountsNoPrivilegedPermission = 'Guest accounts have no privileged permissions.'
            }
            ReportTime  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        }
    }

    Context 'When no guest accounts exist' {
        It 'Should return compliant' {
            Mock Get-AzADUser -ModuleName 'Check-PrivilegedExternalAccounts'  { return $null }

            $result = Check-PrivilegedExternalUsers @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
            $result.ComplianceResults.Comments | Should -Be 'No guest accounts found.'
        }
    }

    Context 'When guest accounts exist but have no role assignments' {
        It 'Should return compliant' {
            $guestUsers = @(
                [PSCustomObject]@{ DisplayName = 'Guest1'; Id = 'g1'; mail = 'guest1@ext.com'; userType = 'Guest'; createdDateTime = '2024-01-01'; accountEnabled = $true; UserPrincipalName = 'guest1_ext.com#EXT#@test.com' }
            )

            Mock Get-AzADUser -ModuleName 'Check-PrivilegedExternalAccounts'  { return $guestUsers }
            Mock Get-AzSubscription -ModuleName 'Check-PrivilegedExternalAccounts'  {
                @([PSCustomObject]@{ Id = 'sub1'; Name = 'TestSub'; State = 'Enabled' })
            }
            Mock Get-AzRoleAssignment -ModuleName 'Check-PrivilegedExternalAccounts'  { return @() }

            $result = Check-PrivilegedExternalUsers @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
        }
    }
}
