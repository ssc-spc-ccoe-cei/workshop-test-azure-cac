BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 2 MANAGE ACCESS\Audit\Check-ExternalAccounts.psm1'
    Import-Module $modulePath -Force

    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'Check-ExternalUsers' {
    BeforeEach {
        $script:commonParams = @{
            ControlName = 'GUARDRAIL 2'
            ItemName    = 'External Accounts'
            itsgcode    = 'AC-2'
            msgTable    = @{
                noGuestAccounts              = 'No guest accounts found.'
                guestAssigned                = 'Guest assigned role.'
                guestNotAssigned             = 'Guest not assigned role.'
                guestAccountsNoPermission    = 'Guest accounts have no permissions.'
                existingGuestAccountsComment = 'Existing guest accounts detected.'
                existingGuestAccounts        = 'Review guest accounts.'
            }
            ReportTime  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        }
    }

    Context 'When no guest accounts exist' {
        It 'Should return compliant with no guest accounts message' {
            Mock Get-AzADUser -ModuleName 'Check-ExternalAccounts'  { return $null }

            $result = Check-ExternalUsers @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
            $result.ComplianceResults.Comments | Should -Be 'No guest accounts found.'
        }
    }

    Context 'When guest accounts exist but have no role assignments' {
        It 'Should return compliant' {
            $guestUsers = @(
                [PSCustomObject]@{ DisplayName = 'Guest1'; Id = 'g1'; mail = 'guest1@ext.com'; userType = 'Guest'; createdDateTime = '2024-01-01'; accountEnabled = $true }
            )

            Mock Get-AzADUser -ModuleName 'Check-ExternalAccounts'  { return $guestUsers }
            Mock Get-AzSubscription -ModuleName 'Check-ExternalAccounts'  {
                @([PSCustomObject]@{ Id = 'sub1'; Name = 'TestSub'; State = 'Enabled' })
            }
            Mock Get-AzRoleAssignment -ModuleName 'Check-ExternalAccounts'  { return @() }

            $result = Check-ExternalUsers @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
        }
    }

    Context 'When guest accounts have role assignments' {
        It 'Should return compliant but log the guest users' {
            $guestUsers = @(
                [PSCustomObject]@{ DisplayName = 'Guest1'; Id = 'g1'; mail = 'guest1@ext.com'; userType = 'Guest'; createdDateTime = '2024-01-01'; accountEnabled = $true }
            )

            Mock Get-AzADUser -ModuleName 'Check-ExternalAccounts'  { return $guestUsers }
            Mock Get-AzSubscription -ModuleName 'Check-ExternalAccounts'  {
                @([PSCustomObject]@{ Id = 'sub1'; Name = 'TestSub'; State = 'Enabled' })
            }
            Mock Get-AzRoleAssignment -ModuleName 'Check-ExternalAccounts'  {
                @([PSCustomObject]@{ ObjectId = 'g1'; RoleDefinitionName = 'Reader' })
            }

            $result = Check-ExternalUsers @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
        }
    }
}
