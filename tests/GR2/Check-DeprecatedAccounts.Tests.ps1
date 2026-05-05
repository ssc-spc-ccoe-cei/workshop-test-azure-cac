BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 2 MANAGE ACCESS\Audit\Check-DeprecatedAccounts.psm1'
    Import-Module $modulePath -Force

    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'Check-DeprecatedUsers' {
    BeforeEach {
        $script:commonParams = @{
            ControlName = 'GUARDRAIL 2'
            ItemName    = 'Deprecated Accounts'
            itsgcode    = 'AC-2'
            msgTable    = @{
                noncompliantUsers   = 'Non-compliant users: '
                compliantComment    = 'No deprecated accounts found.'
                noncompliantComment = '{0} deprecated account(s) found. {1}'
                mitigationCommands  = 'Remove deprecated accounts.'
            }
            ReportTime  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        }
    }

    Context 'When no deprecated accounts exist' {
        It 'Should return compliant' {
            Mock Get-AzADUser -ModuleName 'Check-DeprecatedAccounts'  { return @() }

            $result = Check-DeprecatedUsers @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
            $result.ComplianceResults.Comments | Should -Be 'No deprecated accounts found.'
        }
    }

    Context 'When deprecated accounts exist' {
        It 'Should return non-compliant with user list' {
            $deprecatedUsers = @(
                [PSCustomObject]@{ UserPrincipalName = 'deprecated1@test.com'; onPremisesSyncEnabled = $null; accountEnabled = $false },
                [PSCustomObject]@{ UserPrincipalName = 'deprecated2@test.com'; onPremisesSyncEnabled = $null; accountEnabled = $false }
            )

            Mock Get-AzADUser -ModuleName 'Check-DeprecatedAccounts'  { return $deprecatedUsers }

            $result = Check-DeprecatedUsers @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
            $result.ComplianceResults.Comments | Should -Match 'deprecated'
        }
    }
}
