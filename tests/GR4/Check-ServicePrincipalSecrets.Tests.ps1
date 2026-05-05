BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 4 ENTERPRISE MONITORING ACCOUNTS\Audit\Check-ServicePrincipalSecrets.psm1'
    Import-Module $modulePath -Force

    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'Get-DepartmentServicePrincipalNameSecrets' {
    BeforeEach {
        $script:commonParams = @{
            SPNID       = '00000000-0000-0000-0000-000000000001'
            ControlName = 'GUARDRAIL 4'
            ItemName    = 'SPN Secrets'
            itsgcode    = 'IA-5'
            msgTable    = @{
                NoSPN                       = 'SPN not found.'
                SPNNoValidCredentials       = 'SPN has no valid credentials. Expired: {0}'
                SPNSingleValidCredential    = 'SPN has 1 valid credential: {0}'
                SPNMultipleValidCredentials = 'SPN has multiple valid credentials: {0}'
            }
            ReportTime  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        }
    }

    Context 'When SPN does not exist' {
        It 'Should return non-compliant' {
            Mock Get-AzADServicePrincipal -ModuleName 'Check-ServicePrincipalSecrets'  { return $null }

            $result = Get-DepartmentServicePrincipalNameSecrets @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
            $result.ComplianceResults.Comments | Should -Be 'SPN not found.'
        }
    }

    Context 'When SPN exists with exactly 1 valid credential' {
        It 'Should return compliant' {
            Mock Get-AzADServicePrincipal -ModuleName 'Check-ServicePrincipalSecrets'  {
                [PSCustomObject]@{ AppId = '00000000-0000-0000-0000-000000000001'; Id = 'spn-id' }
            }
            Mock Get-AzADAppCredential -ModuleName 'Check-ServicePrincipalSecrets'  {
                @([PSCustomObject]@{
                    DisplayName = 'Secret1'
                    EndDateTime = (Get-Date).AddDays(30)
                })
            }

            $result = Get-DepartmentServicePrincipalNameSecrets @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
        }
    }

    Context 'When SPN exists with no valid credentials (all expired)' {
        It 'Should return non-compliant' {
            Mock Get-AzADServicePrincipal -ModuleName 'Check-ServicePrincipalSecrets'  {
                [PSCustomObject]@{ AppId = '00000000-0000-0000-0000-000000000001'; Id = 'spn-id' }
            }
            Mock Get-AzADAppCredential -ModuleName 'Check-ServicePrincipalSecrets'  {
                @([PSCustomObject]@{
                    DisplayName = 'ExpiredSecret'
                    EndDateTime = (Get-Date).AddDays(-30)
                })
            }

            $result = Get-DepartmentServicePrincipalNameSecrets @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
        }
    }

    Context 'When SPN exists with multiple valid credentials' {
        It 'Should return non-compliant' {
            Mock Get-AzADServicePrincipal -ModuleName 'Check-ServicePrincipalSecrets'  {
                [PSCustomObject]@{ AppId = '00000000-0000-0000-0000-000000000001'; Id = 'spn-id' }
            }
            Mock Get-AzADAppCredential -ModuleName 'Check-ServicePrincipalSecrets'  {
                @(
                    [PSCustomObject]@{ DisplayName = 'Secret1'; EndDateTime = (Get-Date).AddDays(30) },
                    [PSCustomObject]@{ DisplayName = 'Secret2'; EndDateTime = (Get-Date).AddDays(60) }
                )
            }

            $result = Get-DepartmentServicePrincipalNameSecrets @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
        }
    }

    Context 'When Get-AzADServicePrincipal throws' {
        It 'Should add error to ErrorList' {
            Mock Get-AzADServicePrincipal -ModuleName 'Check-ServicePrincipalSecrets'  { throw 'SPN retrieval failed' }

            $result = Get-DepartmentServicePrincipalNameSecrets @commonParams

            $result.Errors.Count | Should -BeGreaterThan 0
            $result.ComplianceResults.ComplianceStatus | Should -Be $false
        }
    }
}
