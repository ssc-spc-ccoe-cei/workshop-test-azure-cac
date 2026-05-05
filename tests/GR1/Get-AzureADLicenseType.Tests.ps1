BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 1 PROTECT USER ACCOUNTS AND IDENTITIES\Audit\Get-AzureADLicenseType.psm1'
    Import-Module $modulePath -Force

    function Invoke-GraphQueryEX { param($urlPath) }
    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'Get-ADLicenseType' {
    BeforeEach {
        $script:commonParams = @{
            ControlName = 'GUARDRAIL 1'
            ItemName    = 'AD License Type'
            itsgcode    = 'AC-2'
            msgTable    = @{
                MSEntIDLicenseTypeFound    = 'AAD_PREMIUM_P2 license found.'
                MSEntIDLicenseTypeNotFound = 'AAD_PREMIUM_P2 license not found.'
            }
            ReportTime  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        }
    }

    Context 'When AAD_PREMIUM_P2 license is found' {
        It 'Should return compliant with license type' {
            Mock Invoke-GraphQueryEX -ModuleName 'Get-AzureADLicenseType'  {
                [PSCustomObject]@{
                    Content = [PSCustomObject]@{
                        value = @([PSCustomObject]@{
                            servicePlans = @([PSCustomObject]@{ ServicePlanName = 'AAD_PREMIUM_P2' })
                        })
                    }
                }
            }

            $result = Get-ADLicenseType @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
            $result.ComplianceResults.ADLicenseType | Should -Be 'AAD_PREMIUM_P2'
            $result.ComplianceResults.Comments | Should -Be 'AAD_PREMIUM_P2 license found.'
        }
    }

    Context 'When AAD_PREMIUM_P2 license is not found' {
        It 'Should return non-compliant' {
            Mock Invoke-GraphQueryEX -ModuleName 'Get-AzureADLicenseType'  {
                [PSCustomObject]@{
                    Content = [PSCustomObject]@{
                        value = @([PSCustomObject]@{
                            servicePlans = @([PSCustomObject]@{ ServicePlanName = 'BASIC_LICENSE' })
                        })
                    }
                }
            }

            $result = Get-ADLicenseType @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
            $result.ComplianceResults.ADLicenseType | Should -Be 'N/A'
            $result.ComplianceResults.Comments | Should -Be 'AAD_PREMIUM_P2 license not found.'
        }
    }

    Context 'When Graph API call fails' {
        It 'Should populate ErrorList' {
            Mock Invoke-GraphQueryEX -ModuleName 'Get-AzureADLicenseType'  { throw 'API Error' }

            $result = Get-ADLicenseType @commonParams

            $result.Errors.Count | Should -BeGreaterThan 0
        }
    }
}
