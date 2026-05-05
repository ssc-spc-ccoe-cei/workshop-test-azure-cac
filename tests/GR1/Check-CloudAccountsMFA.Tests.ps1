BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 1 PROTECT USER ACCOUNTS AND IDENTITIES\Audit\Check-CloudAccountsMFA.psm1'
    Import-Module $modulePath -Force

    function Invoke-GraphQueryEX { param($urlPath) }
    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'Check-CloudAccountsMFA' {
    BeforeEach {
        $script:commonParams = @{
            ControlName = 'GUARDRAIL 1'
            ItemName    = 'Cloud Accounts MFA'
            itsgcode    = 'AC-2'
            msgTable    = @{
                mfaRequiredForAllUsers = 'MFA is required for all users.'
                noMFAPolicyForAllUsers = 'No MFA policy found for all users.'
            }
            ReportTime  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        }
    }

    Context 'When a valid MFA policy exists for all users' {
        It 'Should return compliant status' {
            $mockPolicy = [PSCustomObject]@{
                state = 'enabled'
                conditions = [PSCustomObject]@{
                    users = [PSCustomObject]@{ includeUsers = @('All') }
                    applications = [PSCustomObject]@{ includeApplications = @('All') }
                    clientAppTypes = @('all')
                    userRiskLevels = $null
                    signInRiskLevels = $null
                    platforms = $null
                    locations = $null
                    devices = $null
                    clientApplications = $null
                }
                grantControls = [PSCustomObject]@{ builtInControls = @('mfa') }
            }

            Mock Invoke-GraphQueryEX -ModuleName 'Check-CloudAccountsMFA'  {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = @($mockPolicy) } }
            }

            $result = Check-CloudAccountsMFA @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
            $result.ComplianceResults.Comments | Should -Be 'MFA is required for all users.'
        }
    }

    Context 'When no valid MFA policy exists' {
        It 'Should return non-compliant status' {
            $mockPolicy = [PSCustomObject]@{
                state = 'disabled'
                conditions = [PSCustomObject]@{
                    users = [PSCustomObject]@{ includeUsers = @('All') }
                    applications = [PSCustomObject]@{ includeApplications = @('All') }
                    clientAppTypes = @('all')
                    userRiskLevels = $null
                    signInRiskLevels = $null
                    platforms = $null
                    locations = $null
                    devices = $null
                    clientApplications = $null
                }
                grantControls = [PSCustomObject]@{ builtInControls = @('mfa') }
            }

            Mock Invoke-GraphQueryEX -ModuleName 'Check-CloudAccountsMFA'  {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = @($mockPolicy) } }
            }

            $result = Check-CloudAccountsMFA @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
            $result.ComplianceResults.Comments | Should -Be 'No MFA policy found for all users.'
        }
    }

    Context 'When no policies are returned' {
        It 'Should return non-compliant' {
            Mock Invoke-GraphQueryEX -ModuleName 'Check-CloudAccountsMFA'  {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = @() } }
            }

            $result = Check-CloudAccountsMFA @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
        }
    }

    Context 'When Graph API call fails' {
        It 'Should add error to ErrorList' {
            Mock Invoke-GraphQueryEX -ModuleName 'Check-CloudAccountsMFA'  { throw 'API Error' }

            $result = Check-CloudAccountsMFA @commonParams

            $result.Errors.Count | Should -BeGreaterThan 0
        }
    }

    Context 'When policy targets MicrosoftAdminPortals' {
        It 'Should return compliant status' {
            $mockPolicy = [PSCustomObject]@{
                state = 'enabled'
                conditions = [PSCustomObject]@{
                    users = [PSCustomObject]@{ includeUsers = @('All') }
                    applications = [PSCustomObject]@{ includeApplications = @('MicrosoftAdminPortals') }
                    clientAppTypes = @('all')
                    userRiskLevels = $null
                    signInRiskLevels = $null
                    platforms = $null
                    locations = $null
                    devices = $null
                    clientApplications = $null
                }
                grantControls = [PSCustomObject]@{ builtInControls = @('mfa') }
            }

            Mock Invoke-GraphQueryEX -ModuleName 'Check-CloudAccountsMFA'  {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = @($mockPolicy) } }
            }

            $result = Check-CloudAccountsMFA @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
        }
    }
}
