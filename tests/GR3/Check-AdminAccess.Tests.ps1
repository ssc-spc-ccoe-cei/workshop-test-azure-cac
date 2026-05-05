BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 3 SECURE ENDPOINTS\Audit\Check-AdminAccess.psm1'
    Import-Module $modulePath -Force

    function Invoke-GraphQuery { param($urlPath) }
    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'Get-AdminAccess' {
    BeforeEach {
        $script:commonParams = @{
            ControlName = 'GUARDRAIL 3'
            ItemName    = 'Admin Access'
            itsgcode    = 'AC-6'
            msgTable    = @{
                hasRequiredPolicies      = 'Both device and location policies exist.'
                noLocationFilterPolicies = 'No location-based filter policies.'
                noDeviceFilterPolicies   = 'No device-based filter policies.'
                noCompliantPoliciesAdmin = 'No compliant admin access policies.'
            }
            ReportTime  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        }
    }

    Context 'When both device and location policies exist' {
        It 'Should return compliant' {
            $caps = @(
                [PSCustomObject]@{
                    state = 'enabled'
                    conditions = [PSCustomObject]@{
                        devices = [PSCustomObject]@{ deviceFilter = 'some-filter' }
                        applications = [PSCustomObject]@{ includeApplications = @('All') }
                        locations = $null
                        users = [PSCustomObject]@{ includeRoles = '62e90394-69f5-4237-9190-012177145e10' }
                    }
                },
                [PSCustomObject]@{
                    state = 'enabled'
                    conditions = [PSCustomObject]@{
                        devices = $null
                        applications = [PSCustomObject]@{ includeApplications = @('All') }
                        locations = [PSCustomObject]@{ includeLocations = @('Canada') }
                        users = [PSCustomObject]@{ includeRoles = '62e90394-69f5-4237-9190-012177145e10' }
                    }
                }
            )

            Mock Invoke-GraphQuery -ModuleName 'Check-AdminAccess'  {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = $caps } }
            }

            $result = Get-AdminAccess @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
            $result.ComplianceResults.Comments | Should -Be 'Both device and location policies exist.'
        }
    }

    Context 'When no policies exist' {
        It 'Should return non-compliant' {
            Mock Invoke-GraphQuery -ModuleName 'Check-AdminAccess'  {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = @() } }
            }

            $result = Get-AdminAccess @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
            $result.ComplianceResults.Comments | Should -Be 'No compliant admin access policies.'
        }
    }

    Context 'When only device policies exist' {
        It 'Should return non-compliant with missing location message' {
            $caps = @(
                [PSCustomObject]@{
                    state = 'enabled'
                    conditions = [PSCustomObject]@{
                        devices = [PSCustomObject]@{ deviceFilter = 'filter' }
                        applications = [PSCustomObject]@{ includeApplications = @('All') }
                        locations = $null
                        users = [PSCustomObject]@{ includeRoles = '62e90394-69f5-4237-9190-012177145e10' }
                    }
                }
            )

            Mock Invoke-GraphQuery -ModuleName 'Check-AdminAccess'  {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = $caps } }
            }

            $result = Get-AdminAccess @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
            $result.ComplianceResults.Comments | Should -Be 'No location-based filter policies.'
        }
    }

    Context 'When Graph API fails' {
        It 'Should add error to ErrorList' {
            Mock Invoke-GraphQuery -ModuleName 'Check-AdminAccess'  { throw 'API Error' }

            $result = Get-AdminAccess @commonParams

            $result.Errors.Count | Should -BeGreaterThan 0
        }
    }
}
