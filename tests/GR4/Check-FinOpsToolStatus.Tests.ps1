BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 4 ENTERPRISE MONITORING ACCOUNTS\Audit\Check-FinOpsToolStatus.psm1'
    Import-Module $modulePath -Force

    function Invoke-GraphQuery { param($urlPath) }
    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $ErrorList) return $Result }
}

Describe 'Check-ServicePrincipalExists' {
    Context 'When SPN exists' {
        It 'Should return true' {
            Mock Invoke-GraphQuery -ModuleName 'Check-FinOpsToolStatus'  {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'spn-id'; displayName = 'TestSPN' }) } }
            }

            $result = Check-ServicePrincipalExists -spnName 'TestSPN'

            $result | Should -Be $true
        }
    }

    Context 'When SPN does not exist' {
        It 'Should return false' {
            Mock Invoke-GraphQuery -ModuleName 'Check-FinOpsToolStatus'  {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = @() } }
            }

            $result = Check-ServicePrincipalExists -spnName 'NonExistentSPN'

            $result | Should -Be $false
        }
    }

    Context 'When Graph API throws' {
        It 'Should return false' {
            Mock Invoke-GraphQuery -ModuleName 'Check-FinOpsToolStatus'  { throw 'API Error' }

            $result = Check-ServicePrincipalExists -spnName 'FailSPN'

            $result | Should -Be $false
        }
    }
}

Describe 'Check-ServicePrincipalPermissions' {
    Context 'When SPN has required permissions' {
        It 'Should return true' {
            Mock Invoke-GraphQuery -ModuleName 'Check-FinOpsToolStatus'  -ParameterFilter { $urlPath -like '*servicePrincipals?*' } {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'spn-id' }) } }
            }
            Mock Invoke-GraphQuery -ModuleName 'Check-FinOpsToolStatus'  -ParameterFilter { $urlPath -like '*oauth2PermissionGrants*' } {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = @([PSCustomObject]@{ scope = 'User.Read user_impersonation' }) } }
            }

            $result = Check-ServicePrincipalPermissions -spnName 'TestSPN'

            $result | Should -Be $true
        }
    }

    Context 'When SPN is missing required permissions' {
        It 'Should return false' {
            Mock Invoke-GraphQuery -ModuleName 'Check-FinOpsToolStatus'  -ParameterFilter { $urlPath -like '*servicePrincipals?*' } {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'spn-id' }) } }
            }
            Mock Invoke-GraphQuery -ModuleName 'Check-FinOpsToolStatus'  -ParameterFilter { $urlPath -like '*oauth2PermissionGrants*' } {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = @([PSCustomObject]@{ scope = 'User.Read' }) } }
            }

            $result = Check-ServicePrincipalPermissions -spnName 'TestSPN'

            $result | Should -Be $false
        }
    }

    Context 'When SPN does not exist' {
        It 'Should return false' {
            Mock Invoke-GraphQuery -ModuleName 'Check-FinOpsToolStatus'  -ParameterFilter { $urlPath -like '*servicePrincipals?*' } {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = @() } }
            }

            $result = Check-ServicePrincipalPermissions -spnName 'NonExistent'

            $result | Should -Be $false
        }
    }
}

Describe 'Check-FinOpsToolStatus' {
    BeforeEach {
        $script:commonParams = @{
            ControlName = 'GUARDRAIL 4'
            ItemName    = 'FinOps Tool Status'
            itsgcode    = 'SA-4'
            msgTable    = @{
                SPNNotExist              = 'SPN does not exist.'
                SPNIncorrectPermissions  = 'SPN has incorrect permissions.'
                FinOpsToolCompliant      = 'FinOps tool is compliant.'
                FinOpsToolNonCompliant   = 'FinOps tool is non-compliant: {0}'
            }
            ReportTime  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        }
    }

    Context 'When SPN exists and has correct permissions' {
        It 'Should return compliant' {
            Mock Check-ServicePrincipalExists -ModuleName 'Check-FinOpsToolStatus'  { return $true }
            Mock Check-ServicePrincipalPermissions -ModuleName 'Check-FinOpsToolStatus'  { return $true }

            $result = Check-FinOpsToolStatus @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
            $result.ComplianceResults.Comments | Should -Be 'FinOps tool is compliant.'
        }
    }

    Context 'When SPN does not exist' {
        It 'Should return non-compliant' {
            Mock Check-ServicePrincipalExists -ModuleName 'Check-FinOpsToolStatus'  { return $false }

            $result = Check-FinOpsToolStatus @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
        }
    }

    Context 'When SPN exists but has incorrect permissions' {
        It 'Should return non-compliant' {
            Mock Check-ServicePrincipalExists -ModuleName 'Check-FinOpsToolStatus'  { return $true }
            Mock Check-ServicePrincipalPermissions -ModuleName 'Check-FinOpsToolStatus'  { return $false }

            $result = Check-FinOpsToolStatus @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
        }
    }
}
