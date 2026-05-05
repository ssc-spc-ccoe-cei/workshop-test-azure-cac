BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 1 PROTECT USER ACCOUNTS AND IDENTITIES\Audit\Check-GAUserCountMFARequired.psm1'
    Import-Module $modulePath -Force

    function Invoke-GraphQueryEX { param($urlPath) }
    function Get-AllUserAuthInformation { param($allUserList) }
    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'get-MFACount' {
    Context 'When all GA member users have valid MFA' {
        It 'Should return correct userValidMFACounter' {
            $gaUsers = @(
                [PSCustomObject]@{ userPrincipalName = 'admin1@test.com'; mail = 'admin1@test.com' }
            )

            Mock Get-AllUserAuthInformation -ModuleName 'Check-GAUserCountMFARequired'  {
                [PSCustomObject]@{
                    userUPNsBadMFA      = @()
                    userUPNsValidMFA    = @([PSCustomObject]@{ UPN = 'admin1@test.com' })
                    userValidMFACounter = 1
                    ErrorList           = $null
                }
            }

            $result = get-MFACount -globalAdminUserAccounts $gaUsers

            $result.userValidMFACounter | Should -Be 1
            $result.userUPNsBadMFA | Should -BeNullOrEmpty
        }
    }

    Context 'When GA user has bad MFA' {
        It 'Should return user in userUPNsBadMFA' {
            $gaUsers = @(
                [PSCustomObject]@{ userPrincipalName = 'admin1@test.com'; mail = 'admin1@test.com' }
            )

            Mock Get-AllUserAuthInformation -ModuleName 'Check-GAUserCountMFARequired'  {
                [PSCustomObject]@{
                    userUPNsBadMFA      = @([PSCustomObject]@{ UPN = 'admin1@test.com' })
                    userUPNsValidMFA    = @()
                    userValidMFACounter = 0
                    ErrorList           = $null
                }
            }

            $result = get-MFACount -globalAdminUserAccounts $gaUsers

            $result.userValidMFACounter | Should -Be 0
            $result.userUPNsBadMFA.Count | Should -Be 1
        }
    }
}

Describe 'Check-GAUserCountMFARequired' {
    BeforeEach {
        $script:commonParams = @{
            ControlName         = 'GUARDRAIL 1'
            ItemName            = 'GA User Count MFA'
            itsgcode            = 'AC-2'
            msgTable            = @{
                isCompliant                 = 'Compliant'
                isNotCompliant              = 'Not Compliant'
                globalAdminAccntsMinimum    = 'GA accounts at minimum.'
                globalAdminAccntsSurplus    = 'GA accounts surplus (>5).'
                allGAUserHaveMFA            = 'All GA users have MFA.'
                gaUserMisconfiguredMFA      = 'GA users with misconfigured MFA: {0}'
            }
            ReportTime          = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
            FirstBreakGlassUPN  = 'bg1@test.com'
            SecondBreakGlassUPN = 'bg2@test.com'
        }
    }

    Context 'When only BG accounts are GA (0 non-BG GA users)' {
        It 'Should return compliant' {
            $rolesResponse = @([PSCustomObject]@{ displayName = 'Global Administrator'; id = 'ga-role-id' })
            $gaMembers = @(
                [PSCustomObject]@{ userPrincipalName = 'bg1@test.com'; id = '1'; displayName = 'BG1'; mail = 'bg1@test.com' },
                [PSCustomObject]@{ userPrincipalName = 'bg2@test.com'; id = '2'; displayName = 'BG2'; mail = 'bg2@test.com' }
            )

            Mock Invoke-GraphQueryEX -ModuleName 'Check-GAUserCountMFARequired'  -ParameterFilter { $urlPath -eq '/directoryRoles' } -MockWith {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = $rolesResponse } }
            }
            Mock Invoke-GraphQueryEX -ModuleName 'Check-GAUserCountMFARequired'  -ParameterFilter { $urlPath -like '/directoryRoles/*/members' } -MockWith {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = $gaMembers } }
            }

            $result = Check-GAUserCountMFARequired @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
        }
    }

    Context 'When more than 5 non-BG GA users exist' {
        It 'Should return non-compliant with surplus message' {
            $rolesResponse = @([PSCustomObject]@{ displayName = 'Global Administrator'; id = 'ga-role-id' })
            $gaMembers = @()
            1..8 | ForEach-Object {
                $gaMembers += [PSCustomObject]@{ userPrincipalName = "admin$_@test.com"; id = "$_"; displayName = "Admin$_"; mail = "admin$_@test.com" }
            }

            Mock Invoke-GraphQueryEX -ModuleName 'Check-GAUserCountMFARequired'  -ParameterFilter { $urlPath -eq '/directoryRoles' } -MockWith {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = $rolesResponse } }
            }
            Mock Invoke-GraphQueryEX -ModuleName 'Check-GAUserCountMFARequired'  -ParameterFilter { $urlPath -like '/directoryRoles/*/members' } -MockWith {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = $gaMembers } }
            }

            $result = Check-GAUserCountMFARequired @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
        }
    }

    Context 'When 1-5 non-BG GA users all have MFA' {
        It 'Should return compliant' {
            $rolesResponse = @([PSCustomObject]@{ displayName = 'Global Administrator'; id = 'ga-role-id' })
            $gaMembers = @(
                [PSCustomObject]@{ userPrincipalName = 'admin1@test.com'; id = '10'; displayName = 'Admin1'; mail = 'admin1@test.com' },
                [PSCustomObject]@{ userPrincipalName = 'admin2@test.com'; id = '11'; displayName = 'Admin2'; mail = 'admin2@test.com' }
            )

            Mock Invoke-GraphQueryEX -ModuleName 'Check-GAUserCountMFARequired'  -ParameterFilter { $urlPath -eq '/directoryRoles' } -MockWith {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = $rolesResponse } }
            }
            Mock Invoke-GraphQueryEX -ModuleName 'Check-GAUserCountMFARequired'  -ParameterFilter { $urlPath -like '/directoryRoles/*/members' } -MockWith {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = $gaMembers } }
            }
            Mock Get-AllUserAuthInformation -ModuleName 'Check-GAUserCountMFARequired'  {
                [PSCustomObject]@{
                    userUPNsBadMFA      = @()
                    userUPNsValidMFA    = @([PSCustomObject]@{ UPN = 'admin1@test.com' }, [PSCustomObject]@{ UPN = 'admin2@test.com' })
                    userValidMFACounter = 2
                    ErrorList           = $null
                }
            }

            $result = Check-GAUserCountMFARequired @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
        }
    }
}
