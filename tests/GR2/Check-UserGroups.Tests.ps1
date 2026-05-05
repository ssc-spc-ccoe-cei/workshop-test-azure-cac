BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 2 MANAGE ACCESS\Audit\Check-UserGroups.psm1'
    Import-Module $modulePath -Force

    function Invoke-GraphQueryEX { param($urlPath) }
    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'Check-UserGroups' {
    BeforeEach {
        $script:commonParams = @{
            ControlName = 'GUARDRAIL 2'
            ItemName    = 'User Groups'
            itsgcode    = 'AC-2'
            msgTable    = @{
                isCompliant    = 'Compliant'
                isNotCompliant = 'Not Compliant'
                userCountOne   = 'Only 1 user in tenant.'
                userGroupsMany = 'Fewer than 2 user groups in tenant.'
                userInGroup    = 'User is in a group.'
                userNotInGroup = 'User is not in any group.'
                groupsCAPCompliant    = 'Groups referenced in CAP.'
                groupsCAPNonCompliant = 'No groups referenced in CAP.'
            }
            ReportTime  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        }
    }

    Context 'When only 1 user exists in the tenant' {
        It 'Should return compliant' {
            Mock Get-AzAccessToken -ModuleName 'Check-UserGroups'  { [PSCustomObject]@{ Token = 'mock-token' } }
            Mock Invoke-RestMethod -ModuleName 'Check-UserGroups'  -ParameterFilter { $Uri -like '*users?*' } {
                [PSCustomObject]@{
                    value = @([PSCustomObject]@{ id = '1'; displayName = 'User1'; givenName = 'U'; userPrincipalName = 'user1@test.com' })
                    '@odata.nextLink' = $null
                }
            }
            Mock Invoke-RestMethod -ModuleName 'Check-UserGroups'  -ParameterFilter { $Uri -like '*users/$count*Member*' } { 1 }
            Mock Invoke-RestMethod -ModuleName 'Check-UserGroups'  -ParameterFilter { $Uri -like '*users/$count*Guest*' } { 0 }
            Mock Invoke-RestMethod -ModuleName 'Check-UserGroups'  -ParameterFilter { $Uri -like '*groups/$count*' } { 0 }
            Mock Invoke-RestMethod -ModuleName 'Check-UserGroups'  -ParameterFilter { $Uri -like '*groups?*' } {
                [PSCustomObject]@{ value = @(); '@odata.nextLink' = $null }
            }

            $result = Check-UserGroups @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
        }
    }

    Context 'When fewer than 2 groups exist' {
        It 'Should return non-compliant' {
            Mock Get-AzAccessToken -ModuleName 'Check-UserGroups'  { [PSCustomObject]@{ Token = 'mock-token' } }
            Mock Invoke-RestMethod -ModuleName 'Check-UserGroups'  -ParameterFilter { $Uri -like '*users?*' } {
                [PSCustomObject]@{
                    value = @(
                        [PSCustomObject]@{ id = '1'; displayName = 'User1'; givenName = 'U1'; userPrincipalName = 'user1@test.com' },
                        [PSCustomObject]@{ id = '2'; displayName = 'User2'; givenName = 'U2'; userPrincipalName = 'user2@test.com' }
                    )
                    '@odata.nextLink' = $null
                }
            }
            Mock Invoke-RestMethod -ModuleName 'Check-UserGroups'  -ParameterFilter { $Uri -like '*users/$count*Member*' } { 2 }
            Mock Invoke-RestMethod -ModuleName 'Check-UserGroups'  -ParameterFilter { $Uri -like '*users/$count*Guest*' } { 0 }
            Mock Invoke-RestMethod -ModuleName 'Check-UserGroups'  -ParameterFilter { $Uri -like '*groups/$count*' } { 1 }
            Mock Invoke-RestMethod -ModuleName 'Check-UserGroups'  -ParameterFilter { $Uri -like '*groups?*' } {
                [PSCustomObject]@{
                    value = @([PSCustomObject]@{ id = 'g1' })
                    '@odata.nextLink' = $null
                }
            }
            Mock Invoke-RestMethod -ModuleName 'Check-UserGroups'  -ParameterFilter { $Uri -like '*groups/g1/members*' } {
                [PSCustomObject]@{ value = @([PSCustomObject]@{ userPrincipalName = 'user1@test.com' }); '@odata.nextLink' = $null }
            }

            $result = Check-UserGroups @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
        }
    }
}
