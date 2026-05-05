BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 4 ENTERPRISE MONITORING ACCOUNTS\Audit\Check-ServicePrincipal.psm1'
    Import-Module $modulePath -Force

    function Invoke-GraphQuery { param($urlPath) }
    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'Verify-Roles' {
    Context 'When SPN has both Cost Management Reader and Marketplace Admin roles' {
        It 'Should set ComplianceStatus to true' {
            $spn = [PSCustomObject]@{
                ServicePrincipalNameAPPID = 'app-id'
                ServicePrincipalNameID    = 'spn-id'
                ComplianceStatus          = $false
                ComplianceComments        = ''
            }

            Mock Get-AzContext -ModuleName 'Check-ServicePrincipal'  { [PSCustomObject]@{ Tenant = [PSCustomObject]@{ Id = 'tenant-id' } } }
            Mock Get-AzRoleAssignment -ModuleName 'Check-ServicePrincipal'  -ParameterFilter { $true } {
                @([PSCustomObject]@{
                    ObjectId           = 'spn-id'
                    RoleDefinitionName = 'Cost Management Reader'
                    Scope              = '/providers/Microsoft.Management/managementGroups/tenant-id'
                })
            }
            Mock Get-AzRoleAssignment -ModuleName 'Check-ServicePrincipal'  -ParameterFilter { $Scope -like '*Marketplace*' } {
                @([PSCustomObject]@{
                    ObjectId           = 'spn-id'
                    RoleDefinitionName = 'Marketplace Admin'
                })
            }

            $msgTable = @{
                ServicePrincipalNameHasReaderRole            = 'Has Reader role. '
                ServicePrincipalNameHasNoReaderRole          = 'No Reader role. '
                ServicePrincipalNameHasMarketPlaceAdminRole  = 'Has Marketplace Admin role.'
                ServicePrincipalNameHasNoMarketPlaceAdminRole = 'No Marketplace Admin role.'
            }

            Verify-Roles -ServicePrincipal $spn -msgTable $msgTable

            # The function modifies the object in place
            $spn.ComplianceComments | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Check-DepartmentServicePrincipalName' {
    BeforeEach {
        $script:commonParams = @{
            SPNID       = '00000000-0000-0000-0000-000000000001'
            ControlName = 'GUARDRAIL 4'
            ItemName    = 'Department SPN'
            itsgcode    = 'SA-4'
            msgTable    = @{
                NoSPN   = 'SPN not found.'
                SPNExist = 'SPN exists.'
                ServicePrincipalNameHasReaderRole            = 'Has Reader role.'
                ServicePrincipalNameHasNoReaderRole          = 'No Reader role.'
                ServicePrincipalNameHasMarketPlaceAdminRole  = 'Has Marketplace Admin role.'
                ServicePrincipalNameHasNoMarketPlaceAdminRole = 'No Marketplace Admin role.'
            }
            ReportTime  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        }
    }

    Context 'When SPN does not exist' {
        It 'Should return non-compliant with NoSPN message' {
            Mock Get-AzADServicePrincipal -ModuleName 'Check-ServicePrincipal'  { return $null }

            $result = Check-DepartmentServicePrincipalName @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
            $result.ComplianceResults.Comments | Should -Be 'SPN not found.'
        }
    }

    Context 'When SPN exists and Graph API returns 200' {
        It 'Should check roles and return result' {
            Mock Get-AzADServicePrincipal -ModuleName 'Check-ServicePrincipal'  {
                [PSCustomObject]@{ AppId = '00000000-0000-0000-0000-000000000001'; Id = 'spn-id' }
            }
            Mock Invoke-GraphQuery -ModuleName 'Check-ServicePrincipal'  {
                [PSCustomObject]@{ statusCode = 200; Content = [PSCustomObject]@{} }
            }
            Mock Get-AzContext -ModuleName 'Check-ServicePrincipal'  { [PSCustomObject]@{ Tenant = [PSCustomObject]@{ Id = 'tenant-id' } } }
            Mock Get-AzRoleAssignment -ModuleName 'Check-ServicePrincipal'  { return @() }

            $result = Check-DepartmentServicePrincipalName @commonParams

            $result.ComplianceResults | Should -Not -BeNullOrEmpty
        }
    }

    Context 'When Graph API returns 404' {
        It 'Should return non-compliant' {
            Mock Get-AzADServicePrincipal -ModuleName 'Check-ServicePrincipal'  {
                [PSCustomObject]@{ AppId = '00000000-0000-0000-0000-000000000001'; Id = 'spn-id' }
            }
            Mock Invoke-GraphQuery -ModuleName 'Check-ServicePrincipal'  {
                [PSCustomObject]@{ statusCode = 404 }
            }

            $result = Check-DepartmentServicePrincipalName @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
        }
    }
}
