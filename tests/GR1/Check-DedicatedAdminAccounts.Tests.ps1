BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 1 PROTECT USER ACCOUNTS AND IDENTITIES\Audit\Check-DedicatedAdminAccounts.psm1'
    Import-Module $modulePath -Force

    function Invoke-GraphQueryEX { param($urlPath) }
    function add-documentFileExtensions { param($DocumentName, $ItemName) return @('AdminAccounts.csv') }
    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'Check-DedicatedAdminAccounts' {
    BeforeEach {
        $script:commonParams = @{
            StorageAccountName  = 'teststorage'
            ContainerName       = 'testcontainer'
            ResourceGroupName   = 'TestRG'
            SubscriptionID      = '00000000-0000-0000-0000-000000000000'
            ControlName         = 'GUARDRAIL 1'
            ItemName            = 'Dedicated Admin Accounts'
            itsgcode            = 'AC-6'
            msgTable            = @{
                isCompliant                            = 'Compliant'
                isNotCompliant                         = 'Not Compliant'
                procedureFileNotFound                  = 'File {0} not found in {1} of {2}.'
                procedureFileNotFoundWithCorrectExtension = 'File {0} found in {1} of {2} but has wrong extension.'
                invalidUserFile                        = 'Invalid user file {0}.'
                invalidFileHeader                      = 'Invalid file header in {0}.'
                bgAccExistInUPNlist                    = 'BG accounts found in UPN list.'
                missingHPaccUPN                        = 'HP admin UPN is missing.'
                missingRegAccUPN                       = 'Regular account UPN is missing.'
                dupHPAccount                           = 'Duplicate HP account.'
                dupRegAccount                          = 'Duplicate regular account.'
                dedicatedAdminAccNotExist              = 'Dedicated admin account not found.'
                regAccHasHProle                        = 'Regular account has HP role.'
                dedicatedAccExist                      = 'Dedicated admin accounts exist.'
                hpAccNotGA                             = 'HP account not GA.'
            }
            ReportTime          = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
            FirstBreakGlassUPN  = 'bg1@test.com'
            SecondBreakGlassUPN = 'bg2@test.com'
            DocumentName        = @('AdminAccounts')
        }
    }

    Context 'When Graph API fails to retrieve directory roles' {
        It 'Should add error to ErrorList' {
            Mock Invoke-GraphQueryEX -ModuleName 'Check-DedicatedAdminAccounts'  { throw 'Graph API failed' }
            Mock Set-AzContext -ModuleName 'Check-DedicatedAdminAccounts'  {}
            Mock Get-AzStorageAccount -ModuleName 'Check-DedicatedAdminAccounts'  { throw 'Storage not found' }

            { Check-DedicatedAdminAccounts @commonParams } | Should -Throw
        }
    }

    Context 'When blob file is not found' {
        It 'Should return comment about missing file' {
            $rolesResponse = @(
                [PSCustomObject]@{ displayName = 'Global Administrator'; id = 'ga-id' },
                [PSCustomObject]@{ displayName = 'Privileged Role Administrator'; id = 'pra-id' }
            )

            Mock Invoke-GraphQueryEX -ModuleName 'Check-DedicatedAdminAccounts'  -ParameterFilter { $urlPath -eq '/directoryRoles' } {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = $rolesResponse } }
            }
            Mock Invoke-GraphQueryEX -ModuleName 'Check-DedicatedAdminAccounts'  -ParameterFilter { $urlPath -like '/directoryRoles/*/members' } {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = @() } }
            }
            Mock Invoke-GraphQueryEX -ModuleName 'Check-DedicatedAdminAccounts'  -ParameterFilter { $urlPath -eq '/users' } {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = @() } }
            }
            Mock Set-AzContext -ModuleName 'Check-DedicatedAdminAccounts'  {}
            Mock Get-AzStorageAccount -ModuleName 'Check-DedicatedAdminAccounts'  {
                [PSCustomObject]@{ Context = 'mock-context' }
            }
            Mock Get-AzStorageBlob -ModuleName 'Check-DedicatedAdminAccounts'  { return $null }

            $result = Check-DedicatedAdminAccounts @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
        }
    }
}
