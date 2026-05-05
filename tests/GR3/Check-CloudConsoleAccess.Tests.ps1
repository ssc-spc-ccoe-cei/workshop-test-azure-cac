BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 3 SECURE ENDPOINTS\Audit\Check-CloudConsoleAccess.psm1'
    Import-Module $modulePath -Force

    function Get-allowedLocationCAPCompliance { param($ErrorList, $IsCompliant) }
    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'Get-CloudConsoleAccess' {
    BeforeEach {
        $script:commonParams = @{
            ControlName = 'GUARDRAIL 3'
            ItemName    = 'Cloud Console Access'
            itsgcode    = 'AC-17'
            msgTable    = @{}
            ReportTime  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        }
    }

    Context 'When allowed location CAP is compliant' {
        It 'Should return compliant' {
            Mock Get-allowedLocationCAPCompliance -ModuleName 'Check-CloudConsoleAccess'  {
                [PSCustomObject]@{
                    ComplianceStatus = $true
                    Comments         = 'Location CAP configured.'
                    Errors           = @()
                }
            }

            $result = Get-CloudConsoleAccess @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
            $result.ComplianceResults.Comments | Should -Be 'Location CAP configured.'
        }
    }

    Context 'When allowed location CAP is non-compliant' {
        It 'Should return non-compliant' {
            Mock Get-allowedLocationCAPCompliance -ModuleName 'Check-CloudConsoleAccess'  {
                [PSCustomObject]@{
                    ComplianceStatus = $false
                    Comments         = 'No location CAP found.'
                    Errors           = @()
                }
            }

            $result = Get-CloudConsoleAccess @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
        }
    }

    Context 'When allowed location CAP returns errors' {
        It 'Should pass errors through' {
            Mock Get-allowedLocationCAPCompliance -ModuleName 'Check-CloudConsoleAccess'  {
                [PSCustomObject]@{
                    ComplianceStatus = $false
                    Comments         = 'Error occurred.'
                    Errors           = @('Error retrieving policies')
                }
            }

            $result = Get-CloudConsoleAccess @commonParams

            $result.Errors | Should -Contain 'Error retrieving policies'
        }
    }
}
