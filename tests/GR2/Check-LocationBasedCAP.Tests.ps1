BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 2 MANAGE ACCESS\Audit\Check-LocationBasedCAP.psm1'
    Import-Module $modulePath -Force

    function Get-allowedLocationCAPCompliance { param($ErrorList, $IsCompliant) }
    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'Get-LocationBasedCAP' {
    BeforeEach {
        $script:commonParams = @{
            ControlName = 'GUARDRAIL 2'
            ItemName    = 'Location Based CAP'
            itsgcode    = 'AC-2'
            msgTable    = @{
                isCompliant    = 'Compliant'
                isNotCompliant = 'Not Compliant'
                compliantC2    = 'Location CAP is compliant.'
                nonCompliantC2 = 'Location CAP is not compliant.'
            }
            ReportTime  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        }
    }

    Context 'When location CAP compliance returns compliant' {
        It 'Should return compliant' {
            Mock Get-allowedLocationCAPCompliance -ModuleName 'Check-LocationBasedCAP'  {
                [PSCustomObject]@{
                    ComplianceStatus = $true
                    Comments         = 'Canada locations configured.'
                    Errors           = @()
                }
            }

            $result = Get-LocationBasedCAP @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
            $result.ComplianceResults.Comments | Should -Match 'Compliant'
        }
    }

    Context 'When location CAP compliance returns non-compliant' {
        It 'Should return non-compliant' {
            Mock Get-allowedLocationCAPCompliance -ModuleName 'Check-LocationBasedCAP'  {
                [PSCustomObject]@{
                    ComplianceStatus = $false
                    Comments         = 'No location policy found.'
                    Errors           = @()
                }
            }

            $result = Get-LocationBasedCAP @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
            $result.ComplianceResults.Comments | Should -Match 'Not Compliant'
        }
    }
}
