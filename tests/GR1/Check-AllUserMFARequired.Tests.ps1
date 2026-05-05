BeforeAll {
    # Dot-source or import the module under test
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 1 PROTECT USER ACCOUNTS AND IDENTITIES\Audit\Check-AllUserMFARequired.psm1'
    Import-Module $modulePath -Force

    # Common mock for Add-ProfileInformation
    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'Check-AllUserMFARequired' {
    BeforeEach {
        $script:commonParams = @{
            ControlName  = 'GUARDRAIL 1'
            ItemName     = 'All User MFA'
            itsgcode     = 'AC-2'
            msgTable     = @{}
            ReportTime   = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        }
        # Set WorkSpaceID in the module scope where the function reads it
        InModuleScope 'Check-AllUserMFARequired' {
            $script:WorkSpaceID = 'test-workspace-id'
        }
    }

    Context 'When KQL function returns a valid compliance result on first attempt' {
        It 'Should return the compliance result successfully' {
            $mockResult = [PSCustomObject]@{ ComplianceStatus = $true; Comments = 'All users MFA compliant' }
            Mock Invoke-AzOperationalInsightsQuery -ModuleName 'Check-AllUserMFARequired' {
                [PSCustomObject]@{ Results = @($mockResult) }
            }
            Mock Start-Sleep -ModuleName 'Check-AllUserMFARequired' {}

            $result = Check-AllUserMFARequired @commonParams

            $result | Should -Not -BeNullOrEmpty
            $result.ComplianceResults | Should -Not -BeNullOrEmpty
        }
    }

    Context 'When KQL function returns no results after all retries' {
        It 'Should throw when no results are returned' {
            Mock Invoke-AzOperationalInsightsQuery -ModuleName 'Check-AllUserMFARequired' {
                [PSCustomObject]@{ Results = @() }
            }
            Mock Start-Sleep -ModuleName 'Check-AllUserMFARequired' {}

            { Check-AllUserMFARequired @commonParams } | Should -Throw
        }
    }

    Context 'When KQL function throws an exception on all retries' {
        It 'Should throw with failure message' {
            Mock Invoke-AzOperationalInsightsQuery -ModuleName 'Check-AllUserMFARequired' { throw 'Query failed' }
            Mock Start-Sleep -ModuleName 'Check-AllUserMFARequired' {}

            { Check-AllUserMFARequired @commonParams } | Should -Throw
        }
    }

    Context 'When EnableMultiCloudProfiles is set' {
        It 'Should call Add-ProfileInformation' {
            $mockResult = [PSCustomObject]@{ ComplianceStatus = $true; Comments = 'Compliant' }
            Mock Invoke-AzOperationalInsightsQuery -ModuleName 'Check-AllUserMFARequired'  {
                [PSCustomObject]@{ Results = @($mockResult) }
            }
            Mock Add-ProfileInformation -ModuleName 'Check-AllUserMFARequired'  { return $mockResult } -Verifiable

            $result = Check-AllUserMFARequired @commonParams -EnableMultiCloudProfiles -CloudUsageProfiles '3' -ModuleProfiles '1,2,3'

            Should -InvokeVerifiable
        }
    }
}
