BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 2 MANAGE ACCESS\Audit\Check-UserRoleReviews.psm1'
    Import-Module $modulePath -Force

    function Invoke-GraphQueryEX { param($urlPath) }
    function Expand-ListColumns { param($accessReviewList) return $accessReviewList }
    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'Check-UserRoleReviews' {
    BeforeEach {
        $script:commonParams = @{
            ControlName = 'GUARDRAIL 2'
            ItemName    = 'User Role Reviews'
            itsgcode    = 'AC-2'
            msgTable    = @{
                isCompliant                    = 'Compliant'
                isNotCompliant                 = 'Not Compliant'
                noAutomatedAccessReviewForUsers = 'No automated access review for users.'
                noInProgressAccessReview        = 'No in-progress access review.'
                noScheduledUserAccessReview     = 'No scheduled user access review.'
                compliantRecurrenceReviews      = 'Compliant recurrence reviews.'
                nonCompliantRecurrenceReviews   = 'Non-compliant recurrence reviews.'
            }
            ReportTime  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        }
    }

    Context 'When no access reviews exist' {
        It 'Should return non-compliant' {
            Mock Invoke-GraphQueryEX -ModuleName 'Check-UserRoleReviews'  {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = @() } }
            }

            $result = Check-UserRoleReviews @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
        }
    }

    Context 'When Graph API returns null data' {
        It 'Should handle gracefully' {
            Mock Invoke-GraphQueryEX -ModuleName 'Check-UserRoleReviews'  {
                [PSCustomObject]@{ Content = $null }
            }

            $result = Check-UserRoleReviews @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
        }
    }

    Context 'When Graph API call fails' {
        It 'Should add error to ErrorList' {
            Mock Invoke-GraphQueryEX -ModuleName 'Check-UserRoleReviews'  { throw 'API Error' }

            $result = Check-UserRoleReviews @commonParams

            $result.Errors.Count | Should -BeGreaterThan 0
        }
    }
}
