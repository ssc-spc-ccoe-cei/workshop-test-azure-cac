BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 2 MANAGE ACCESS\Audit\Check-GuestRoleReviews.psm1'
    Import-Module $modulePath -Force

    function Invoke-GraphQueryEX { param($urlPath) }
    function Expand-ListColumns { param($accessReviewList) return $accessReviewList }
    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'Check-GuestRoleReviews' {
    BeforeEach {
        $script:commonParams = @{
            ControlName = 'GUARDRAIL 2'
            ItemName    = 'Guest Role Reviews'
            itsgcode    = 'AC-2'
            msgTable    = @{
                isCompliant                        = 'Compliant'
                isNotCompliant                     = 'Not Compliant'
                noAutomatedAccessReviewForGuests    = 'No automated access review for guests.'
                noInProgressGuestAccessReview       = 'No in-progress guest access review.'
                noScheduledGuestAccessReview        = 'No scheduled guest access review.'
                compliantRecurrenceGuestReviews     = 'Compliant recurrence guest reviews.'
                nonCompliantRecurrenceReviews       = 'Non-compliant recurrence reviews.'
            }
            ReportTime  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        }
    }

    Context 'When no access reviews exist' {
        It 'Should return non-compliant' {
            Mock Invoke-GraphQueryEX -ModuleName 'Check-GuestRoleReviews'  {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = @() } }
            }

            $result = Check-GuestRoleReviews @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
        }
    }

    Context 'When access reviews exist but none are in progress' {
        It 'Should return non-compliant' {
            $reviews = @(
                [PSCustomObject]@{
                    displayName    = 'Guest Review'
                    id             = 'r1'
                    status         = 'Completed'
                    createdDateTime = '2024-01-01'
                    createdBy      = [PSCustomObject]@{ userPrincipalName = 'admin@test.com' }
                    settings       = [PSCustomObject]@{
                        recurrence = [PSCustomObject]@{
                            range   = [PSCustomObject]@{ startDate = '2024-01-01'; endDate = '2024-12-31'; type = 'noEnd' }
                            pattern = [PSCustomObject]@{ type = 'weekly' }
                        }
                    }
                    scope     = [PSCustomObject]@{ query = '/guest'; principalScopes = $null; resourceScopes = $null }
                    reviewers = @([PSCustomObject]@{ query = '/v1.0/users/user1' })
                }
            )

            Mock Invoke-GraphQueryEX -ModuleName 'Check-GuestRoleReviews'  {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = $reviews } }
            }

            $result = Check-GuestRoleReviews @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
        }
    }

    Context 'When Graph API call fails' {
        It 'Should add error to ErrorList' {
            Mock Invoke-GraphQueryEX -ModuleName 'Check-GuestRoleReviews'  { throw 'API Error' }

            $result = Check-GuestRoleReviews @commonParams

            $result.Errors.Count | Should -BeGreaterThan 0
        }
    }
}
