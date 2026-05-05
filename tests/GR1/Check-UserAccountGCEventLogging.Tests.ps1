BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 1 PROTECT USER ACCOUNTS AND IDENTITIES\Audit\Check-UserAccountGCEventLogging.psm1'
    Import-Module $modulePath -Force

    function get-AADDiagnosticSettings { return @() }
    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'Get-ResourceIdInfo' {
    It 'Should parse a LAW resource ID correctly' {
        $id = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/TestRG/providers/Microsoft.OperationalInsights/workspaces/TestLAW'
        $result = Get-ResourceIdInfo -Id $id

        $result.SubscriptionId | Should -Be '00000000-0000-0000-0000-000000000000'
        $result.ResourceGroupName | Should -Be 'TestRG'
        $result.Name | Should -Be 'TestLAW'
    }
}

Describe 'Test-SentinelTables' {
    Context 'When Sentinel tables exist' {
        It 'Should return HasAny = true' {
            $mockWorkspace = [PSCustomObject]@{ CustomerId = 'test-customer-id' }

            Mock Invoke-AzOperationalInsightsQuery -ModuleName 'Check-UserAccountGCEventLogging'  { return @{} }

            $result = Test-SentinelTables -Workspace $mockWorkspace

            $result.HasAny | Should -Be $true
        }
    }

    Context 'When no Sentinel tables exist' {
        It 'Should return HasAny = false' {
            $mockWorkspace = [PSCustomObject]@{ CustomerId = 'test-customer-id' }

            Mock Invoke-AzOperationalInsightsQuery -ModuleName 'Check-UserAccountGCEventLogging'  { throw 'Table does not exist' }

            $result = Test-SentinelTables -Workspace $mockWorkspace

            $result.HasAny | Should -Be $false
        }
    }
}

Describe 'Check-UserAccountGCEventLogging' {
    BeforeEach {
        $script:commonParams = @{
            LAWResourceId        = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/TestRG/providers/Microsoft.OperationalInsights/workspaces/TestLAW'
            RequiredRetentionDays = 90
            ControlName          = 'GUARDRAIL 1'
            ItemName             = 'GC Event Logging'
            itsgcode             = 'AU-2'
            msgTable             = @{
                retentionNotMet              = 'Retention not met for {0}.'
                logsNotCollected             = 'Required logs not collected.'
                lockLevelApproved            = '{0} has approved lock level: {1}.'
                lockLevelNotApproved         = '{0} has non-approved lock level: {1}.'
                tagFound                     = 'Sentinel tag found for {0}.'
                sentinelTablesFound          = 'Sentinel tables found for {0}.'
                noLockNoTagNoTables          = 'No lock, no tag, no Sentinel tables for {0}.'
                nonCompliantLaw              = 'LAW {0} not found.'
                gcEventLoggingCompliantComment = 'GC event logging is compliant.'
            }
            ReportTime           = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        }
    }

    Context 'When LAW meets all requirements' {
        It 'Should return compliant' {
            Mock Select-AzSubscription -ModuleName 'Check-UserAccountGCEventLogging'  {}
            Mock Get-AzOperationalInsightsWorkspace -ModuleName 'Check-UserAccountGCEventLogging'  {
                [PSCustomObject]@{
                    RetentionInDays = 90
                    CustomerId      = 'cust-id'
                    Tags            = @{ sentinel = 'true' }
                }
            }
            Mock get-AADDiagnosticSettings -ModuleName 'Check-UserAccountGCEventLogging'  {
                @([PSCustomObject]@{
                    properties = [PSCustomObject]@{
                        workspaceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/TestRG/providers/Microsoft.OperationalInsights/workspaces/TestLAW'
                        logs = @(
                            [PSCustomObject]@{ enabled = $true; category = 'AuditLogs' },
                            [PSCustomObject]@{ enabled = $true; category = 'SignInLogs' },
                            [PSCustomObject]@{ enabled = $true; category = 'ManagedIdentitySignInLogs' },
                            [PSCustomObject]@{ enabled = $true; category = 'RiskyUsers' },
                            [PSCustomObject]@{ enabled = $true; category = 'MicrosoftGraphActivityLogs' }
                        )
                    }
                })
            }
            Mock Get-AzResourceLock -ModuleName 'Check-UserAccountGCEventLogging'  {
                [PSCustomObject]@{ Properties = [PSCustomObject]@{ level = 'CanNotDelete' } }
            }

            $result = Check-UserAccountGCEventLogging @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
            $result.ComplianceResults.Comments | Should -Be 'GC event logging is compliant.'
        }
    }

    Context 'When retention is below required days' {
        It 'Should return non-compliant' {
            Mock Select-AzSubscription -ModuleName 'Check-UserAccountGCEventLogging'  {}
            Mock Get-AzOperationalInsightsWorkspace -ModuleName 'Check-UserAccountGCEventLogging'  {
                [PSCustomObject]@{
                    RetentionInDays = 30
                    CustomerId      = 'cust-id'
                    Tags            = @{ sentinel = 'true' }
                }
            }
            Mock get-AADDiagnosticSettings -ModuleName 'Check-UserAccountGCEventLogging'  { @() }
            Mock Get-AzResourceLock -ModuleName 'Check-UserAccountGCEventLogging'  {
                [PSCustomObject]@{ Properties = [PSCustomObject]@{ level = 'CanNotDelete' } }
            }

            $result = Check-UserAccountGCEventLogging @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
        }
    }

    Context 'When LAW is not found' {
        It 'Should return non-compliant with error' {
            Mock Select-AzSubscription -ModuleName 'Check-UserAccountGCEventLogging'  {}
            Mock Get-AzOperationalInsightsWorkspace -ModuleName 'Check-UserAccountGCEventLogging'  { throw 'ResourceNotFound: LAW not found' }

            $result = Check-UserAccountGCEventLogging @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
            $result.Errors.Count | Should -BeGreaterThan 0
        }
    }

    Context 'When subscription selection fails' {
        It 'Should throw an error' {
            Mock Select-AzSubscription -ModuleName 'Check-UserAccountGCEventLogging'  { throw 'Subscription not found' }

            { Check-UserAccountGCEventLogging @commonParams } | Should -Throw
        }
    }
}
