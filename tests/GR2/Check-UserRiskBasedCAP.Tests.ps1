BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 2 MANAGE ACCESS\Audit\Check-UserRiskBasedCAP.psm1'
    Import-Module $modulePath -Force

    function Invoke-GraphQueryEX { param($urlPath) }
    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'Test-CommonFilters' {
    Context 'When a valid risk-based CAP policy exists' {
        It 'Should return the matching policy' {
            $policy = @([PSCustomObject]@{
                state = 'enabled'
                conditions = [PSCustomObject]@{
                    users = [PSCustomObject]@{
                        includeUsers = @('All')
                        excludeUsers = @('bg1-id', 'bg2-id')
                        includedGroups = $null
                        includeRoles = $null
                        excludeRoles = $null
                        includeGuestsOrExternalUsers = $null
                        excludeGuestsOrExternalUsers = $null
                    }
                    applications = [PSCustomObject]@{
                        includeApplications = @('All')
                        excludeApplications = $null
                    }
                    clientAppTypes   = @('all')
                    userRiskLevels   = @('high')
                    signInRiskLevels = $null
                    platforms        = $null
                    locations        = $null
                    devices          = $null
                    clientApplications = $null
                }
                grantControls = [PSCustomObject]@{
                    builtInControls = @('mfa', 'passwordChange')
                }
                sessionControls = [PSCustomObject]@{
                    signInFrequency = [PSCustomObject]@{
                        frequencyInterval    = 'everyTime'
                        authenticationType   = 'primaryAndSecondaryAuthentication'
                        isEnabled            = $true
                    }
                }
            })

            $result = Test-CommonFilters -policy $policy -FirstBreakGlassID 'bg1-id' -SecondBreakGlassID 'bg2-id'

            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context 'When no matching policy exists' {
        It 'Should return null or empty' {
            $policy = @([PSCustomObject]@{
                state = 'disabled'
                conditions = [PSCustomObject]@{
                    users = [PSCustomObject]@{
                        includeUsers = @('All')
                        excludeUsers = @()
                    }
                    applications = [PSCustomObject]@{ includeApplications = @('All') }
                    clientAppTypes = @('all')
                    userRiskLevels = @()
                    signInRiskLevels = $null
                    platforms = $null
                    locations = $null
                    devices = $null
                    clientApplications = $null
                }
                grantControls = [PSCustomObject]@{ builtInControls = @('mfa') }
                sessionControls = [PSCustomObject]@{
                    signInFrequency = [PSCustomObject]@{
                        frequencyInterval = 'everyTime'
                        authenticationType = 'primaryAndSecondaryAuthentication'
                        isEnabled = $true
                    }
                }
            })

            $result = Test-CommonFilters -policy $policy -FirstBreakGlassID 'bg1-id' -SecondBreakGlassID 'bg2-id'

            $result | Should -BeNullOrEmpty
        }
    }
}

Describe 'Get-UserRiskBasedCAP' {
    BeforeEach {
        $script:commonParams = @{
            ControlName         = 'GUARDRAIL 2'
            ItemName            = 'User Risk Based CAP'
            itsgcode            = 'AC-7'
            msgTable            = @{
                isCompliant    = 'Compliant'
                isNotCompliant = 'Not Compliant'
                riskBasedCAPCompliant = 'Risk-based CAP is compliant.'
                riskBasedCAPNonCompliant = 'Risk-based CAP is not compliant.'
            }
            ReportTime          = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
            FirstBreakGlassUPN  = 'bg1@test.com'
            SecondBreakGlassUPN = 'bg2@test.com'
        }
    }

    Context 'When Graph API call fails for CAP policies' {
        It 'Should add error to ErrorList' {
            Mock Invoke-GraphQueryEX -ModuleName 'Check-UserRiskBasedCAP'  -ParameterFilter { $urlPath -like '*/conditionalAccess/*' } { throw 'API Error' }
            Mock Invoke-GraphQueryEX -ModuleName 'Check-UserRiskBasedCAP'  -ParameterFilter { $urlPath -eq '/users' } {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = @() } }
            }
            Mock Invoke-GraphQueryEX -ModuleName 'Check-UserRiskBasedCAP'  -ParameterFilter { $urlPath -eq '/groups' } {
                [PSCustomObject]@{ Content = [PSCustomObject]@{ value = @() } }
            }

            $result = Get-UserRiskBasedCAP @commonParams

            $result.Errors.Count | Should -BeGreaterThan 0
        }
    }
}
