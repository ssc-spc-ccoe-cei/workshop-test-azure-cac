BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 2 MANAGE ACCESS\Audit\Check-OnlineAttackCountermeasures.psm1'
    Import-Module $modulePath -Force

    function Invoke-GraphQueryEX { param($urlPath) }
    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
}

Describe 'Check-OnlineAttackCountermeasures' {
    BeforeEach {
        $script:commonParams = @{
            ControlName = 'GUARDRAIL 2'
            ItemName    = 'Online Attack Countermeasures'
            itsgcode    = 'AC-7'
            msgTable    = @{
                onlineAttackIsCompliant       = 'Online attack countermeasures are compliant.'
                onlineAttackNonCompliantC1     = 'Lockout threshold exceeds 10.'
                onlineAttackNonCompliantC2     = 'Banned password list is non-compliant.'
                onlineAttackNonCompliantC1C2   = 'Both lockout threshold and banned password list are non-compliant.'
            }
            ReportTime  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        }
    }

    Context 'When lockout threshold is within limit and banned passwords are correct' {
        It 'Should return compliant' {
            Mock Invoke-GraphQueryEX -ModuleName 'Check-OnlineAttackCountermeasures'  {
                [PSCustomObject]@{
                    Content = [PSCustomObject]@{
                        value = @([PSCustomObject]@{
                            displayName = 'Password Rule Settings'
                            values = @(
                                [PSCustomObject]@{ name = 'LockoutThreshold'; value = '5' },
                                [PSCustomObject]@{ name = 'BannedPasswordList'; value = "password`tPassword!`tSummer2018`textra1" }
                            )
                        })
                    }
                }
            }

            $result = Check-OnlineAttackCountermeasures @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $true
            $result.ComplianceResults.Comments | Should -Be 'Online attack countermeasures are compliant.'
        }
    }

    Context 'When lockout threshold exceeds 10' {
        It 'Should return non-compliant for C1' {
            Mock Invoke-GraphQueryEX -ModuleName 'Check-OnlineAttackCountermeasures'  {
                [PSCustomObject]@{
                    Content = [PSCustomObject]@{
                        value = @([PSCustomObject]@{
                            displayName = 'Password Rule Settings'
                            values = @(
                                [PSCustomObject]@{ name = 'LockoutThreshold'; value = '15' },
                                [PSCustomObject]@{ name = 'BannedPasswordList'; value = "password`tPassword!`tSummer2018`textra1" }
                            )
                        })
                    }
                }
            }

            $result = Check-OnlineAttackCountermeasures @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
            $result.ComplianceResults.Comments | Should -Match 'Lockout threshold'
        }
    }

    Context 'When banned password list is missing required passwords' {
        It 'Should return non-compliant for C2' {
            Mock Invoke-GraphQueryEX -ModuleName 'Check-OnlineAttackCountermeasures'  {
                [PSCustomObject]@{
                    Content = [PSCustomObject]@{
                        value = @([PSCustomObject]@{
                            displayName = 'Password Rule Settings'
                            values = @(
                                [PSCustomObject]@{ name = 'LockoutThreshold'; value = '5' },
                                [PSCustomObject]@{ name = 'BannedPasswordList'; value = "password`tSummer2018" }
                            )
                        })
                    }
                }
            }

            $result = Check-OnlineAttackCountermeasures @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
            $result.ComplianceResults.Comments | Should -Match 'Banned password'
        }
    }

    Context 'When banned password list has only the 3 required passwords and nothing else' {
        It 'Should return non-compliant' {
            Mock Invoke-GraphQueryEX -ModuleName 'Check-OnlineAttackCountermeasures'  {
                [PSCustomObject]@{
                    Content = [PSCustomObject]@{
                        value = @([PSCustomObject]@{
                            displayName = 'Password Rule Settings'
                            values = @(
                                [PSCustomObject]@{ name = 'LockoutThreshold'; value = '5' },
                                [PSCustomObject]@{ name = 'BannedPasswordList'; value = "password`tPassword!`tSummer2018" }
                            )
                        })
                    }
                }
            }

            $result = Check-OnlineAttackCountermeasures @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
        }
    }

    Context 'When both checks fail' {
        It 'Should return non-compliant with combined message' {
            Mock Invoke-GraphQueryEX -ModuleName 'Check-OnlineAttackCountermeasures'  {
                [PSCustomObject]@{
                    Content = [PSCustomObject]@{
                        value = @([PSCustomObject]@{
                            displayName = 'Password Rule Settings'
                            values = @(
                                [PSCustomObject]@{ name = 'LockoutThreshold'; value = '20' },
                                [PSCustomObject]@{ name = 'BannedPasswordList'; value = '' }
                            )
                        })
                    }
                }
            }

            $result = Check-OnlineAttackCountermeasures @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
            $result.ComplianceResults.Comments | Should -Be 'Both lockout threshold and banned password list are non-compliant.'
        }
    }

    Context 'When Graph API fails' {
        It 'Should return non-compliant with error' {
            Mock Invoke-GraphQueryEX -ModuleName 'Check-OnlineAttackCountermeasures'  { throw 'API Error' }

            $result = Check-OnlineAttackCountermeasures @commonParams

            $result.ComplianceResults.ComplianceStatus | Should -Be $false
            $result.Errors.Count | Should -BeGreaterThan 0
        }
    }
}
