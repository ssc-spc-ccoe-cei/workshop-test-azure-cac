BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\..\src\GUARDRAIL 5 DATA LOCATION\Audit\Check-AllowedLocationPolicy.psm1'
    Import-Module $modulePath -Force

    function Add-ProfileInformation { param($Result, $CloudUsageProfiles, $ModuleProfiles, $SubscriptionId, $ErrorList) return $Result }
    function Get-EvaluationProfile { param($CloudUsageProfiles, $ModuleProfiles, $SubscriptionId) 
        return [PSCustomObject]@{ ShouldEvaluate = $true; ShouldAvailable = $true }
    }
}

Describe 'Get-PolicyComplianceDataOptimized' {
    Context 'When ARG query returns subscription compliance data' {
        It 'Should return a hashtable with subscription data' {
            Mock Search-AzGraph -ModuleName 'Check-AllowedLocationPolicy'  {
                $result = @([PSCustomObject]@{
                    subscriptionId              = 'sub-1'
                    InitiativeTotalCount        = 10
                    InitiativeCompliantCount    = 8
                    InitiativeNonCompliantCount = 2
                    PolicyTotalCount            = 5
                    PolicyCompliantCount        = 5
                    PolicyNonCompliantCount      = 0
                })
                $result | Add-Member -MemberType NoteProperty -Name SkipToken -Value $null
                $result
            }

            $result = Get-PolicyComplianceDataOptimized -PolicyID 'test-policy-id' -InitiativeID 'test-initiative-id'

            $result | Should -Not -BeNullOrEmpty
            $result.ContainsKey('sub-1') | Should -Be $true
            $result['sub-1'].InitiativeTotalCount | Should -Be 10
            $result['sub-1'].PolicyCompliantCount | Should -Be 5
        }
    }

    Context 'When ARG query returns no results' {
        It 'Should return empty hashtable' {
            Mock Search-AzGraph -ModuleName 'Check-AllowedLocationPolicy'  {
                $result = @()
                $result | Add-Member -MemberType NoteProperty -Name SkipToken -Value $null -Force
                $result
            }

            $result = Get-PolicyComplianceDataOptimized -PolicyID 'test-policy-id' -InitiativeID 'N/A'

            $result.Count | Should -Be 0
        }
    }

    Context 'When ARG query fails' {
        It 'Should return empty hashtable' {
            Mock Search-AzGraph -ModuleName 'Check-AllowedLocationPolicy'  { throw 'ARG query failed' }

            $result = Get-PolicyComplianceDataOptimized -PolicyID 'test-policy-id' -InitiativeID 'test-initiative'

            $result.Count | Should -Be 0
        }
    }
}

Describe 'Check-PolicyStatus' {
    BeforeEach {
        $script:commonParams = @{
            objType      = 'subscription'
            PolicyID     = '/providers/Microsoft.Authorization/policyDefinitions/test-policy'
            InitiativeID = 'N/A'
            ControlName  = 'GUARDRAIL 5'
            ItemName     = 'Allowed Location Policy'
            itsgcode     = 'SA-8'
            msgTable     = @{
                isCompliant             = 'Compliant'
                isNotCompliant          = 'Not Compliant'
                policyNotAssigned       = 'Policy not assigned to {0}.'
                notAllowedLocation      = 'Location not allowed.'
                allCompliantResources   = 'All resources are compliant.'
                allNonCompliantResources = 'All resources are non-compliant.'
                hasNonComplianceResource = '{0} of {1} resources non-compliant.'
                noResource              = 'No resources found.'
            }
            ReportTime   = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        }
    }

    Context 'When policy is not assigned to subscription' {
        It 'Should return non-compliant' {
            $subs = @([PSCustomObject]@{ Id = 'sub-1'; Name = 'TestSub'; DisplayName = 'TestSub' })

            Mock Get-AzPolicyAssignment -ModuleName 'Check-AllowedLocationPolicy'  { return $null }

            $result = Check-PolicyStatus @commonParams -objList $subs

            $result | Should -Not -BeNullOrEmpty
            $result[0].ComplianceStatus | Should -Be $false
        }
    }

    Context 'When policy is assigned and all resources are compliant (cached)' {
        It 'Should return compliant' {
            $subs = @([PSCustomObject]@{ Id = 'sub-1'; Name = 'TestSub'; DisplayName = 'TestSub' })
            $cache = @{
                'sub-1' = @{
                    InitiativeTotalCount        = 0
                    InitiativeCompliantCount    = 0
                    InitiativeNonCompliantCount = 0
                    PolicyTotalCount            = 10
                    PolicyCompliantCount        = 10
                    PolicyNonCompliantCount      = 0
                }
            }

            Mock Get-AzPolicyAssignment -ModuleName 'Check-AllowedLocationPolicy'  -ParameterFilter { $PolicyDefinitionId -like '*test-policy*' } {
                [PSCustomObject]@{ Properties = [PSCustomObject]@{ Parameters = @{}; NotScopesScope = $null } }
            }
            Mock Get-AzPolicyAssignment -ModuleName 'Check-AllowedLocationPolicy'  -ParameterFilter { $PolicyDefinitionId -eq 'N/A' } {
                return $null
            }

            $result = Check-PolicyStatus @commonParams -objList $subs -ComplianceCache $cache

            $result | Should -Not -BeNullOrEmpty
            $result[0].ComplianceStatus | Should -Be $true
        }
    }

    Context 'When allowed locations contain non-allowed location' {
        It 'Should return non-compliant' {
            $subs = @([PSCustomObject]@{ Id = 'sub-1'; Name = 'TestSub'; DisplayName = 'TestSub' })

            Mock Get-AzPolicyAssignment -ModuleName 'Check-AllowedLocationPolicy'  -ParameterFilter { $PolicyDefinitionId -like '*test-policy*' } {
                [PSCustomObject]@{
                    Properties = [PSCustomObject]@{
                        Parameters = [PSCustomObject]@{
                            listOfAllowedLocations = [PSCustomObject]@{ value = @('canadacentral', 'eastus') }
                        }
                        NotScopesScope = $null
                    }
                }
            }
            Mock Get-AzPolicyAssignment -ModuleName 'Check-AllowedLocationPolicy'  -ParameterFilter { $PolicyDefinitionId -eq 'N/A' } {
                return $null
            }

            $result = Check-PolicyStatus @commonParams -objList $subs -AllowedLocations @('canadacentral', 'canadaeast')

            $result | Should -Not -BeNullOrEmpty
            $result[0].ComplianceStatus | Should -Be $false
        }
    }
}
