BeforeAll {
    $setupPath = Join-Path $PSScriptRoot '..\..\setup'
}

Describe 'Bicep File Validation' {
    Context 'All Bicep files should compile without errors' {
        $bicepFiles = @(
            'IaC\guardrails.bicep',
            'IaC\testAlert.bicep',
            'IaC\modules\alert.bicep',
            'IaC\modules\keyvault.bicep',
            'IaC\modules\storage.bicep',
            'IaC\modules\automationaccount.bicep',
            'IaC\modules\loganalyticsworkspace.bicep',
            'lighthouse\lighthouse_rg.bicep',
            'lighthouse\lighthouse_registerRPRole.bicep',
            'lighthouse\lighthouse_assignRPRole.bicep',
            'lighthouse\lighthouseDfCPolicy.bicep',
            'lighthouse\lighthouseDfCPolicyRoleAssignment.bicep',
            'lighthouse\nested_lighthouse_rgAssignment.bicep'
        )

        foreach ($file in $bicepFiles) {
            It "Should compile <file> without errors" -TestCases @(@{ file = $file }) {
                $fullPath = Join-Path $setupPath $file
                if (Test-Path $fullPath) {
                    $outFile = [System.IO.Path]::GetTempFileName() + '.json'
                    try {
                        $result = az bicep build --file $fullPath --outfile $outFile 2>&1
                        $LASTEXITCODE | Should -Be 0 -Because "Bicep file '$file' should compile without errors"
                    }
                    finally {
                        if (Test-Path $outFile) { Remove-Item $outFile -Force }
                    }
                }
                else {
                    Set-ItResult -Skipped -Because "File '$file' not found"
                }
            }
        }
    }
}

Describe 'Storage Account Bicep Module' {
    BeforeAll {
        $storageBicep = Join-Path $setupPath 'IaC\modules\storage.bicep'
        $script:storageContent = Get-Content $storageBicep -Raw
    }

    It 'Should require HTTPS traffic only' {
        $storageContent | Should -Match 'supportsHttpsTrafficOnly:\s*true'
    }

    It 'Should set minimum TLS version to 1.2' {
        $storageContent | Should -Match "minimumTlsVersion:\s*'TLS1_2'"
    }

    It 'Should disable public blob access' {
        $storageContent | Should -Match 'allowBlobPublicAccess:\s*false'
    }

    It 'Should use Standard_LRS SKU' {
        $storageContent | Should -Match "'Standard_LRS'"
    }

    It 'Should create containers with None public access' {
        $storageContent | Should -Match "publicAccess:\s*'None'"
    }

    It 'Should have required parameters' {
        $storageContent | Should -Match 'param storageAccountName string'
        $storageContent | Should -Match 'param location string'
        $storageContent | Should -Match 'param containername string'
    }

    It 'Should create guardrailsstorage and configuration containers' {
        $storageContent | Should -Match 'name: containername'
        $storageContent | Should -Match "name: 'configuration'"
    }
}

Describe 'Key Vault Bicep Module' {
    BeforeAll {
        $kvBicep = Join-Path $setupPath 'IaC\modules\keyvault.bicep'
        $script:kvContent = Get-Content $kvBicep -Raw
    }

    It 'Should enable RBAC authorization' {
        $kvContent | Should -Match 'enableRbacAuthorization:\s*true'
    }

    It 'Should disable deployment features' {
        $kvContent | Should -Match 'enabledForDeployment:\s*false'
        $kvContent | Should -Match 'enabledForDiskEncryption:\s*false'
        $kvContent | Should -Match 'enabledForTemplateDeployment:\s*false'
    }

    It 'Should use standard SKU' {
        $kvContent | Should -Match "name:\s*'standard'"
    }

    It 'Should have secure parameters for break glass accounts' {
        $kvContent | Should -Match '@secure\(\)\s*\n\s*param breakglassAccount1'
        $kvContent | Should -Match '@secure\(\)\s*\n\s*param breakglassAccount2'
    }

    It 'Should create secrets for BGA1, BGA2, and WorkSpaceKey' {
        $kvContent | Should -Match "name: 'BGA1'"
        $kvContent | Should -Match "name: 'BGA2'"
        $kvContent | Should -Match "name: 'WorkSpaceKey'"
    }

    It 'Should assign Key Vault Administrator role for admin user' {
        $kvContent | Should -Match '00482a5a-887f-4fb3-b363-3b7fe8e74483'
    }

    It 'Should assign Key Vault Secrets User role for automation account' {
        $kvContent | Should -Match '4633458b-17de-408a-b874-0445c86b69e6'
    }

    It 'Should conditionally deploy based on deployKV parameter' {
        $kvContent | Should -Match 'if \(deployKV\)'
    }
}

Describe 'Alert Bicep Module' {
    BeforeAll {
        $alertBicep = Join-Path $setupPath 'IaC\modules\alert.bicep'
        $script:alertContent = Get-Content $alertBicep -Raw
    }

    It 'Should have required parameters' {
        $alertContent | Should -Match 'param alertRuleName string'
        $alertContent | Should -Match 'param alertRuleDisplayName string'
        $alertContent | Should -Match 'param alertRuleDescription string'
        $alertContent | Should -Match 'param scope string'
        $alertContent | Should -Match 'param alertRuleSeverity int'
        $alertContent | Should -Match 'param query string'
    }

    It 'Should have default values for windowSize and evaluationFrequency' {
        $alertContent | Should -Match "param windowSize string = 'PT15M'"
        $alertContent | Should -Match "param evaluationFrequency string = 'PT15M'"
    }

    It 'Should target Log Analytics workspaces' {
        $alertContent | Should -Match 'Microsoft\.OperationalInsights/workspaces'
    }

    It 'Should use Count time aggregation' {
        $alertContent | Should -Match "timeAggregation:\s*'Count'"
    }

    It 'Should use GreaterThan operator' {
        $alertContent | Should -Match "operator:\s*'GreaterThan'"
    }

    It 'Should enable skip query validation' {
        $alertContent | Should -Match 'skipQueryValidation:\s*true'
    }

    It 'Should enable the alert rule' {
        $alertContent | Should -Match 'enabled:\s*true'
    }
}

Describe 'Main Guardrails Bicep Template' {
    BeforeAll {
        $mainBicep = Join-Path $setupPath 'IaC\guardrails.bicep'
        $script:mainContent = Get-Content $mainBicep -Raw
    }

    It 'Should target resourceGroup scope' {
        $mainContent | Should -Match "targetScope = 'resourceGroup'"
    }

    It 'Should have secure parameters for break glass accounts' {
        $mainContent | Should -Match '@secure\(\)\s*\n\s*param breakglassAccount1'
        $mainContent | Should -Match '@secure\(\)\s*\n\s*param breakglassAccount2'
    }

    It 'Should reference all required modules' {
        $mainContent | Should -Match "module aa 'modules/automationaccount.bicep'"
        $mainContent | Should -Match "module KV 'modules/keyvault.bicep'"
        $mainContent | Should -Match "module LAW 'modules/loganalyticsworkspace.bicep'"
        $mainContent | Should -Match "module storageaccount 'modules/storage.bicep'"
        $mainContent | Should -Match "module alertNewVersion 'modules/alert.bicep'"
    }

    It 'Should have conditional deployment for core resources' {
        $mainContent | Should -Match 'if \(newDeployment \|\| updatePSModules \|\| updateCoreResources\)'
        $mainContent | Should -Match 'if \(newDeployment && deployKV\)'
    }

    It 'Should default location to canadacentral' {
        $mainContent | Should -Match "param location string = 'canadacentral'"
    }

    It 'Should output automation account MSI' {
        $mainContent | Should -Match 'output guardrailsAutomationAccountMSI string'
    }
}

Describe 'Lighthouse Bicep Files' {
    Context 'lighthouse_rg.bicep' {
        BeforeAll {
            $lhRg = Join-Path $setupPath 'lighthouse\lighthouse_rg.bicep'
            if (Test-Path $lhRg) {
                $script:lhRgContent = Get-Content $lhRg -Raw
            }
        }

        It 'Should target subscription scope' {
            if ($lhRgContent) {
                $lhRgContent | Should -Match "targetScope\s*=\s*'subscription'"
            }
            else { Set-ItResult -Skipped -Because 'File not found' }
        }
    }

    Context 'lighthouse_registerRPRole.bicep' {
        BeforeAll {
            $lhRole = Join-Path $setupPath 'lighthouse\lighthouse_registerRPRole.bicep'
            if (Test-Path $lhRole) {
                $script:lhRoleContent = Get-Content $lhRole -Raw
            }
        }

        It 'Should target managementGroup scope' {
            if ($lhRoleContent) {
                $lhRoleContent | Should -Match "targetScope\s*=\s*'managementGroup'"
            }
            else { Set-ItResult -Skipped -Because 'File not found' }
        }

        It 'Should define register action permission' {
            if ($lhRoleContent) {
                $lhRoleContent | Should -Match 'Microsoft\.ManagedServices/register/action'
            }
            else { Set-ItResult -Skipped -Because 'File not found' }
        }
    }

    Context 'lighthouseDfCPolicy.bicep' {
        BeforeAll {
            $lhPolicy = Join-Path $setupPath 'lighthouse\lighthouseDfCPolicy.bicep'
            if (Test-Path $lhPolicy) {
                $script:lhPolicyContent = Get-Content $lhPolicy -Raw
            }
        }

        It 'Should define a deployIfNotExists policy' {
            if ($lhPolicyContent) {
                $lhPolicyContent | Should -Match 'deployIfNotExists|DeployIfNotExists'
            }
            else { Set-ItResult -Skipped -Because 'File not found' }
        }
    }
}

Describe 'Test Alert Bicep Template' {
    BeforeAll {
        $testAlertBicep = Join-Path $setupPath 'IaC\testAlert.bicep'
        $script:testAlertContent = Get-Content $testAlertBicep -Raw
    }

    It 'Should create GR_VersionInfo_CL table' {
        $testAlertContent | Should -Match 'GR_VersionInfo_CL'
    }

    It 'Should define required columns in schema' {
        $testAlertContent | Should -Match 'CurrentVersion_s'
        $testAlertContent | Should -Match 'AvailableVersion_s'
        $testAlertContent | Should -Match 'ReportTime_s'
        $testAlertContent | Should -Match 'UpdateNeeded_b'
    }

    It 'Should set retention to 31 days' {
        $testAlertContent | Should -Match 'retentionInDays:\s*31'
    }

    It 'Should use Analytics plan' {
        $testAlertContent | Should -Match "plan:\s*'Analytics'"
    }

    It 'Should reference alert module' {
        $testAlertContent | Should -Match "module alertNewVersion 'modules/alert.bicep'"
    }
}
