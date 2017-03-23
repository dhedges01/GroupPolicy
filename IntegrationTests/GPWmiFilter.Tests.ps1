[CmdletBinding()]
Param()

Set-Location $env:SystemDrive | Out-Null

Try{
    Import-Module -Name ActiveDirectory -ErrorAction Stop | Out-Null
    Import-Module GroupPolicy -ErrorAction Stop | Out-Null
    Import-Module GPWmiFilter.psm1 -ErrorAction Stop | Out-Null  #https://gallery.technet.microsoft.com/scriptcenter/Group-Policy-WMI-filter-38a188f3
}
Catch{
    Write-Error $_.Exception
    Exit
}

# Begin Testing

Get-GPWmiFilter -All | ForEach-Object{
    $filter = $_
    $namespace = $filter.Content.Split(';')[5]
    $wmiQuery = $filter.Content.Split(';')[6]

    Describe "GPO WMI Filter Empty Check ($($filter.Name)) ($wmiQuery)" {
        It "WMI Namespace Empty Check" {
            $namespace | Should Not BeNullOrEmpty
        }

        It "WMI Query Empty Check" {
            $wmiQuery | Should Not BeNullOrEmpty
        }
    }

    Describe "GPO WMI Filter Check ($($filter.Name)) ($wmiQuery)"{
        It "Build Number Validation - Windows 7 System"{
            Mock -CommandName Get-WmiObject -MockWith {
                [PSCustomObject]@{
                    BuildNumber = [System.String]'7601';
                    Caption = [System.String]'Microsoft Windows 7 Enterprise';
                    OperatingSystemSKU = [uint32]4;
                    OSArchitecture = [System.String]'64-bit';
                    OSProductSuite = [uint32]256;
                    ProductType = [uint32]1;
                    SuiteMask = [uint32]272;
                    SystemDrive = [System.String]'C:';
                    Version = [System.String]'6.1.7601';
                }
            } -ParameterFilter {$Query -match 'Win32_OperatingSystem'}
            (Get-WmiObject -Namespace $namespace -Query $wmiQuery).BuildNumber | Should BeExactly 7601
        }

        It "Build Number Validation - Windows 8.1 System"{
            Mock -CommandName Get-WmiObject -MockWith {
                [PSCustomObject]@{
                    BuildNumber = [System.String]'9600';
                    Caption = [System.String]'Microsoft Windows 8.1 Enterprise';
                    OperatingSystemSKU = [uint32]4;
                    OSArchitecture = [System.String]'64-bit';
                    OSProductSuite = [uint32]256;
                    ProductType = [uint32]1;
                    SuiteMask = [uint32]272;
                    SystemDrive = [System.String]'C:';
                    Version = [System.String]'6.3.9600';
                }
            } -ParameterFilter {$Query -eq $wmiQuery}
            (Get-WmiObject -Namespace $namespace -Query $wmiQuery).BuildNumber | Should BeExactly 9600
        }

        It "Build Number Validation - Windows 10 (1507) System"{
            Mock -CommandName Get-WmiObject -MockWith {
                [PSCustomObject]@{
                    BuildNumber = [System.String]'10240';
                    Caption = [System.String]'Microsoft Windows 10 Enterprise';
                    OperatingSystemSKU = [uint32]4;
                    OSArchitecture = [System.String]'64-bit';
                    OSProductSuite = [uint32]256;
                    ProductType = [uint32]1;
                    SuiteMask = [uint32]272;
                    SystemDrive = [System.String]'C:';
                    Version = [System.String]'10.0.10240';
                }
            } -ParameterFilter {$Query -eq $wmiQuery}
            (Get-WmiObject -Namespace $namespace -Query $wmiQuery).BuildNumber | Should BeExactly 10240
        }

        It "Build Number Validation - Windows 10 (1511) System"{
            Mock -CommandName Get-WmiObject -MockWith {
                [PSCustomObject]@{
                    BuildNumber = [System.String]'10586';
                    Caption = [System.String]'Microsoft Windows 10 Enterprise';
                    OperatingSystemSKU = [uint32]4;
                    OSArchitecture = [System.String]'64-bit';
                    OSProductSuite = [uint32]256;
                    ProductType = [uint32]1;
                    SuiteMask = [uint32]272;
                    SystemDrive = [System.String]'C:';
                    Version = [System.String]'10.0.10586';
                }
            } -ParameterFilter {$Query -eq $wmiQuery}
            (Get-WmiObject -Namespace $namespace -Query $wmiQuery).BuildNumber | Should BeExactly 10586
        }

        It "Build Number Validation - Windows 10 (1607) System"{
            Mock -CommandName Get-WmiObject -MockWith {
                [PSCustomObject]@{
                    BuildNumber = [System.String]'14393';
                    Caption = [System.String]'Microsoft Windows 10 Enterprise';
                    OperatingSystemSKU = [uint32]4;
                    OSArchitecture = [System.String]'64-bit';
                    OSProductSuite = [uint32]256;
                    ProductType = [uint32]1;
                    SuiteMask = [uint32]272;
                    SystemDrive = [System.String]'C:';
                    Version = [System.String]'10.0.14393';
                }
            } -ParameterFilter {$Query -eq $wmiQuery}
            (Get-WmiObject -Namespace $namespace -Query $wmiQuery).BuildNumber | Should BeExactly 14393
        }

        It "Build Number Validation - Not Null Or Empty"{
            (Get-WmiObject -Namespace $namespace -Query $wmiQuery).BuildNumber | Should Not BeNullOrEmpty
        }
    }
}