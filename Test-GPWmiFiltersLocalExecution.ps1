# Tests all Active Directory WMI Filters to ensure they contain valid queries

Import-Module -Name ActiveDirectory
Import-Module GroupPolicy
Import-Module "$env:USERPROFILE\Downloads\GPWmiFilter.psm1"

Set-Location $env:SystemDrive

Get-GPWmiFilter -All | ForEach-Object{
    $filter = $_
    $namespace = $filter.Content.Split(';')[5]
    $query = $filter.Content.Split(';')[6]

    Try{
        Write-Host "Testing WMI Filter ($($filter.Name))"
        Get-WmiObject -Namespace $namespace -query $query -ErrorAction Stop | Out-Null
        Write-Host -ForegroundColor Green "Success!"
    }
    Catch [System.Management.ManagementException]{
        $e = $_
        if($e.Exception -match 'Invalid namespace'){
            Write-Host -ForegroundColor Yellow "Invalid Namespace"
            Write-Host -ForegroundColor Yellow "Namespace: $namespace"
            Write-Host -ForegroundColor Yellow "Query: $query"
        }
        elseif($e.Exception -match 'Invalid class'){
            Write-Host -ForegroundColor Red "Invalid Class"
            Write-Host -ForegroundColor Red "Namespace: $namespace"
            Write-Host -ForegroundColor Red "Query: $query"
        }
        else{
            Write-Error $_.Exception
        }
    }
}
