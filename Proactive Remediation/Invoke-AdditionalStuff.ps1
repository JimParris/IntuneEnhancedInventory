$UserArray = New-Object System.Collections.ArrayList

# Query all logon events with id 4624 

$MyLogonEvents = Get-EventLog -LogName "Security" -InstanceId 4624 -ErrorAction "SilentlyContinue" 
# Gather logged on users
$UserArray = New-Object System.Collections.ArrayList
$MyLogonEvents = Get-EventLog -LogName "Security" -InstanceId 4624 -ErrorAction "SilentlyContinue" 
foreach ($EventMessage in $MyLogonEvents){
    $AccountName = $EventMessage.ReplacementStrings[5]
    $LogonType = $EventMessage.ReplacementStrings[8]
    $AccountName = $AccountName.ToLower()
    if ( ( $LogonType -in "2","7", "10" ) -and ( $AccountName -notmatch "^(DWM|UMFD)-\d" ) ){
        # Skip duplicate names
        if ( $UserArray.Username -notcontains $AccountName ) {
            # Translate the Logon Type
            if ( $LogonType -eq "2" ) {
                $LogonTypeName = "Local"
            }elseif ($LogonType -eq "7") {
                $LogonTypeName = "Unlock"
            } 
            elseif ( $LogonType -eq "10" ) {
                $LogonTypeName = "Remote"
            }
            # Build an object containing the Username, Logon Type, and Last Logon time
            $LogonEvent = [PSCustomObject]@{
                Username = $AccountName
                LogonType = $LogonTypeName
                LastLogon = $EventMessage.TimeGenerated.ToString("yyyy-MM-dd HH:mm:ss")
            }  
            $null = $UserArray.Add($LogonEvent)
        }

    }
    #write-output $AccountName
    #Write-Output $LogonType
}

# Gather Defender Status 
$DefenderServiceStatus = (Get-Service WinDefend -ErrorAction SilentlyContinue).Status
$DefenderStatus = Get-MpComputerStatus #| Select-Object AMEngineVersion, AMProductVersion. AMRunningMode, AMServiceVersion, AntispywareEnabled, AntispywareSignatureAge, AntivirusSignatureLastUpdated, ComputerID, ComputerState, DeviceControlDefaultEnforcement, DeviceControlPoliciesLastUpdated, NISSignatureAge, OnAccessProtectionEnabled, QuickScanAge, QuickScanEndTime, QuickScanEndTime, QuickScanStartTime, RealTimeScanDirection, TamperProtectionSource
$DefenderPreference = Get-MpPreference

$DefenderInventoryArray = New-Object System.Object
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "AMEngineVersion" -Value "$($DefenderStatus.AMEngineVersion)" -Force   
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "AMProductVersion" -Value "$($DefenderStatus.AMProductVersion)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "AMRunningMode" -Value "$($DefenderStatus.AMRunningMode)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "AMServiceVersion" -Value "$($DefenderStatus.AMServiceVersion)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "AntispywareEnabled" -Value "$($DefenderStatus.AntispywareEnabled)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "AntispywareSignatureAge" -Value "$($DefenderStatus.AntispywareSignatureAge)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "AntivirusSignatureLastUpdated" -Value "$($DefenderStatus.AntivirusSignatureLastUpdated)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "ComputerID" -Value "$($DefenderStatus.ComputerID)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "ComputerState" -Value "$($DefenderStatus.ComputerState)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "DeviceControlDefaultEnforcement" -Value "$($DefenderStatus.DeviceControlDefaultEnforcement)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "DeviceControlPoliciesLastUpdated" -Value "$($DefenderStatus.DeviceControlPoliciesLastUpdated)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "NISSignatureAge" -Value "$($DefenderStatus.NISSignatureAge)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "NISSignatureLastUpdated" -Value "$($DefenderStatus.NISSignatureLastUpdated)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "NISSignatureVersion" -Value "$($DefenderStatus.NISSignatureVersion)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "OnAccessProtectionEnabled" -Value "$($DefenderStatus.OnAccessProtectionEnabled)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "QuickScanAge" -Value "$($DefenderStatus.QuickScanAge)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "QuickScanEndTime" -Value "$($DefenderStatus.QuickScanEndTime)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "QuickScanStartTime" -Value "$($DefenderStatus.QuickScanStartTime)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "RealTimeScanDirection" -Value "$($DefenderStatus.RealTimeScanDirection)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "TamperProtectionSource" -Value "$($DefenderStatus.TamperProtectionSource)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "CloudBlockLevel" -Value "$($DefenderPreference.CloudBlockLevel)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "DefinitionUpdatesChannel" -Value "$($DefenderPreference.DefinitionUpdatesChannel)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "DisableArchiveScanning" -Value "$($DefenderPreference.DisableArchiveScanning)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "DisableAutoExclusions" -Value "$($DefenderPreference.DisableAutoExclusions)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "DisableBehaviorMonitoring" -Value "$($DefenderPreference.DisableBehaviorMonitoring)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "DisableBlockAtFirstSeen" -Value "$($DefenderPreference.DisableBlockAtFirstSeen)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "DisableCatchupFullScan" -Value "$($DefenderPreference.DisableCatchupFullScan)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "DisableCatchupQuickScan" -Value "$($DefenderPreference.DisableCatchupQuickScan)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "DisableCpuThrottleOnIdleScans" -Value "$($DefenderPreference.DisableCpuThrottleOnIdleScans)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "DisableRealtimeMonitoring" -Value "$($DefenderPreference.DisableRealtimeMonitoring)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "EnableDnsSinkhole" -Value "$($DefenderPreference.EnableDnsSinkhole)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "EnableFileHashComputation" -Value "$($DefenderPreference.EnableFileHashComputation)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "EnableFullScanOnBatteryPower" -Value "$($DefenderPreference.EnableFullScanOnBatteryPower)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "EnableLowCpuPriority" -Value "$($DefenderPreference.EnableLowCpuPriority)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "EnableNetworkProtection" -Value "$($DefenderPreference.EnableNetworkProtection)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "HighThreatDefaultAction" -Value "$($DefenderPreference.HighThreatDefaultAction)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "LowThreatDefaultAction" -Value "$($DefenderPreference.LowThreatDefaultAction)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "MAPSReporting" -Value "$($DefenderPreference.MAPSReporting)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "MeteredConnectionUpdates" -Value "$($DefenderPreference.MeteredConnectionUpdates)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "ModerateThreatDefaultAction" -Value "$($DefenderPreference.ModerateThreatDefaultAction)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "PUAProtection" -Value "$($DefenderPreference.PUAProtection)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "LowThreatDefaultAction" -Value "$($DefenderPreference.LowThreatDefaultAction)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "LowThreatDefaultAction" -Value "$($DefenderPreference.LowThreatDefaultAction)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "LowThreatDefaultAction" -Value "$($DefenderPreference.LowThreatDefaultAction)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "LowThreatDefaultAction" -Value "$($DefenderPreference.LowThreatDefaultAction)" -Force
# Additonal Info
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "DefenderServiceStatus" -Value "$($DefenderServiceStatus)" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "AzureADDeviceID" -Value "$AzureADDeviceID" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force
$DefenderInventoryArray | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force

$DefenderInventoryArray 

if ($collectAdminInventory) {
    $adminLog = "AdminInventory"

    $localAdministrators = @()
    $administratorsGroup = ([ADSI]"WinNT://$env:COMPUTERNAME").psbase.children.find("Administrators")
    $administratorsGroupMembers= $administratorsGroup.psbase.invoke("Members")
    foreach ($administrator in $administratorsGroupMembers) { 
        $localAdministrators += $administrator.GetType().InvokeMember('Name','GetProperty',$null,$administrator,$null) 
    }

    $adminArray = @()
    foreach ($localAdministrator in $localAdministrators) {
        $tempAdminArray = New-Object System.Object
        $tempAdminArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
        $tempAdminArray | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force   
        $tempAdminArray | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force 
        $tempAdminArray | Add-Member -MemberType NoteProperty -Name "LocalAdministrator" -Value "$localAdministrator" -Force
        $adminArray += $tempAdminArray
    }  

    #$adminjson = $adminArray | ConvertTo-Json
    #$responseAdminInventory = Send-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($adminjson)) -logType $adminLog
}


#Memory type. It’s indicated in CIM values. A value of 20 means DDR, 21 is DDR2, 22 is DDR2 FB-DIMM, 24 is DDR3, 26 is DDR4.
$PhysicalMemory = Get-CimInstance -ClassName Win32_PhysicalMemory # | Format-Table Manufacturer,Banklabel,Configuredclockspeed,Devicelocator,Capacity, PartNumber, Serialnumber, SMBIOSMemoryType

$MemoryArray = New-Object -TypeName System.Collections.ArrayList
foreach ($Memory in $PhysicalMemory){
        Write-Output $PhysicalMemory.SMBIOSMemoryType
        $MemoryType = $Memory.SMBIOSMemoryType        
        switch ($MemoryType) {
            20 {$PhysicalMemoryType = "DDR"}
            21 {$PhysicalMemoryType = "DDR2"}
            22 {$PhysicalMemoryType = "DDR2 FB-DIMM"}
            24 {$PhysicalMemoryType = "DDR3"}
            26 {$PhysicalMemoryType = "DDR4"}
            default {$PhysicalMemoryType = "Other"}
        }
        $Capacity = [math]::round($Memory.Capacity/1GB, 2)
        $tempmemory = New-Object -TypeName PSObject
        $tempmemory | Add-Member -MemberType NoteProperty -Name "Manufacturer" -Value "$($Memory.Manufacturer)" -Force
        $tempmemory | Add-Member -MemberType NoteProperty -Name "PhysicalMemoryType" -Value "$($PhysicalMemoryType)" -Force
        $tempmemory | Add-Member -MemberType NoteProperty -Name "SMBIOSMemoryType" -Value "$($Memory.SMBIOSMemoryType)" -Force
        $tempmemory | Add-Member -MemberType NoteProperty -Name "Banklabel" -Value "$($Memory.Banklabel)" -Force
        $tempmemory | Add-Member -MemberType NoteProperty -Name "Configuredclockspeed" -Value "$($Memory.Configuredclockspeed)" -Force
        $tempmemory | Add-Member -MemberType NoteProperty -Name "Devicelocator" -Value "$($Memory.Devicelocator)" -Force
        $tempmemory | Add-Member -MemberType NoteProperty -Name "CapacityGB" -Value "$($Capacity)" -Force
        $tempmemory | Add-Member -MemberType NoteProperty -Name "PartNumber" -Value "$($Memory.PartNumber)" -Force
        $tempmemory | Add-Member -MemberType NoteProperty -Name "Serialnumber" -Value "$($Memory.Serialnumber)" -Force
        $MemoryArray.Add($tempmemory) | Out-Null
    }

    


