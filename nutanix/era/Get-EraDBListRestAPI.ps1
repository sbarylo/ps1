<#
.SYNOPSIS
    
    Simple script to create a CSV report of databases via Era REST API

.DESCRIPTION

    Scirpt will run against Era instance and execute a few queries against different endpoints to gather the report.
    At least read-only access to Era is required. If UserName and PassWord are not provided as parameters, 
    the script will pop-up interactive "Get-Credentials" window to gather them.
    Script will create "<EraServer>-db_report.csv" file in the location it was called from.

.PARAMETER EraServer

    Era instance IP or FQDN, mandatory

.PARAMETER UserName

    Optional

.PARAMETER PassWord

    Optional

.PARAMETER DebugModeOn

    Optional, will create log files (including PS transcript log) for troubleshooting

.EXAMPLE
    
    Run the script with full list of parameters, Era server passed as IP Address

    Get-EraDBListRestAPI.ps1 -EraServer 10.11.12.13 -UserName admin -PassWord nutanix/4u
    
.EXAMPLE

    Run the script with EraServer parameter only (as FQDN), script will interacively ask for credentials.

    Get-EraDBListRestAPI.ps1 -EraServer pc.nutanix.demo

   
#>

[CmdletBinding()] #use CmdletBinding, because it's cool and allows for initial paramater validation
Param(

   [Parameter(Mandatory=$True,Position=1)]
   [ValidateNotNullOrEmpty()]
   [string]$EraServer,

   [Parameter(Mandatory=$False,Position=2)]
   [string]$UserName,   
   
   [Parameter(Mandatory=$False,Position=3)]
   [string]$PassWord, 

   [Parameter(Mandatory=$False,Position=4)]
   [switch]$DebugModeOn 
)

Begin { #these are two functions I use for logging and debugging, pretty self-explanatory

	Function ExitWithCode {
 

	[CmdletBinding()]
		Param(

			[Parameter(Mandatory=$True,Position=1)]
			[int]$ExitCode=0
      
		)

    $host.SetShouldExit($ExitCode) 
    Exit 
	}

	Function WriteAndLog {

	[CmdletBinding()]
		Param(
			[Parameter(Mandatory=$True,Position=1)]
			[ValidateNotNullOrEmpty()]
			[string]$LogFile,
	
			[Parameter(Mandatory=$True,Position=2)]
			[ValidateNotNullOrEmpty()]
			[string]$line,

			[Parameter(Mandatory=$False,Position=3)]
			[int]$Severity=0,

			[Parameter(Mandatory=$False,Position=4)]
			[string]$type="terse"

   
		)

	$timestamp = (Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] "))
	$ui = (Get-Host).UI.RawUI

	switch ($Severity) {

			{$_ -gt 0} {$ui.ForegroundColor = "red"; $type ="full"; $LogEntry = $timestamp + ":Error: " + $line; break;}
			{$_ -eq 0} {$ui.ForegroundColor = "green"; $LogEntry = $timestamp + ":Info: " + $line; break;}
			{$_ -lt 0} {$ui.ForegroundColor = "yellow"; $LogEntry = $timestamp + ":Warning: " + $line; break;}

	}
	switch ($type) {
   
			"terse"   {Write-Output $LogEntry; break;}
			"full"    {Write-Output $LogEntry; $LogEntry | Out-file $LogFile -Append; break;}
			"logonly" {$LogEntry | Out-file $LogFile -Append; break;}
     
	}

	$ui.ForegroundColor = "white" 

	}
	
	Function NormalizeInGiB {
 

	[CmdletBinding()]
		Param(
			[Parameter(Mandatory=$True,Position=1)]
			[ValidateNotNullOrEmpty()]
			[long]$value,
			[Parameter(Mandatory=$True,Position=2)]
			[ValidateNotNullOrEmpty()]
			[string]$unit
      
		)

    #constans
	[long]$KiB = 1024
	[long]$MiB = 1024 * 1024
	[long]$GiB = 1024 * 1024 * 1024
	
	switch ($unit) {
		
		"B"  {return [math]::Round($value / $GiB,2)}
		"KB" {return [math]::Round($value / $MiB,2)}
		"MB" {return [math]::Round($value / $KiB,2)}
		"GB" {return [math]::Round($value,2)}
		"TB" {return [math]::Round($value * $KiB,2)}
		
	}
	
	}

}




Process {

#constans
$ContentType = 'application/json' #we will be talking JSON!

#variables
[int]$total_errors = 0
[string]$stage = "startup"
[string]$empty = ""

$nxClusters = @{}
$dbServers = @{}
$timeMachines = @{}
$customProperties = ("os_type", "os_version", "os_info", "application_type", "application_version", "SIZE", "SIZE_UNIT")
$restReportArray = @()

$EraBaseURLv09 = "https://" + $EraServer + "/era/v0.9/"


#self-signed certificate exception
try {

	add-type @"
		using System.Net;
		using System.Security.Cryptography.X509Certificates;
		public class TrustAllCertsPolicy : ICertificatePolicy {
			public bool CheckValidationResult(
				ServicePoint srvPoint, X509Certificate certificate,
				WebRequest request, int certificateProblem) {
				return true;
			}
		}
"@
	
	[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	
}
catch { }

if($DebugModeOn) {
	#constans 
    #array with error messages and return codes explained

	#variables
	$ScriptRoot = (Get-Location).Path
	$StartTime = Get-Date -Format "yyyyMMddHHmmssff_"
	$logdir = $ScriptRoot + "\Get-EraDBListRestAPI_Logs\"
	$logfilename = $logdir + $StartTime + "Get-EraDBListRestAPI.log"
	$transcriptfilename = $logdir + $StartTime + "Get-EraDBListRestAPI_Transcript.log"

	#test for log directory, create one if needed
	if ( -not (Test-Path $logdir)) {
		New-Item -type directory -path $logdir | Out-Null
	}

	#start PowerShell transcript
	Start-Transcript -Path $transcriptfilename | Out-Null
	
	$VerbosePreference = "Continue"
}
else{
	$ErrorActionPreference = "SilentlyContinue"
}

$ProgressPreference = "SilentlyContinue"

#validate if $EraServer is responding on TCP/443 (exit if it doesn't)
if (Test-NetConnection -ComputerName $EraServer -Port 443 -InformationLevel Quiet) {

    if (($UserName) -and ($PassWord)) {
        
        $PlainTextCredentials = "$($UserName):$($PassWord)"
        $EncodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($PlainTextCredentials))
        $restHeader = @{ "Authorization" = "Basic $EncodedCredentials" }
    
    }
    else {

        $restCredentials = $host.ui.PromptForCredential("Need credentials!", "Please specify your Era login credentials.", "", "")
	    $restPassword = $((New-Object PSCredential "$($restCredentials.username)",$($restCredentials.Password)).GetNetworkCredential().Password)
	    $restHeader = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($restCredentials.Username)" + ":" + $($restPassword)))}
    }

	#validate if we have any DBs at all
	try {
		$stage = "REST API check"
		$restResponse = Invoke-RestMethod -Method GET -Uri $($EraBaseURLv09 + "databases?detailed=false") -TimeoutSec 60 -Headers $restHeader -ContentType $ContentType
	} catch {
		$stage
		$_.Exception.Message
		$respStream = $_.Exception.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($respStream)
		$respBody = $reader.ReadToEnd() | ConvertFrom-Json
	}
	
	#we've got something
	if (($restResponse.count -gt 0))  { 

		#build dictionary of Nutanix Clusters
		try {
			$stage = "NTNX Clusters"
			$restResponse = Invoke-RestMethod -Method GET -Uri $($EraBaseURLv09 + "clusters?include-management-server-info=true") -TimeoutSec 60 -Headers $restHeader -ContentType $ContentType
		} catch {
			$stage
			$_.Exception.Message
			$respStream = $_.Exception.Response.GetResponseStream()
			$reader = New-Object System.IO.StreamReader($respStream)
			$respBody = $reader.ReadToEnd() | ConvertFrom-Json
		}

		$restResponse | %{ 
						  $ephem =[ordered]@{
							  "name" = $_.name
							  "ip_addr" = $_.ipAddresses[0]
							  "cloud_type" = $_.cloudType
							  "hypervisor_type" = $_.hypervisorType
							  "aos_version" = $_.hypervisorVersion
							  }
						  $nxClusters[$_.id] = $ephem
						  }

		#build dictionary of Time Machines (tm)
		try {
			$stage = "Time Machines"
			#$restResponse = Invoke-RestMethod -Method GET -Uri $($EraBaseURLv09 + "tms?detailed=true&load-database=true&load-clones=true&load-metrics=true&load-associated-clusters=true") -TimeoutSec 60 -Headers $restHeader -ContentType $ContentType
			$restResponse = Invoke-RestMethod -Method GET -Uri $($EraBaseURLv09 + "tms?load-database=true&load-clones=true&clone-tms=true&database-tms=true&detailed=true&load-metrics=true&load-associated-clusters=true") -TimeoutSec 60 -Headers $restHeader -ContentType $ContentType
		} catch {
			$stage
			$_.Exception.Message
			$respStream = $_.Exception.Response.GetResponseStream()
			$reader = New-Object System.IO.StreamReader($respStream)
			$respBody = $reader.ReadToEnd() | ConvertFrom-Json
		}

		$restResponse | %{ 
						  $ephem =[ordered]@{
							  "name" = $_.name
							  "sla_name" = $_.sla.name
							  "schedule_name" = $_.schedule.name
							  "sizeGiB" = NormalizeInGiB $_.metric.aggregatestorage.size $_.metric.aggregatestorage.unit
							  }
						  $timeMachines[$_.databaseId] = $ephem
						  }

		#build dictionary of Database Server VMs
		try {
			$stage = "DB Server VMs"
			$restResponse = Invoke-RestMethod -Method GET -Uri $($EraBaseURLv09 + "dbservers?detailed=true&load-metrics=true") -TimeoutSec 60 -Headers $restHeader -ContentType $ContentType
		} catch {
			$stage
			$_.Exception.Message
			$respStream = $_.Exception.Response.GetResponseStream()
			$reader = New-Object System.IO.StreamReader($respStream)
			$respBody = $reader.ReadToEnd() | ConvertFrom-Json
		}

		$restResponse | %{ 
						  $ephemProperties = $_.properties | ?{$_.name -in $customProperties}
						  $ephem =[ordered]@{
							"name" = $_.name
							"ip_addr" = $_.ipAddresses[0]
							"socket_count" = $_.metric.compute.numVCPUs
							"corepersocket_count" = $_.metric.compute.numcoresperVCPU
							"memory_sizeGiB" = NormalizeInGiB $_.metric.memory.memory $_.metric.memory.unit
							"storage_allotGiB" = NormalizeInGiB $_.metric.storage.allocatedSize $_.metric.storage.unit
							"storage_usedGiB" = NormalizeInGiB $_.metric.storage.usedSize $_.metric.storage.unit
							"os_type" = ($ephemProperties | ?{$_.name -eq $customProperties[0]}).value
							
							#below is rather ugly, because Era APIv0.9 has separate property (os_version) to identify version of Windows Server and uses os_info property to display uname output for Linux (while "os_version" doesn't exist for Windows:/
							"os_ver" = if ([string](($ephemProperties | ?{$_.name -eq $customProperties[1]}).value) -ne "") {[string](($ephemProperties | ?{$_.name -eq $customProperties[1]}).value)} else {[string](($ephemProperties | ?{$_.name -eq $customProperties[2]}).value.split(' ')[0..2])}
							
							"app_ver" = ($ephemProperties | ?{$_.name -eq $customProperties[4]}).value
							"nx_cluster" = $nxClusters[$_.nxClusterId].name
							"cloud" = $nxClusters[$_.nxClusterId].cloud_type
							"hypervisor" = $nxClusters[$_.nxClusterId].hypervisor_type
							"aos" = $nxClusters[$_.nxClusterId].aos_version
						 }
						 $dbServers[$_.id] = $ephem
						 }

		#grab list of databases and cross reference it to Time Machine and Database Server VMs dictionaries
		try {
			$stage = "Databases"
			$restResponse = Invoke-RestMethod -Method GET -Uri $($EraBaseURLv09 + "databases?detailed=true") -TimeoutSec 60 -Headers $restHeader -ContentType $ContentType
		} catch {
			$stage 
			$_.Exception.Message
			$respStream = $_.Exception.Response.GetResponseStream()
			$reader = New-Object System.IO.StreamReader($respStream)
			$respBody = $reader.ReadToEnd() | ConvertFrom-Json
		}

        foreach ($restDB in $restResponse) {
			$ephemProperties = $restDB.properties | ?{$_.name -in $customProperties}
            $restReportItem = [PSCustomObject]@{
                "db_name" = $($restDB.name)
                "db_type" = $($restDB.type)
				"db_isClustered" = $($restDB.clustered)
				"db_isClone" = $($restDB.clone)
				"db_version" = $dbServers[$($restDB.databaseNodes[0].dbserverId)].app_ver
				"db_sizeGiB" = NormalizeInGiB ($ephemProperties | ?{$_.name -eq $customProperties[5]}).value ($ephemProperties | ?{$_.name -eq $customProperties[6]}).value
				"tms_name" = $timeMachines[$($restDB.id)].name
				"tms_sizeGiB" = $timeMachines[$($restDB.id)].sizeGiB
				"sla_name" = $timeMachines[$($restDB.id)].sla_name
				"schedule_name" = $timeMachines[$($restDB.id)].schedule_name
				"nx_cluster" = $dbServers[$($restDB.databaseNodes[0].dbserverId)].nx_cluster
				"hypervisor" = $dbServers[$($restDB.databaseNodes[0].dbserverId)].hypervisor
				"cloud_type" = $dbServers[$($restDB.databaseNodes[0].dbserverId)].cloud
				"aos_version" = $dbServers[$($restDB.databaseNodes[0].dbserverId)].aos
				"srv_name" = $dbServers[$($restDB.databaseNodes[0].dbserverId)].name
				"srv_OS" = $dbServers[$($restDB.databaseNodes[0].dbserverId)].os_type
				"srv_OSver" = $dbServers[$($restDB.databaseNodes[0].dbserverId)].os_ver
				"srv_sockets" = $dbServers[$($restDB.databaseNodes[0].dbserverId)].socket_count
				"srv_corespersocket" = $dbServers[$($restDB.databaseNodes[0].dbserverId)].corepersocket_count
				"srv_memGiB" = $dbServers[$($restDB.databaseNodes[0].dbserverId)].memory_sizeGiB
				"srv_allocatedGiB" = $dbServers[$($restDB.databaseNodes[0].dbserverId)].storage_allotGiB
				"srv_usedGiB" = $dbServers[$($restDB.databaseNodes[0].dbserverId)].storage_usedGiB
				
            } 

            $restReportArray += $restReportItem
            
        }
		
		#we need to do same as above for Clones, as class is slightly different and no all properties are present
		try {
			$stage = "Databases"
			$restResponse = Invoke-RestMethod -Method GET -Uri $($EraBaseURLv09 + "clones?detailed=true&any-status=true") -TimeoutSec 60 -Headers $restHeader -ContentType $ContentType
		} catch {
			$stage 
			$_.Exception.Message
			$respStream = $_.Exception.Response.GetResponseStream()
			$reader = New-Object System.IO.StreamReader($respStream)
			$respBody = $reader.ReadToEnd() | ConvertFrom-Json
		}

        foreach ($restClone in $restResponse) {
			$ephemProperties = $restClone.properties | ?{$_.name -in $customProperties}
            $restReportItem = [PSCustomObject]@{
                "db_name" = $($restClone.name)
                "db_type" = $($restClone.type)
				"db_isClustered" = $($restClone.clustered)
				"db_isClone" = $($restClone.clone)
				"db_version" = $dbServers[$($restClone.databaseNodes[0].dbserverId)].app_ver
				"db_sizeGiB" = "n/a"
				"tms_name" = $($restClone.parentTimeMachine.name)
				"tms_sizeGiB" = "n/a"
				"sla_name" = $($restClone.parentTimeMachine.sla.name)
				"schedule_name" = $($restClone.parentTimeMachine.schedule.name)
				"nx_cluster" = $dbServers[$($restClone.databaseNodes[0].dbserverId)].nx_cluster
				"hypervisor" = $dbServers[$($restClone.databaseNodes[0].dbserverId)].hypervisor
				"cloud_type" = $dbServers[$($restClone.databaseNodes[0].dbserverId)].cloud
				"aos_version" = $dbServers[$($restClone.databaseNodes[0].dbserverId)].aos
				"srv_name" = $dbServers[$($restClone.databaseNodes[0].dbserverId)].name
				"srv_OS" = $dbServers[$($restClone.databaseNodes[0].dbserverId)].os_type
				"srv_OSver" = $dbServers[$($restClone.databaseNodes[0].dbserverId)].os_ver
				"srv_sockets" = $dbServers[$($restClone.databaseNodes[0].dbserverId)].socket_count
				"srv_corespersocket" = $dbServers[$($restClone.databaseNodes[0].dbserverId)].corepersocket_count
				"srv_memGiB" = $dbServers[$($restClone.databaseNodes[0].dbserverId)].memory_sizeGiB
				"srv_allocatedGiB" = $dbServers[$($restClone.databaseNodes[0].dbserverId)].storage_allotGiB
				"srv_usedGiB" = $dbServers[$($restClone.databaseNodes[0].dbserverId)].storage_usedGiB
				
            } 

            $restReportArray += $restReportItem
            
        } #>
        
		$restReportArray | Sort-Object -Property vm_name | Export-Csv -path ((Get-Location).Path + "\" + $EraServer + "-db_report.csv") -NoTypeInformation -Encoding UTF8
		 
	}
	else {
		$total_errors += 2 #no DBs
	}
}
else {
	$total_errors += 1 #no connection over TCP/443 to $EraServer
}


if($DebugModeOn) { #always stop transcript before exiting, otherwise it will keep writing in background and ultimately fill-up your filesystem
	Stop-Transcript
}

return $total_errors #if no errors occured, this should be 0 (ZERO)

}


End { #is intentionally left empty right now, but might be useful for some clean-up and stuff

}
