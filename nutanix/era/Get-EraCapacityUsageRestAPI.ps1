<#
.SYNOPSIS
    
    Simple script to report capacity usage via Era REST API

.DESCRIPTION

    Scirpt will run against Era instance and execute a few queries against different endpoints to gather the report.
    At least read-only access to Era is required. If UserName and PassWord are not provided as parameters, 
    the script will pop-up interactive "Get-Credentials" window to gather them.
    Script will determine the underlying Nutanix cluster and ask for credentials to access it

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

    Get-EraCapacityUsageRestAPI.ps1 -EraServer 10.11.12.13 -UserName admin -PassWord Nutanix/4u
    
.EXAMPLE

    Run the script with EraServer parameter only (as FQDN), script will interacively ask for credentials.

    Get-EraCapacityUsageRestAPI.ps1 -EraServer pc.nutanix.demo

   
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
			[string]$line,

			[Parameter(Mandatory=$False,Position=2)]
			[int]$Severity=0,

			[Parameter(Mandatory=$False,Position=3)]
			[string]$type="terse",

			[Parameter(Mandatory=$False,Position=4)]
			[string]$LogFile
   
		)

	$timestamp = (Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] "))
	$ui = (Get-Host).UI.RawUI

	switch ($Severity) {

			{$_ -gt 0} {$ui.ForegroundColor = "red"; $LogEntry = $timestamp + ":Error: " + $line; break;}
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
	[long]$MiB = $KiB * 1024
	[long]$GiB = $MiB * 1024
	
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

$Global:ProgressPreference = 'SilentlyContinue'

#constans
$ContentType = 'application/json' #we will be talking JSON!

#variables
[long]$total_errors = 0
[int]$error_entry = 1
[int]$info_entry = 0
[int]$warning_entry = -1
[string]$LogMode = "terse"
[string]$empty_text = ""
[string]$stage = "At stage 'Startup' "
[string]$clusterHAState = ""


$ScriptRoot = (Get-Location).Path
$StartTime = Get-Date -Format "yyyyMMddHHmmssff_"
$logdir = $ScriptRoot + "\Get-EraCapacityUsageRestAPI_Logs\"
$logfilename = $logdir + $StartTime + "Get-EraCapacityUsageRestAPI.log"
$transcriptfilename = $logdir + $StartTime + "Get-EraCapacityUsageRestAPI_Transcript.log"

$nxClusterHosts = @{}
#[System.Collections.ArrayList]$nxClusterHosts = New-Object System.Collections.ArrayList($null)
$nxClusterVMs = @{}
$nxClusterCVMs = @{}
$eraContaierVMs = @{}
$eraRegisteredVMs = @()
$eraRegisteredVMUUIDs = @()
$customProperties = ("ERA_STORAGE_CONTAINER", "UP", "B", "MB", "SIZE", "SIZE_UNIT", "AHV", "NoReservations", "Disabled", "Enabled", "2", "1:", "95")

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
	$VerbosePreference = "Continue"
	$LogMode = "full"
	
	#variables

	#test for log directory, create one if needed
	if ( -not (Test-Path $logdir)) {
		New-Item -type directory -path $logdir | Out-Null
	}

	#start PowerShell transcript
	Start-Transcript -Path $transcriptfilename | Out-Null

}
<#else{
	$ErrorActionPreference = "SilentlyContinue"
}#>

#validate if $EraServer is responding on TCP/443 (exit if it doesn't)
if (Test-NetConnection -ComputerName $EraServer -Port 443 -InformationLevel Quiet) {

    if (($UserName) -and ($PassWord)) {
        
        $PlainTextCredentials = "$($UserName):$($PassWord)"
        $EncodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($PlainTextCredentials))
        $eraRestHeader = @{ "Authorization" = "Basic $EncodedCredentials" }
    
    }
    else {

        $eraRestCredentials = $host.ui.PromptForCredential("Need credentials!", "Please specify your Era login credentials.", "", "")
		if ($eraRestCredentials.username){
			$eraRestPassword = $((New-Object PSCredential "$($eraRestCredentials.username)",$($eraRestCredentials.Password)).GetNetworkCredential().Password)
			$eraRestHeader = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($eraRestCredentials.Username)" + ":" + $($eraRestPassword)))}
		}
		else {
			WriteAndLog ("Era UserName not specified, exiting...") $error_entry $LogMode $logfilename
			$total_errors += 1024
			return $total_errors;
		}
    }

	#validate if we have any DBs at all
	try {
		$stage = "At stage 'Era REST API check'. "
		$restResponse = Invoke-RestMethod -Method GET -Uri $($EraBaseURLv09 + "clusters?include-management-server-info=false") -TimeoutSec 60 -Headers $eraRestHeader -ContentType $ContentType -ErrorAction Stop
	} catch {
		WriteAndLog ($stage + "Exception message follows:") $error_entry $LogMode $logfilename
		WriteAndLog $_.Exception.Message $error_entry $LogMode $logfilename
		$respStream = $_.Exception.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($respStream)
		$respBody = $reader.ReadToEnd() | ConvertFrom-Json
		$total_errors += 8192
		throw $total_errors
	}
	finally {
		
	}
	
	#we've got something
	if ($restResponse.count -gt 0)  {
		if ($restResponse.count -lt 2)  { #currently this script can handle exactly one Nutanix Cluster

			#build dictionary of Nutanix Clusters
			try {
				$stage = "At stage 'Retrieving NTNX Cluster'. "
				$restResponse = Invoke-RestMethod -Method GET -Uri $($EraBaseURLv09 + "clusters?include-management-server-info=true") -TimeoutSec 60 -Headers $eraRestHeader -ContentType $ContentType -ErrorAction Stop
			} catch {
				WriteAndLog ($stage + "Exception message follows:") $error_entry $LogMode $logfilename
				WriteAndLog $_.Exception.Message $error_entry $LogMode $logfilename
				$respStream = $_.Exception.Response.GetResponseStream()
				$reader = New-Object System.IO.StreamReader($respStream)
				$respBody = $reader.ReadToEnd() | ConvertFrom-Json
				$total_errors += 4096
				throw $total_errors
			}
			finally {
				
			}

			$restResponse | %{ 
						  $nxCluster =[ordered]@{
							  "cluster_name" = $_.name
							  "ip_addr" = $_.ipAddresses[0]
							  "status" = $_.status
							  "cloud_type" = $_.cloudType
							  "hypervisor_type" = $_.hypervisorType
							  "aos_version" = $_.hypervisorVersion
							  "era_container" = ($_.properties | ?{$_.name -eq $customProperties[0]}).value
							  "storage_threshold" = $_.resourceConfig.storageThresholdPercentage
							  "memory_threshold" = $_.resourceConfig.memoryThresholdPercentage
							}
			}
			
			if ($nxCluster.status -eq $customProperties[1]){
				
				WriteAndLog ("Please provide credentials for Nutanix Cluster {0} with IP {1}" -f $nxCluster.cluster_name, $nxCluster.ip_addr) $info_entry $LogMode $logfilename
				$ntnxRestCredentials = $host.ui.PromptForCredential("Need credentials!", "Please specify login credentials for Prism Element $($nxCluster.cluster_name).", "", "")
				if ($ntnxRestCredentials.username) {
					$ntnxRestPassword = $((New-Object PSCredential "$($ntnxRestCredentials.username)",$($ntnxRestCredentials.Password)).GetNetworkCredential().Password)
					$ntnxRestHeader = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($ntnxRestCredentials.Username)" + ":" + $($ntnxRestPassword)))}
				}
				else {
					WriteAndLog ("Prism Element UserName not specified, exiting...") $error_entry $LogMode $logfilename
					$total_errors += 2048
					return $total_errors;
				}
				
				$PrismBaseURLv2 = "https://" + $nxCluster.ip_addr + ":9440/PrismGateway/services/rest/v2.0/"

				try {
					$stage = "At stage 'Retrieving Cluster Memory utilization'. "
					$restResponse = Invoke-RestMethod -Method GET -Uri $($PrismBaseURLv2 + "cluster") -TimeoutSec 60 -Headers $ntnxRestHeader -ContentType $ContentType -ErrorAction Stop
				} catch {
					WriteAndLog ($stage + "Exception message follows:") $error_entry $LogMode $logfilename
					WriteAndLog $_.Exception.Message $error_entry $LogMode $logfilename
					$respStream = $_.Exception.Response.GetResponseStream()
					$reader = New-Object System.IO.StreamReader($respStream)
					$respBody = $reader.ReadToEnd() | ConvertFrom-Json
				    $total_errors += 16
					throw $total_errors;
				}
				finally {
					
				}
				$nxClusterMemoryUsage = [math]::Round($restResponse.stats.hypervisor_memory_usage_ppm / 10000, 2)
				
				Clear-Host
				WriteAndLog ("Both Era Server {0} and Prism Element {1} successfully connected. Please wait..." -f $EraServer, $nxCluster.cluster_name) $info_entry $LogMode $logfilename
				
				try {
					$stage = "At stage 'Retrieving Era Container utilization'. "
					$restResponse = Invoke-RestMethod -Method GET -Uri $($PrismBaseURLv2 + "storage_containers/?search_string=$($nxCluster.era_container)") -TimeoutSec 60 -Headers $ntnxRestHeader -ContentType $ContentType -ErrorAction Stop
				} catch {
					WriteAndLog ($stage + "Exception message follows:") $error_entry $LogMode $logfilename
					WriteAndLog $_.Exception.Message $error_entry $LogMode $logfilename
					$respStream = $_.Exception.Response.GetResponseStream()
					$reader = New-Object System.IO.StreamReader($respStream)
					$respBody = $reader.ReadToEnd() | ConvertFrom-Json
				    $total_errors += 32
					throw $total_errors
				}
				finally {
					
				}				

				#filter container name exactly, cause REST API search will return all DBaaS, dbaas and DBaaSS even.
				$entity = ($restResponse | %{$_.entities} | ?{$_.name -ceq $nxCluster.era_container})

				$entity | %{ 							#some properties are in quotations to escape dots '.' in json path
							  $eraContainer =[ordered]@{
								"uuid" = $_.storage_container_uuid
								"rf" = $_.replication_factor
								"container_availableGiB" = NormalizeInGiB $_.usage_stats.'storage.user_unreserved_capacity_bytes' $customProperties[2]
								"container_freeGiB" = NormalizeInGiB $_.usage_stats.'storage.user_unreserved_free_bytes' $customProperties[2]
								"usage_pct" = [math]::Round((($(NormalizeInGiB $_.usage_stats.'storage.user_unreserved_capacity_bytes' $customProperties[2]) - $(NormalizeInGiB $_.usage_stats.'storage.user_unreserved_free_bytes' $customProperties[2]))*100) / $(NormalizeInGiB $_.usage_stats.'storage.user_unreserved_capacity_bytes' $customProperties[2]),2)
								}
				}
				
				#let's grab info about hosts
				try {
					$stage = "At stage 'Retrieving Host info'. "
					$restResponse = Invoke-RestMethod -Method GET -Uri $($PrismBaseURLv2 + "/hosts") -TimeoutSec 60 -Headers $ntnxRestHeader -ContentType $ContentType -ErrorAction Stop
				} catch {
					WriteAndLog ($stage + "Exception message follows:") $error_entry $LogMode $logfilename
					WriteAndLog $_.Exception.Message $error_entry $LogMode $logfilename
					$respStream = $_.Exception.Response.GetResponseStream()
					$reader = New-Object System.IO.StreamReader($respStream)
					$respBody = $reader.ReadToEnd() | ConvertFrom-Json
				    $total_errors += 64
					throw $total_errors;					
				}				
				finally {
					
				}
				
				$restResponse.entities | %{ 
										   $memory_sizeGiB = NormalizeInGiB $_.memory_capacity_in_bytes $customProperties[2]
										   $ephem =[ordered]@{
										   "sockets" = $_.num_cpu_sockets
										   "socket_cores" = $_.num_cpu_cores / $_.num_cpu_sockets
										   "host_cores" = $_.num_cpu_cores
										   "memory_sizeGiB" = $memory_sizeGiB
										   "numa_GiB" = $memory_sizeGiB / $_.num_cpu_sockets
										   }
										$nxClusterHosts[$_.uuid] = $ephem
										#$nxClusterHosts.Add((New-Object PSObject -Property $ephem)) | Out-Null
				}
				
				if ($nxCluster.hypervisor_type -ceq $customProperties[6]) { #check for /ha state
					try {
						$stage = "At stage 'Retrieving Cluster HA state'. "
						$restResponse = Invoke-RestMethod -Method GET -Uri $($PrismBaseURLv2 + "/ha") -TimeoutSec 60 -Headers $ntnxRestHeader -ContentType $ContentType -ErrorAction Stop
					} catch {
						WriteAndLog ($stage + "Exception message follows:") $error_entry $LogMode $logfilename
						WriteAndLog $_.Exception.Message $error_entry $LogMode $logfilename
						$respStream = $_.Exception.Response.GetResponseStream()
						$reader = New-Object System.IO.StreamReader($respStream)
						$respBody = $reader.ReadToEnd() | ConvertFrom-Json
						$total_errors += 128
						throw $total_errors;						
					}
					finally {
						
					}					
					$clusterHAState = $restResponse.reservation_type
				}
				
				$PrismBaseURLv1 = "https://" + $nxCluster.ip_addr + ":9440/PrismGateway/services/rest/v1/" #REST API v1 rulz for getting VM info!
				
				try {
					$stage = "At stage 'Retrieving VM info'. "
					$restResponse = Invoke-RestMethod -Method GET -Uri $($PrismBaseURLv1 + "/vms/") -TimeoutSec 60 -Headers $ntnxRestHeader -ContentType $ContentType -ErrorAction Stop
				} catch {
					WriteAndLog ($stage + "Exception message follows:") $error_entry $LogMode $logfilename
					WriteAndLog $_.Exception.Message $error_entry $LogMode $logfilename
					$respStream = $_.Exception.Response.GetResponseStream()
					$reader = New-Object System.IO.StreamReader($respStream)
					$respBody = $reader.ReadToEnd() | ConvertFrom-Json
					$total_errors += 256
					throw $total_errors;
				}				
				finally {
					
				}
				
				$restResponse.entities | %{ 
										   $ephem =[ordered]@{
										   "name" = $_.vmName
										   "uuid" = $_.uuid	
										   "vm_cores" = $_.numVCpus
										   "memory_sizeGiB" = NormalizeInGiB $_.memoryCapacityInBytes $customProperties[2]
										   }
										$nxClusterVMs[$_.uuid] = $ephem
										#$nxClusterHosts.Add((New-Object PSObject -Property $ephem)) | Out-Null
				}
				
				#filter out CVMs
				$restResponse.entities | ?{$_.controllerVm -eq "true"} |
									     %{
										   $ephem =[ordered]@{
										   "name" = $_.vmName
										   "uuid" = $_.uuid	
										   "vm_cores" = $_.numVCpus
										   "container" = $_.containerUuids
										   "memory_sizeGiB" = NormalizeInGiB $_.memoryCapacityInBytes $customProperties[2]	   
									      }
										$nxClusterCVMs[$_.uuid] = $ephem
				}				
				#now filter out only VMs deployed in Era Container ?
				$restResponse.entities | ?{(%{$_.containerUuids} | ?{$_ -eq $eraContainer.uuid}).count -gt 0} |
									     %{
										   $ephem =[ordered]@{
										   "name" = $_.vmName
										   "uuid" = $_.uuid	
										   "vm_cores" = $_.numVCpus
										   "container" = $_.containerUuids
										   "memory_sizeGiB" = NormalizeInGiB $_.memoryCapacityInBytes $customProperties[2]	   
									      }
										$eraContaierVMs[$_.uuid] = $ephem
				}
				
				WriteAndLog ("Data collection from Prism Element {0} completed, cross-checking with Era. Please wait..." -f $nxCluster.cluster_name) $info_entry $LogMode $logfilename
				
				#reach out to Era to grab UUIDs of VMs registered in Era
				try {
					$stage = "At stage 'Era deployed UUIDs'. "
					$restResponse = Invoke-RestMethod -Method GET -Uri $($EraBaseURLv09 + "dbservers?load-dbserver-cluster=true&load-databases=false&load-clones=true&detailed=true&load-metrics=false&time-zone=UTC") -TimeoutSec 60 -Headers $eraRestHeader -ContentType $ContentType -ErrorAction Stop
				} catch {
					WriteAndLog ($stage + "Exception message follows:") $error_entry $LogMode $logfilename
					WriteAndLog $_.Exception.Message $error_entry $LogMode $logfilename
					$respStream = $_.Exception.Response.GetResponseStream()
					$reader = New-Object System.IO.StreamReader($respStream)
					$respBody = $reader.ReadToEnd() | ConvertFrom-Json
					$total_errors += 512
					throw $total_errors
				}
				finally {
					
				}
				
				$restResponse.dbserverClusters | %{$_.dbservers} | %{$eraRegisteredVMUUIDs += $_.vmClusterUuid}
				$restResponse.dbservers | %{$eraRegisteredVMUUIDs += $_.vmClusterUuid}
				
				$eraRegisteredVMs = $nxClusterVMs.GetEnumerator() | ?{$_.value.uuid -in $eraRegisteredVMUUIDs}
								
				Write-Host (">>>>>>>>>>>>>>>>>>> Nutanix Cluster information: <<<<<<<<<<<<<<<<<<<<<<")
				Write-Host ("{0,-52}  :  {1,14}" -f "Cluster name", $nxCluster.cluster_name) -ForegroundColor Green
				Write-Host ("{0,-52}  :  {1,14}" -f "Hypervisor type", $nxCluster.hypervisor_type) -ForegroundColor Green
				Write-Host ("{0,-52}  :  {1,14}" -f "AOS version", $nxCluster.aos_version) -ForegroundColor Green
				Write-Host ("{0,-52}  :  {1,14}" -f "Number of hosts", $nxClusterHosts.count) -ForegroundColor Green
				Write-Host ("{0,-52}  :  {1,14}" -f "Number of VMs", $nxClusterVMs.count) -ForegroundColor Green
				Write-Host ("{0,-52}  :  {1,14}" -f "Era Storage Container", $nxCluster.era_container) -ForegroundColor Green
				Write-Host ("{0,-52}  :  {1,14}" -f "Era Storage Container RF", $eraContainer.rf) -ForegroundColor Green
				$sumCVMRAM = ($nxClusterCVMs.GetEnumerator() | %{$_.value.memory_sizeGiB} | measure-object -Sum).Sum
				$sumpRAM = ($nxClusterHosts.GetEnumerator() | %{$_.value.memory_sizeGiB} | measure-object -Sum).Sum
				if ($nxCluster.hypervisor_type -eq $customProperties[6]) {
					if ($clusterHAState -eq $customProperties[7]) {
						Write-Host ("{0,-52}  :  {1,14}" -f "AHV HA Reservation", $customProperties[8]) -ForegroundColor Red
					}
					else {
						$sumpRAM -= (($nxClusterHosts.GetEnumerator() | %{$_.value.memory_sizeGiB} | measure-object -Maximum).Maximum + $sumCVMRAM)
						Write-Host ("{0,-52}  :  {1,14}" -f "AHV HA Reservation", $customProperties[9]) -ForegroundColor Green
					}
				}
				Write-Host ("{0,-52}  :  {1,14}" -f "Current cluster memory usage from Prism Element (%)", $nxClusterMemoryUsage) -ForegroundColor Green
				Write-Host ("{0,-52}  :  {1,14}" -f "Era memory usage threshold (%)", $nxCluster.memory_threshold) -ForegroundColor Green
				Write-Host ("{0,-52}  :  {1,14}" -f "Era storage usage threshold (%)", $nxCluster.storage_threshold) -ForegroundColor Green
				
				Write-Host (">>>>>>>>>>>>>> Nutanix Cluster COMPUTE capacity usage: <<<<<<<<<<<<<<<<")
				Write-Host ("{0,-52}  :  {1,14}" -f "Aggregate host pRAM capacity (GiB)", $sumpRAM ) -ForegroundColor Green
				$sumvRAM = ($nxClusterVMs.GetEnumerator() | %{$_.value.memory_sizeGiB} | measure-object -Sum).Sum
				Write-Host ("{0,-52}  :  {1,14}" -f "Sum of VMs' configured memory (GiB)", $sumvRAM) -ForegroundColor Green
				$vRAMpRAM = [math]::Round(($sumvRAM * 100)/ $sumpRAM,2)
				if ($vRAMpRAM -gt $customProperties[12]) {
					Write-Host ("{0,-52}  :  {1,14}" -f "Configured VM vRAM vs host pRAM capacity (%)", $vRAMpRAM) -ForegroundColor Yellow
				}
				else {
					Write-Host ("{0,-52}  :  {1,14}" -f "Configured VM vRAM vs host pRAM capacity (%)", $vRAMpRAM) -ForegroundColor Green
				}
				
				$sumpCPU = ($nxClusterHosts.GetEnumerator() | %{$_.value.host_cores} | measure-object -Sum).Sum
				Write-Host ("{0,-52}  :  {1,14}" -f "Aggregate pCPU core count", $sumpCPU) -ForegroundColor Green
				$sumvCPU = ($nxClusterVMs.GetEnumerator() | %{$_.value.vm_cores} | measure-object -Sum).Sum
				Write-Host ("{0,-52}  :  {1,14}" -f "Sum of VMs' configured vCPU cores", $sumvCPU) -ForegroundColor Green
			    $nxClusterCPURatio = [math]::Round(($nxClusterVMs.GetEnumerator() | %{$_.value.vm_cores} | measure-object -Sum).Sum / ($nxClusterHosts.GetEnumerator() | %{$_.value.host_cores} | measure-object -Sum).Sum, 2)
				if ($nxClusterCPURatio -gt $customProperties[10]) {
					Write-Host ("{0,-52}  :  {1,14}" -f "Cluster pCPU to vCPU ratio (cores)", ($customProperties[11] + $nxClusterCPURatio)) -ForegroundColor Yellow
				}
				else {
					Write-Host ("{0,-52}  :  {1,14}" -f "Cluster pCPU to vCPU ratio (cores)", ($customProperties[11] + $nxClusterCPURatio)) -ForegroundColor Green
				}
				$minNUMApRAM = ($nxClusterHosts.GetEnumerator() | %{$_.value.numa_GiB} | measure-object -Minimum).Minimum
				$maxNUMAvRAM = ($nxClusterVMs.GetEnumerator() | %{$_.value.memory_sizeGiB} | measure-object -Maximum).Maximum
				Write-Host ("{0,-52}  :  {1,14}" -f "Smallest physical memory NUMA boundary (GiB)", $minNUMApRAM) -ForegroundColor Green
				if ($maxNUMAvRAM -gt $minNUMApRAM) {
					Write-Host ("{0,-52}  :  {1,14}" -f "Largest configured vRAM (GiB)", $maxNUMAvRAM) -ForegroundColor Red
				}
				$minNUMApCPU = ($nxClusterHosts.GetEnumerator() | %{$_.value.socket_cores} | measure-object -Minimum).Minimum
				$maxNUMAvCPU = ($nxClusterVMs.GetEnumerator() | %{$_.value.vm_cores} | measure-object -Maximum).Maximum
				Write-Host ("{0,-52}  :  {1,14}" -f "Smallest physical core count NUMA boundary", $minNUMApCPU) -ForegroundColor Green
				if ($maxNUMAvCPU -gt $minNUMApCPU) {
					Write-Host ("{0,-52}  :  {1,14}" -f "Largest configured vCPU core count", $maxNUMAvCPU) -ForegroundColor Red
				}
				Write-Host ("{0,-52}  :  {1,14}" -f "Number of CVMs", $nxClusterCVMs.count) -ForegroundColor Green
				Write-Host ("{0,-52}  :  {1,14}" -f "CVM configured vRAM footprint (GiB)", $sumCVMRAM) -ForegroundColor Green
				Write-Host ("{0,-52}  :  {1,14}" -f "CVM vCPU footprint (cores)", ($nxClusterCVMs.GetEnumerator() | %{$_.value.vm_cores} | measure-object -Sum).Sum) -ForegroundColor Green
				Write-Host ("{0,-52}  :  {1,14}" -f "Number of UVMs registered in Era", $eraRegisteredVMs.count) -ForegroundColor Green
				$sumEravRAM = ($eraRegisteredVMs | %{$_.value.memory_sizeGiB}| measure-object -Sum).Sum
				Write-Host ("{0,-52}  :  {1,14}" -f "Era UVMs configured vRAM footprint (GiB)", $sumEravRAM) -ForegroundColor Green
				$EravRAMpRAM = [math]::Round(($sumEravRAM * 100)/($sumpRAM - $sumCVMRAM),2)
				if ($EravRAMpRAM -gt ($nxCluster.memory_threshold * $customProperties[12])/100) {
					Write-Host ("{0,-52}  :  {1,14}" -f "Era UVMs configured vRAM vs host pRAM capacity (%)", $EravRAMpRAM) -ForegroundColor Yellow
				}
				else {
					Write-Host ("{0,-52}  :  {1,14}" -f "Era UVMs configured vRAM vs host pRAM capacity (%)", $EravRAMpRAM) -ForegroundColor Green
				}
				$maxEravRAM = ($eraRegisteredVMs | %{$_.value.memory_sizeGiB} | measure-object -Maximum).Maximum
				if ($maxEravRAM -gt $minNUMApRAM) {
					Write-Host ("{0,-52}  :  {1,14}" -f "Largest configured vRAM (GiB)", $maxEravRAM) -ForegroundColor Red
				}				
				Write-Host ("{0,-52}  :  {1,14}" -f "Era UVMs vCPU footprint (cores)",($eraRegisteredVMs | %{$_.value.vm_cores}| measure-object -Sum).Sum) -ForegroundColor Green
				$maxEravCPU = ($eraRegisteredVMs | %{$_.value.vm_cores} | measure-object -Maximum).Maximum
				if ($maxEravCPU -gt $minNUMApCPU) {
					Write-Host ("{0,-52}  :  {1,14}" -f "Largest configured vCPU core count", $maxEravCPU) -ForegroundColor Red
				}
				
				Write-Host (">>>>>>>>>>>>>> Nutanix Cluster STORAGE capacity usage: <<<<<<<<<<<<<<<<")
				Write-Host ("{0,-52}  :  {1,14}" -f "Number of UVMs existing in Era Storage Container", $eraContaierVMs.count) -ForegroundColor Green
				Write-Host ("{0,-52}  :  {1,14}" -f "Current Era Storage Container usage (%)", $eraContainer.usage_pct) -ForegroundColor Green
				
			}
			else {
				total_errors += 8 #NTNX cluster down?
				WriteAndLog ("Nutanix Cluster {0} with IP {1} seems to be not responding, please check!" -f $nxCluster.cluster_name, $nxCluster.ip_addr) $warning_entry $LogMode $logfilename
			}
		}
		else {
			$total_errors += 4 #more than one cluster
			WriteAndLog "Sorry, this script currently doesn't support Era Multi-Cluster :(" $warning_entry $LogMode $logfilename
		}	
      
#		$restReportArray | Sort-Object -Property vm_name | Export-Csv -path ((Get-Location).Path + "\" + $EraServer + "-db_report.csv") -NoTypeInformation -Encoding UTF8 #>
		 
	}
	else {
		$total_errors += 2 #no clusters
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