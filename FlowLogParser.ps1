<#

.SYNOPSIS
  NSG FlowLog Parser

.DESCRIPTION
  NSG FlowLog Parser.  Parameters decides what block blob you will get. i.e time. Flowlogs are divided into hours of data. 
  
.EXAMPLE
  .\FlowLogParser.ps1 -ParametersFile .\<jsonfile> -macAddress "000D3AAAD413" -logTime "11.25.2019 10:00"
  .\FlowLogParser.ps1 -ParametersFile .\<jsonfile> -macAddress "000D3AAAD413"  -will get latest blob of flowlogs.
  .\FlowLogParser.ps1 -ParametersFile -macAddress "000D3AAAD413"   -will try to run with flowlogparser.json
  .\FlowLogParser.ps1 -ParametersFile .\<jsonfile> -will get all settings from config file. 
  
.NOTES
  Version:        1.0
  Author:         IEU/Thomas Aure
  Creation Date:  2019

#>

[CmdletBinding()]
param (
  
  [Parameter(Mandatory = $false)] 
  [datetime]$logTime = (get-date).ToUniversalTime(),

  [Parameter(Mandatory=$false)]
  [string] $ParametersFile = ".\flowlogparser.json"
)

Import-Module .\NSGFlowLogsModule.psm1 -Verbose

$configuration = Get-Content -Raw -Path $ParametersFile | ConvertFrom-Json

Write-Output "Setting Subscription Context: $($configuration.common.subscriptionname)"
if (!(Set-AzContext -SubscriptionName $configuration.common.subscriptionname)) { 
    throw "Not able to set the subscription context. Update the configuration file with the subscriptionname."
} 
Get-AzContext

foreach ($flowlog in $configuration.flowlogs) {

  # Get the block blob from the storageaccount
  $CloudBlockBlob = Get-NSGFlowLogCloudBlockBlob -subscriptionId $flowlog.subscriptionId -NSGResourceGroupName $flowlog.NSGResourceGroupName -NSGName $flowlog.NSGName -storageAccountName $flowlog.storageAccountName -storageAccountResourceGroup $flowlog.storageAccountResourceGroup -macAddress $flowlog.macAddress -logTime $logTime

  # Get the text (this is in json format) in the blob (this gets the whole blob for the hour)
  $blob = $CloudBlockBlob.DownloadText()

  # Convert the json into a psobject 
  [PSObject]$blobobj = $blob | ConvertFrom-Json

  # Table to keep the flows
  $Events = @()

  foreach ($entry in $blobobj.records) {

    $time = (get-date $entry.time).ToUniversalTime()

    foreach ($flow in $entry.properties.flows) {

      $rules = $flow.rule.split("_")
      $RuleType = $rules[0]
      $RuleName = $rules[1]
          
      foreach ($f in $flow.flows) {
        $Header = "Ref", "SrcIP", "DstIP", "SrcPort", "DstPort", "Protocol", "Direction", "Type"
        $o = $f.flowTuples | ConvertFrom-Csv -Delimiter "," -Header $Header    
        $o = $o | Select-Object @{n = 'ResourceGroup'; e = { $NSGResourceGroupName } }, @{n = 'NSG'; e = { $NSGName } }, Ref, SrcIP, DstIP, SrcPort, DstPort, Protocol, Direction, Type, @{n = 'Time'; e = { $time } }, @{n = "RuleType"; e = { $RuleType } }, @{n = "RuleName"; e = { $RuleName } }
        $Events += $o
      }
    }
  }

  # Enrich the information in the cells
  foreach ($entry in $events) {
    switch ($entry.protocol) {
      "U" { $entry.protocol = "UDP" }
      "T" { $entry.protocol = "TCP" }
    } 
    switch ($entry.direction) {
      "I" { $entry.direction = "InBound" }
      "O" { $entry.direction = "OutBound" }
    } 
    switch ($entry.type) {
      "A" { $entry.type = "Allow" }
      "D" { $entry.type = "Deny" }
    } 
  }

  # Open the array of flows in GridView
  $Events | Sort-Object Time -Descending | Out-GridView

  # Output the same table as text
  # $Events | Format-Table 

}