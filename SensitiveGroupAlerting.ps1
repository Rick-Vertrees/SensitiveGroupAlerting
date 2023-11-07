<#
    .Version
        1.0
    .Author
        Richard Vertrees
    .Company
        Radiology Partners
    .Date
        03/07/2023
    .Source Material
        .Author
            Francois-Xavier Cat
        .Company
            LazyWinAdmin.Com
        .Source
            https://github.com/lazywinadmin/Monitor-ADGroupMembership

    .Changes From Source
        .1
            Central focus is being domain agnostic
        .2
            Domain group file is held in central Sharepoint repository
        .3
            Group Membership files are held in central Sharepoint repository
        .4
            Group change files are held in central Sharepoint repository
        .5
            Files are accessed via Microsoft Graph API via app registration
        .6
            Email is sent from Exchange Online using Microsoft Graph API via app registration
        .7
            Due to focus on a single use case I have removed all parameter options

    .Environment Requirements
        .1
            Powershell Version 5.1 or later
        .2
            PSGallery is available as a repository
        .3
            MSAL.ps for generating an access token
        .6
            Microsoft Graph Powershell SDK installed for Exchange Online functions
        .5
            RSAT installed for ActiveDirectory Module
        .6
            HTTP/HTTPS outbound and inbound from ops server
        .7
            Encrypted Client Secret file is generated on ops server:
            "ConvertTo-SecureString <Client Secret> -AsPlainText -Force | ConvertFrom-SecureString |Out-file -FilePath C:\Utils\Secure_Secret.txt"
        .8
            Service Account on host domain with read permission. Basic Domain User account.
#>

#Set TLS settings
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#Set Date Format
$DateFormat = Get-Date -Format "yyyyMMdd_HHmmss"

# HTML Report settings
$Report = "<p style=`"font-family:consolas;font-size:9pt`">" +
"<strong>Report Time:</strong> $DateFormat <br>" +
"<strong>Account:</strong> $env:userdomain\$($env:username.toupper()) on $($env:ComputerName.toUpper())" +
"</p>"

$Head = "<style>" +
"BODY{font-family:consolas;font-size:11pt}" +
"BODY{font-family:consolas;font-size:11pt}" +
"TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse}" +
"TH{border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color:`"#00297A`";font-color:white}" +
"TD{border-width: 1px;padding-right: 2px;padding-left: 2px;padding-top: 0px;padding-bottom: 0px;border-style: solid;border-color: black;background-color:white}" +
"TH{border-width: 1px;padding: 3px;border-style: solid;border-color: black;font-color:white}" +
"TD{border-width: 1px;padding-right: 2px;padding-left: 2px;padding-top: 0px;padding-bottom: 0px;border-style: solid;border-color: black}" +
"</style>"
$Head2 = "<style>" +
"BODY{font-family:consolas;font-size:9pt;}" +
"BODY{font-family:consolas;font-size:9pt;}" +
"TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}" +
"TH{border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color:`"#C0C0C0`"}" +
"TD{border-width: 1px;padding-right: 2px;padding-left: 2px;padding-top: 0px;padding-bottom: 0px;border-style: solid;border-color: black;background-color:white}" +
"TH{border-width: 1px;padding: 3px;border-style: solid;border-color: black}" +
"TD{border-width: 1px;padding-right: 2px;padding-left: 2px;padding-top: 0px;padding-bottom: 0px;border-style: solid;border-color: black}" +
"</style>"

#Declare Microsoft Graph authentication information
$myTenantId = <Tenant ID>
$clientID = <Client ID>
$clientSecret = Get-Content "<Location of Secret Secure String>" | ConvertTo-SecureString

#Get Access token
$myToken = Get-MsalToken -clientID $clientID -clientSecret $clientSecret -tenantID $myTenantId
$AccessToken = $MyToken.accesstoken | ConvertTo-SecureString -AsPlainText -Force
$Headers = @{Authorization = "Bearer $($myToken.AccessToken)"}

#Get Drive ID for Active Direcotry Engineers Sharepoint Site
$url = "https://graph.microsoft.com/v1.0/sites/<Tenant Sharepoint URL>:\sites\<Site Name>:\drive"
$Global:driveID = Invoke-RestMethod -Uri $url -Headers $Headers | Select-Object ID -ExpandProperty ID

Function SensitiveGroupReport {
    
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [String]$ReportPrefix,

        [Parameter(Mandatory=$false, Position=1)]
        [String]$RecipientsFile = "Group_Alerting_Recipients.txt"
    )

    #Get Group information from file
    $DomainGroupFile = $ReportPrefix + "_Groups.txt"
    $url2 = "https://graph.microsoft.com/v1.0/drives/$Global:driveID/items/root:<Folder Path>\$($DomainGroupFile):/content"
    $Groups = Invoke-RestMethod -Uri $url2 -Headers $Headers -Method Get -ContentType 'text/plain' | ConvertFrom-CSV

    ForEach ($Group in $Groups) {
        # Splatting for the AD Group Request
	    $GroupSplatting = @{ }
	    $GroupSplatting.Identity = $Group.Group
    
        #Get Group information from AD
        $GroupName = Get-ADGroup @GroupSplatting -Properties * -ErrorAction Continue -ErrorVariable ErrorProcessGetADGroup
	    $RealGroupName = $GroupName.name
    
        IF ($GroupName) {
					
	        # Splatting for the AD Group Members Request
	        $GroupMemberSplatting = @{ }
	        $GroupMemberSplatting.Identity = $GroupName
        
            #Get Member information from AD
            $Members = Get-ADGroupMember @GroupMemberSplatting -Recursive -ErrorAction Stop -ErrorVariable ErrorProcessGetADGroupMember
		    $Members = $members | get-aduser -Properties PasswordExpired  | Select-Object -Property *,@{ Name = 'DN'; Expression = { $_.DistinguishedName } }
        
            #Try to access member log in Sharepoint and if that fails create it.
            $StateFile = ("$($ReportPrefix)-$($RealGroupName)-membership.txt").Replace(' ','_')
            $url3 = "https://graph.microsoft.com/v1.0/drives/$driveID/items/root:<Folder Path>\$($StateFile):/content"
            $StateFileLocation = "C:\Reports\Group_Alerting\" + $StateFile
            Try {
                $ImportCSV = Invoke-RestMethod -Uri $url3 -Headers $Headers -Method Get -ContentType 'text/plain' | ConvertFrom-CSV
		        $Members | Export-csv -Path $StateFileLocation
                $upload = Invoke-RestMethod -Uri $url3 -Headers $Headers -Method Put -InFile $StateFileLocation -ContentType 'text/plain'
                Remove-Item -Path $StateFileLocation -Force
            }
            Catch {
                $ImportCSV = $Members
			    $Members | Export-csv -Path $StateFileLocation
                $upload = Invoke-RestMethod -Uri $url3 -Headers $Headers -Method Put -InFile $StateFileLocation -ContentType 'text/plain'
                Remove-Item -Path $StateFileLocation -Force
            }

            # GroupName Membership File is compared with the current GroupName Membership
		    $Changes = Compare-Object -DifferenceObject $ImportCSV -ReferenceObject $Members -ErrorAction stop -ErrorVariable ErrorProcessCompareObject -Property Name, SamAccountName, DN |
		    Select-Object @{ Name = "DateTime"; Expression = { Get-Date -Format "yyyyMMdd-hh:mm:ss" } }, @{
			    n = 'State'; e = {
				    IF ($_.SideIndicator -eq "=>") { "Removed" }
				    ELSE { "Added" }
			    }
		    }, DisplayName, Name, SamAccountName, DN | Where-Object { $_.name -notlike "*no user or group*" }

            If ($Changes) {
						
			    # CHANGE HISTORY
			    #  Get the Past Changes History
                $ChangesHistoryFile = ("$($ReportPrefix)-$($RealGroupName)-Changes.txt").Replace(' ','_')
                $url4 = "https://graph.microsoft.com/v1.0/drives/$driveID/items/root:<Folder Path>\$($ChangesHistoryFile):/content"
                $ChangesFileLocation = "C:\Reports\Group_Alerting\" + $ChangesHistoryFile
                [System.Collections.ArrayList]$ChangesHistory = @()
			    Try {
                    $ChangesHistory += Invoke-RestMethod -Uri $url4 -Headers $Headers -Method Get -ContentType 'text/plain' | ConvertFrom-CSV
                    $ChangesHistory += $Changes
                    $ChangesHistory | Export-csv -Path $ChangesFileLocation
                    $upload = Invoke-RestMethod -Uri $url4 -Headers $Headers -Method Put -InFile $ChangesFileLocation -ContentType 'text/plain'
                    Remove-Item -Path $ChangesFileLocation -Force
                }
                Catch {
                    $Changes | Export-csv -Path $ChangesFileLocation
                    $upload = Invoke-RestMethod -Uri $url4 -Headers $Headers -Method Put -InFile $ChangesFileLocation -ContentType 'text/plain'
                    Remove-Item -Path $ChangesFileLocation -Force
                    $ChangesHistory += $Changes
                }

                # EMAIL
						
                $EmailSubject = "PS MONITORING - $($GroupName.SamAccountName) Membership Change"
						
                #  Preparing the body of the Email
                $body = "<h2>Group: $($GroupName.SamAccountName)</h2>"
                $body += "<p style=`"font-family:consolas;font-size:8pt`">"
                $body += "<u>Group Description:</u> $($GroupName.Description)<br>"
                $body += "<u>Group DistinguishedName:</u> $($GroupName.DistinguishedName)<br>"
                $body += "<u>Group CanonicalName:</u> $($GroupName.CanonicalName)<br>"
                $body += "<u>Group SID:</u> $($GroupName.Sid.value)<br>"
                $body += "<u>Group Scope/Type:</u> $($GroupName.GroupScope) / $($GroupName.GroupType)<br>"
                $body += "</p>"
                $body += "<h3> Membership Change"
                $body += "</h3>"
                $body += "<i>The membership of this group changed. See the following Added or Removed members.</i>"
						
                # Removing the old DisplayName Property
                $eChanges = $changes | Select-Object -Property DateTime, State,Name, SamAccountName, DN
						
                $body += $eChanges | ConvertTo-Html -head $head | Out-String
                $body += "<br><br><br>"


                $eChangesHistory = $ChangesHistory | Select-Object -Property DateTime, State, Name, SamAccountName, DN				
                $body += "<h3>Change History</h3>"
                $body += "<i>List of the previous changes on this group observed by the script</i>"
                $body += $eChangesHistory | Sort-Object -Property DateTime -Descending | ConvertTo-Html -Fragment -PreContent $Head2 | Out-String
                $body = $body -replace "Added", "<font color=`"blue`"><b>Added</b></font>"
                $body = $body -replace "Removed", "<font color=`"red`"><b>Removed</b></font>"
                $body += $Report

                Connect-MgGraph -AccessToken $AccessToken >> $Null

                $url5 = "https://graph.microsoft.com/v1.0/drives/$driveID/items/root:<Folder Path>\$($RecipientsFile):/content"
                $EmailAddresses = Invoke-RestMethod -Uri $url5 -Headers $Headers -Method Get -ContentType 'text/plain' | ConvertFrom-CSV

                $EmailAddress  = @($EmailAddresses.email)
                $Recipient = $EmailAddress | % {@{emailAddress = @{ address = $_ }}}

                $body1  = @{
                content = $body
                ContentType = 'html'
                }

                $Message1 = New-MgUserMessage -UserId <Alerting Email> -Body $body1 -ToRecipients $Recipient -Subject $EmailSubject
                Send-MgUserMessage -UserId <Alerting Email> -MessageId $Message1.Id
            
            }
        }
    }

}
Try {
    $SubReportsFile = (Get-ADDomain).name + "_SubReports.txt"
    $url6 = "https://graph.microsoft.com/v1.0/drives/$Global:driveID/items/root:<Folder Path>\$($SubReportsFile):/content"
    $SubProcesses = Invoke-RestMethod -Uri $url6 -Headers $Headers -Method Get -ContentType 'text/plain' | ConvertFrom-CSV
} Catch {
    $SubProcesses = ""
}

$ReportPrefix = (Get-ADDomain).name
SensitiveGroupReport -ReportPrefix $ReportPrefix

If($SubProcesses) {
    ForEach($SubProcess in $SubProcesses) {
        write-host "Starting subprocesses"
        $ReportPrefix = (Get-ADDomain).name + "_" +$SubProcess.SubProcess
        $RecipientFile = $ReportPrefix + "_Group_Alerting_Recipients.txt"
        SensitiveGroupReport -ReportPrefix $ReportPrefix -RecipientsFile $RecipientFile
    }
}
 

