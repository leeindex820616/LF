#Function that logs a message to a text file
function LogMessage {
    param([string]$Message, [string]$LogFile)
    ((Get-Date).ToString() + " - " + $Message) >> $LogFile;
}
 
#Function that deletes log file if it exists
function DeleteLogFile {
    param([string]$LogFile)
    
    #Delete log file if it exists
    if (Test-Path $LogFile) {
        Remove-Item $LogFile
    }
} 

function WriteLog {
    param([string]$Message) 
    LogMessage -Message $Message -LogFile $LogFile
}

function Check_file {
    param([string]$Check_Message)
    $File_Path = Read-Host "$Check_Message"
    If ($File_Path -eq '') { 
        Write-Host -ForegroundColor Red "Souce file name could not empty" 
        $File_Exists = 0
    } 
    else {
        $ValidPath = Test-Path $File_Path
        If ($ValidPath) {
            WriteLog -Message "[Log] Will process the items in the File $File_Path"
            $File_Exists = 1
        } 
        else {
            Write-Host -ForegroundColor Red "Not Find the File $File_Path"
            WriteLog -Message "[error] Not Find the file $File_Path"
            $File_Exists = 0
            Start-Sleep -s 2
        }      
    }
    return $File_Exists, $File_Path
}

function Catch_It {
    # Obtain some information
    $expMessage = $_.Exception.Message
    $failedItem = $_.Exception.Source
    $line = $_.InvocationInfo.ScriptLineNumber
    $response = $_.Exception.Response
    # Check if there is a response.
    if ($_.Exception.Response -eq $null) {
        Write-Host "At $($line): $expMessage" -ForeGroundColor Red
        WriteLog -Message "[error] At $($line): $expMessage"
        $errorStatus = "404"
    }
    else {
        # Get the response body with more error detail.
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $respStream = $_.ErrorDetails.Message
            $errorCode = $respStream.code
            $errorMessage = $respStream.message         
            WriteLog -Message "[error] At line $($line): $expMessage $($errorCode): $errorMessage "
        }
        else {
            $respStream = $_.Exception.Response.GetResponseStream()    
            $reader = New-Object System.IO.StreamReader($respStream)
            $respBody = $reader.ReadToEnd() | ConvertFrom-Json
            $errorCode = $respBody.code
            $errorMessage = $respBody.message
            $causeDetails = $respBody.causeDetails
            WriteLog -Message "[error] At line $($line): $expMessage $($errorCode): $errorMessage $causeDetails"
        }
        $errorStatus = $_.Exception.Response.StatusCode.value__
        Write-Host -ForegroundColor Red "Error Code:" $_.Exception.Response.StatusCode.value__
        Write-Host -ForegroundColor Red "Description:" $_.Exception.Response.StatusDescription
    } 
    return $errorStatus
}

function UltraDNS_Auth {
    if ($security -eq 1) {
        Write-Host -ForegroundColor Yellow -NoNewline "`n`t`t Login UltraDNS by security.ini ID:  "
        Write-Host "$ultradns_secureID`n`n" -ForegroundColor White -NoNewline
        #Write-Host -ForegroundColor Yellow -NoNewline "`n`t`t Login UltraDNS by security.ini ID: $ultradns_secureID !`n"
    }
    else {
        $ultradns_secureID = Read-Host "`nPlease Enter Your UltraDNS ID"
        $ultradns_securePwd = Read-Host "Please Enter Your UltraDNS password" -AsSecureString
        if (($ultradns_secureID) -and ($ultradns_securePwd)) {
            $ultradns_plainPwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ultradns_securePwd))
        }
        else {
            Write-Host -ForegroundColor Red   " `n`t`t Login info could not empty!"
            $UltraDNS_Login = 0
            return $UltraDNS_Login, $UltraDNS_token, $UltraDNS_AuthHeader
        }
    }
    $auth_url = $ultradns_url + "authorization/token"
    $body = @{
        grant_type = 'password';
        username   = $ultradns_secureID;
        password   = $ultradns_plainPwd;
    }
    try {
        $auth = Invoke-RestMethod -Uri $auth_url -Body $body -Method POST -Verbose -ContentType "application/x-www-form-urlencoded" | Select-Object accessToken
    } 
    catch {
        $errorStatus = Catch_It
    }
    finally {
        if (($errorStatus -eq 401) -or ($errorStatus -eq 404)) {
            Write-Host -ForegroundColor Red "`n`t`t UltraDNS Login Fail, please check your login info!`n"
            Start-Sleep -s 3
            $UltraDNS_Login = 0
        }
        elseif ($errorStatus -eq 501) {
            Write-Host -ForegroundColor Red "`n`t`t UltraDNS Server could not connect or maintain, please wait a few minutes!`n"
            Start-Sleep -s 3
            $UltraDNS_Login = 0
        } 
        else {
            $UltraDNS_token = $auth.accessToken
            Write-Host -ForegroundColor Green "`n`t`t UltraDNS Login Success`n"
            Write-Host -ForegroundColor Green " Get Token=`n$UltraDNS_token"
            Write-Host -ForegroundColor Red   " `n`t`t It will expires in 3600 sec"
            $UltraDNS_AuthHeader = @{ 'Authorization' = "Bearer $UltraDNS_token" }
            $UltraDNS_Login = 1
        }

    }
    return $UltraDNS_Login, $UltraDNS_token, $UltraDNS_AuthHeader
}

function GoDaddy_Auth {
    if ($security -eq 1) {
        Write-Host -ForegroundColor Yellow -NoNewline "`n`t`t Login GoDaddy by security.ini API Key:  "
        Write-Host "$ini_godaddy_api_key`n`n" -ForegroundColor White -NoNewline
        $godaddy_api_key = "$ini_godaddy_api_key"
        $gogaddy_api_secret = "$ini_gogaddy_api_secret"
        #Write-Host -ForegroundColor Red "`n`t`t Login GoDaddy by security.ini API Key: $godaddy_api_key !`n"
    }
    else {
        $godaddy_api_key = Read-Host "`nPlease Enter Your GoDaddy API_Key"
        $godaddy_secret = Read-Host "Please Enter Your GoDaddy API Secret" -AsSecureString
        if (($godaddy_api_key) -and ($godaddy_secret)) {
            $gogaddy_api_secret = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($godaddy_secret))
        }        
        else {
            Write-Host -ForegroundColor Red  " `n`t`t Login info could not empty!"
            $GoDaddy_Login = 0
            return $GoDaddy_Login, $godaddy_api_key, $gogaddy_api_secret , $godaddy_headers
        }  
    }
    $action = "GET"
    $godaddy_authurl = "https://api.godaddy.com/v1/domains?limit=1"
    $key = "$godaddy_api_key" + ":" + "$gogaddy_api_secret"
    $godaddy_headers = @{ 'Authorization' = "sso-key $key" }
    try {
        $request = Invoke-RestMethod -Method $action -Uri $godaddy_authurl -Headers $godaddy_headers
    } 
    catch {
        $errorStatus = Catch_It
    }
    finally {
        if (($errorStatus -eq 401) -or ($errorStatus -eq 404) -or ($errorStatus -eq 500) ) {
            Write-Host -ForegroundColor Red "`n`t`t GoDaddy Login Fail, please check your login info!`n"
            Start-Sleep -s 3
            $GoDaddy_Login = 0
        }
        else {
            Write-Host -ForegroundColor Green "$errorStatus`n`t`t GoDaddy Login Success!"
            $GoDaddy_Login = 1
        }

    }
    return $GoDaddy_Login, $godaddy_api_key, $gogaddy_api_secret , $godaddy_headers
}

function GoDaddyDNS_Get_Record {
    Param
    (
        [Parameter(Mandatory = $true,
            Position = 0)]
        [string]$domain
    )

    Begin {
    }
    Process {
        $NoRecords = 0
        $records = @()
        #---- Build the request URI based on domain ----#
        $GoDaddy_uri = "https://api.godaddy.com/v1/domains/$domain/records"

        #---- Make the request ----#
        try {
            $records = Invoke-RestMethod -Uri $GoDaddy_uri -Method Get -Headers $godaddy_headers
        }
        catch {
            $errorStatus = Catch_It
        }
        finally {
            if ($errorStatus -eq 404) {
                Write-Host -ForegroundColor Red "Not find the Records in GoDaddy or domain not belong to this account. ."
                WriteLog -Message "[error  ] Not find the Record in GoDaddy or domain not belong to this account."
                $NoRecords = 1
            }
            else {
                Write-Host -ForegroundColor Green "Find the Records in GoDaddy will continue next process."
                WriteLog -Message "[log] Find the Records in GoDaddy will continue next process."
                if ($getdata -eq 1) {
                    $Types = "A", "CNAME", "MX", "TXT", "SRV"
                    foreach ($i in $Types) {
                        $num = ($records | Where-Object { $_.type -eq $i -and $_.data -ne "Parked" -and $_.name -ne "_domainconnect" } | Measure-Object | Select-Object Count ).count
                        Write-Host -ForegroundColor Green "Godaddy have $i type record $num`n"
                        WriteLog -Message "[ log ] Godaddy have $i type record $num."
                    }
                }
                $NoRecords = 0
            }
            Start-Sleep -s 1
        }
    }
    End {
        return $records, $NoRecords
    }
}

function GoDaddy_Check_DNS_Record {
    Param
    (
        [Parameter(Mandatory = $true,
            Position = 0)]
        [string]$domain
    )

    Begin {
    }
    Process {
        $Match_NS_Records = "0"
        $records = @()
        #---- Build the request URI based on domain ----#
        $GoDaddy_uri = "https://api.godaddy.com/v1/domains/$domain/records/NS"

        #---- Make the request ----#
        try {
            $records = Invoke-RestMethod -Uri $GoDaddy_uri -Method GET -Headers $godaddy_headers
        }
        catch {
            $errorStatus = Catch_It
        }
        finally {
            if ($errorStatus -eq 404) {
                Write-Host -ForegroundColor Red "This domain $domain does not find NS record in Godaddy DNS.`n"
                WriteLog -Message "[error  ] This domain $domain does not find NS record in Godaddy DNS."
            }
            else {
                #Write-Host -ForegroundColor Green "Find the NS Records in GoDaddy will continue next process."
                #WriteLog -Message "[log] Find the NS Records in GoDaddy will continue next process."
                foreach ($item in $request) {
                    [PSCustomObject]@{
                        createdAt   = $item.createdAt
                        domain      = $item.domain
                        domainId    = $item.domainId
                        expires     = $item.expires
                        nameServers = $item.nameServers
                        status      = $item.status
                    }
                    if ($item.nameServers -match "domaincontrol" -And $item.status -match "ACTIVE") {
                        $Match_NS_Records = "1"
                        Write-Host -ForegroundColor Green "This domain $domain NS record is Godaddy DNS so it will continue the process.`n"
                        WriteLog -Message "[ log ] This domain $domain NS record is Godaddy DNS so it will continue the process."
                    }
                    else {
                        $Match_NS_Records = "0"
                        Write-Host -ForegroundColor Green "This domain $domain NS record is not Godaddy DNS so it will not continue the process.`n"
                        WriteLog -Message "[error  ] This domain $domain NS record is not Godaddy DNS so it will not continue the process.."
                    }
                }
            }
        }
        Start-Sleep -s 1
    }
    End {
        return $Match_NS_Records
    }
}

function GoDaddyDNS_Get_Domain {
    $domaindata = @()

    #---- Build the request URI based on domain ----#
    $GoDaddy_uri = "https://api.godaddy.com/v1/domains?includes=nameServers"
    
    #---- Make the request ----#
    $request = Invoke-WebRequest -Uri $GoDaddy_uri -Method GET -Headers $godaddy_headers -UseBasicParsing | ConvertFrom-Json

    #---- Convert the request data into an object ----#
    foreach ($item in $request) {
        [PSCustomObject]@{
            createdAt   = $item.createdAt
            domain      = $item.domain
            domainId    = $item.domainId
            expires     = $item.expires
            nameServers = $item.nameServers
            status      = $item.status
        }
        $domain = $item.domain
        if ($item.nameServers -match "domaincontrol" -and $item.status -match "ACTIVE") {
            Write-Host "`nThis domain $domain not move to UltraDNS yet!`n"
            $domaindata = $domaindata + $item.domain
            GoDaddyDNS_Get_Record $item.domain
            Start-Sleep -s 1
        }
    }
}

function GoDaddyDNS_Check_Domain_Status {
    Param
    (
        [Parameter(Mandatory = $true,
            Position = 0)]
        [string]$domain
    )
    #---- Build the request URI based on domain ----#
    $GoDaddy_uri = "https://api.godaddy.com/v1/domains/" + $domain
    $godaddy_headers = @{ }
    $godaddy_headers["Authorization"] = 'sso-key ' + $godaddy_api_key + ':' + $gogaddy_api_secret
    #---- Make the request ----#
    $request = Invoke-RestMethod -Uri $GoDaddy_uri -Method GET -Headers $godaddy_headers
    if ($request.status -eq "CANCELLED") {
        $GoDaddy_expired = 1 
        Write-Host "`nThis domain $domain already expired in GoDaddy!`n"
        Start-Sleep -s 1
    }
    else {
        $GoDaddy_expired = 0
    }
    return $GoDaddy_expired
}


function GoDaddyDNS_Modify_Record {
    Write-Host "Modify GoDaddy DNS domain $domain NS records to UltraDNS"
       
    #---- Build the request URI based on domain ----#
    $action = "PATCH"
    $GoDaddy_uri = "https://api.godaddy.com/v1/domains/$domain"
    $body = @{
        "nameServers" = @(
            "pdns73.ultradns.com", "pdns73.ultradns.org", "pdns73.ultradns.net", "pdns73.ultradns.biz"
        )
    }
    $Check_NS = GoDaddy_Check_DNS_Record $domain
    #---- Make the request ----#
    try {
        Invoke-RestMethod -Method $action -Uri $GoDaddy_uri -Body (ConvertTo-Json $body) -ContentType "application/json" -Headers $godaddy_headers
    }
    catch {
        $errorStatus = Catch_It
    }
    finally {
        if (($errorStatus -eq 400) -or ($errorStatus -eq 404)) {
            Write-Host -ForegroundColor Red "Modify Godaddy domain $domain NS record to UltraDNS fail."
            WriteLog -Message "[error] Modify Godaddy domain $domain NS record to UltraDNS fail."
        }
        else {
            if ($Check_NS -eq "0") {
            }
            else {
                UltraDNS_Create_Migrated_TXT
                Write-Host -ForegroundColor Green "Modify Godaddy domain $domain NS record to UltraDNS success."
                WriteLog -Message "[ log ] Modify Godaddy domain $domain NS record to UltraDNS success."
            }
        }
    }
}

function UltraDNS_Check_TXT {
    $record = "mfg"
    $action = "GET"
    $check_url = $ultradns_url + "zones/" + $domain + "./rrsets/16/" + $record
    $checkparams = @{
        Uri         = $check_url
        Headers     = $UltraDNS_AuthHeader
        Method      = 'GET'
        ContentType = 'application/x-www-form-urlencoded'
    }
    try {
        Invoke-RestMethod @checkparams
    }
    catch {
        $errorStatus = Catch_It
    }
    finally {
        if ($errorStatus -eq 404) {
            Write-Host -ForegroundColor Red "Not find the GoDaddy TXT record in ULtraDns. There will start the transfer process."
            WriteLog -Message "[ log ] Not find the GoDaddy TXT record in ULtraDns. There will start the transfer process."
            $GoDaddy_Migrated = 0
        }
        elseif ($errorStatus -eq 400) {
            Write-Host -ForegroundColor Red "Query GoDaddy format was wrong."
            WriteLog -Message "[error] Query GoDaddy format was wrong."
        }
        elseif ($errorStatus -eq 401) {
            Write-Host -ForegroundColor Red "Authorize fail,please check your GoDaddy API Key and Secret."
            WriteLog -Message "[error] Authorize fail, wrong GoDaddy API Key and Secret."
        }
        else {
            Write-Host -ForegroundColor Green "Find the GoDaddy TXT record in UltraDNS. There will not start the transfer process."
            WriteLog -Message "[error] Find the GoDaddy TXT record in UltraDNS. There will not start the transfer process."
            $GoDaddy_Migrated = 1
        }
    }
    return $GoDaddy_Migrated
}

function UltraDNS_Get_Record {
    Param
    (
        [Parameter(Mandatory = $true,
            Position = 0)]
        [string]$domain
    )
    Begin { }
    Process {
        $records = @()
        #---- Build the request URI based on domain ----#
        $get_url = $ultradns_url + "zones/" + $domain + "./rrsets"

        #---- Make the request ----#
        $ultradns_resoult = Invoke-RestMethod -Ur $get_url  -Headers $UltraDNS_AuthHeader -Method GET -ContentType "application/x-www-form-urlencoded"
    }
    End {
        return $ultradns_records
    }
}

function UltraDNS_Create_Migrated_TXT {
    $ID = $ultradns_secureID | convertto-securestring -asplaintext -force
    $encrypted_ID = convertfrom-securestring $ID -key (Get-Content "AES.Key")
    $add_txt = 1
    $date = Get-Date -Format "yyyy-dd-mm_HHMMss"
    $record = "mfg"
    $action = "POST"
    $type = "TXT"
    $destination = "This domain Migrate from GoDaddy by $encrypted_ID at $date"
    UltraDNS_Modify_Record
}

function UltraDNS_Create_Zone {
    Write-Host "`n`t`tWill Running Script in $ultradns_url`n"
    $action = "POST"
    $create_url = $ultradns_url + "zones"
    Write-Host "Will Create domain $domain in UltraDNS"
    $zone_properties = @{
        "name"        = "$domain"
        "accountName" = "quantumglobal"
        "type"        = "PRIMARY"
    }

    $primary_zone_info = @{
        "forceImport" = "true" 
        "createType"  = "NEW"
    }

    $zone_data = @{
        "primaryCreateInfo" = $primary_zone_info
        "properties"        = $zone_properties
    }

    Write-Host -ForegroundColor Red "Star Create domain $domain in UltraDNS"
    try {
        Invoke-RestMethod -Method $action -Uri $create_url -Body (ConvertTo-Json $zone_data) -ContentType "application/json" -Headers @{"Authorization" = "Bearer $UltraDNS_token" }
    } 
    catch {
        $errorStatus = Catch_It
    }
    finally {
        if (($errorStatus -eq 400) -or ($errorStatus -eq 404)) {
            Write-Host -ForegroundColor Red "Create domain $domain in UltraDNS fail."
            WriteLog -Message "[error] Create domain $domain in UltraDNS fail."
        }
        else {
            Write-Host -ForegroundColor Green "Create domain $domain in UltraDNS Success."
            WriteLog -Message "[ log ] Create domain $domain in UltraDNS Success."
        }
    }
}

function UltraDNS_Delete_Zone {
    Write-Host "`n`t`tWill Running Script in $ultradns_url`n"
    $action = "DELETE"
    $delete_url = $ultradns_url + "zones" + $domain
    Write-Host "Will delete domain $domain in UltraDNS"
    try {
        Invoke-RestMethod -Method $action -Uri $delete_url -Headers @{"Authorization" = "Bearer $UltraDNS_token" }
    } 
    catch {
        $errorStatus = Catch_It
    }
    finally {
        if (($errorStatus -eq 400) -or ($errorStatus -eq 404)) {
            Write-Host -ForegroundColor Red "Delete domain $domain in UltraDNS fail."
            WriteLog -Message "[error] Delete domain $domain in UltraDNS fail."
        }
        else {
            Write-Host -ForegroundColor Green "Delete domain $domain in UltraDNS Success."
            WriteLog -Message "[ log ] Delete domain $domain in UltraDNS Success."
        }
    }
}


function UltraDNS_Check_Zone {
    #Write-Host "`n`t`tWill Running Script in $ultradns_url`n"
    $action = "GET"
    $check_url = $ultradns_url + "zones/" + $domain
    Write-Host -ForegroundColor Cyan "Check the domain $domain already in UltraDNS or Not ....`n"
    try {
        Invoke-RestMethod -Method $action -Uri $check_url -ContentType "application/json" -Headers @{"Authorization" = "Bearer $UltraDNS_token" }
    }
    catch {
        $errorStatus = Catch_It
    }
    finally {
        if (($errorStatus -eq 400) -or ($errorStatus -eq 404)) {
            Write-Host -ForegroundColor Red "This domain $domain not in UltraDNS`n"
            WriteLog -Message "[error  ] This domain $domain not in UltraDNS"
            if ($check_status -ne 1) {
                UltraDNS_Create_Zone $domain
                $UltraDNS_Zone_Status = 0
            }
            else {
                $UltraDNS_Zone_Status = 0
            }
        }
        else {
            $UltraDNS_Zone_Status = 1
            Write-Host -ForegroundColor Green "This domain $domain in UltraDNS`n"
            WriteLog -Message "[ log ] This domain $domain in UltraDNS"
        }
    }
    return $UltraDNS_Zone_Status
}

function UltraDNS_Modify_DIR_Pool {
    $body_raw = @{ }
    $rdatas = New-Object System.Collections.ArrayList
    $rdataInfo = New-Object System.Collections.ArrayList
    $action = "PUT"
    $X = 0
    $Next_FileContent = Get-Content $File_Path
    foreach ($FileContent in Get-Content $File_Path) {
        $X = $X + 1
        $Next_Content = $Next_FileContent[$X]
        if ($Next_Content) {
            $Next_poolname = $Next_Content.Split(":")[4]
            $Next_domain = $Next_Content.Split(":")[5]
        }
        $country_codes = New-Object System.Collections.ArrayList
        $country_codes = @($FileContent.Split(":")[0])
        $group_name = $FileContent.Split(":")[1]
        $rdata = $FileContent.Split(":")[2]
        $ttl = $FileContent.Split(":")[3]
        $poolname = $FileContent.Split(":")[4]
        $poolname_raw = $poolname
        $domain = $FileContent.Split(":")[5]
        if ($rdata -as [IPAddress] -as [Bool]) {
        }
        else {
            $rdata = $rdata + "."
        }
        if ($poolname -as [IPAddress] -as [Bool]) {
        }
        else {
            $poolname = $poolname + "."
        }
        if (($last_poolname) -and (($poolname -ne $last_poolname) -or ($domain -ne $last_domain))) {
            Write-Host -ForegroundColor Green "`nStart modify next Directional pool group or domain`n"
            $body_raw = @{ }
            $rdatas = New-Object System.Collections.ArrayList
            $rdataInfo = New-Object System.Collections.ArrayList
        }
        if ((!$Next_Content) -or ($Next_poolname -ne $poolname_raw) -or ($Next_domain -ne $domain)) {
            $backup_url = $ultradns_url + "zones/" + $domain + "/rrsets/A/" + "$poolname" + "?q=kind:DIR_POOLS"
            $backup_file = $JsonFile + "_" + $domain + "_" + $poolname + "_" + "zone.json.backup"
            $backup_result = Invoke-RestMethod -Uri $backup_url -Method GET -Headers @{"Authorization" = "Bearer $UltraDNS_token" }
            $backup_result | ConvertTo-Json -Depth 10 | Out-File "$backup_file"
            UltraDNS_rollback_pool
            $url = $ultradns_url + "zones/" + $domain + "/rrsets/A/" + $poolname
            $count = $country_codes.Split(",").count
            if ($count -gt 1) {
                $countrys = $country_codes.Split(",")
            }
            else {
                $countrys = @($country_codes)
            }
            $geoInfo = @{"name" = "$group_name"; "codes" = $countrys; }
            $rdatas = $rdatas + $rdata
            $rdataInfo.Add(@{"geoInfo" = $geoInfo; "ttl" = $ttl; })
            $profile = @{"@context" = "http://schemas.ultradns.com/DirPool.jsonschema"; "rdataInfo" = $rdataInfo; }
            $body_raw.Add("rdata", @($rdatas))
            $body_raw.Add("profile", $profile)
            $jason_file_name = $JsonFile + "_" + $domain + "_" + $poolname + "_" + "zone.json"
            $body_raw | ConvertTo-Json -Depth 10 | Out-File "$jason_file_name"
            $body = $body_raw | ConvertTo-Json -Depth 10
            try {
                Invoke-RestMethod -Method $action -Uri $url -Body $body -ContentType "application/json" -Headers @{"Authorization" = "Bearer $UltraDNS_token" }
            }
            catch {
                $errorStatus = Catch_It 
            }
            finally {
                if (($errorStatus -eq 400) -or ($errorStatus -eq 404)) {
                    Write-Host -ForegroundColor Red "Modify UltraDNS the domain $domain Directional Pool $poolname records fail."
                    WriteLog -Message "[error] Modify UltraDNS the domain $domain Directional Pool $poolname records fail."
                }
                else {
                    Write-Host -ForegroundColor Green "Modify UltraDNS the domain $domain Directional Pool $poolname records success."
                    WriteLog -Message "[ log ] Modify UltraDNS the domain $domain Directional Pool $poolname records success."
                }
            }
        }
        else {
            $count = $country_codes.Split(",").count
            if ($count -gt 1) {
                $countrys = $country_codes.Split(",")
            }
            else {
                $countrys = @($country_codes)
            }
            $geoInfo = @{"name" = "$group_name"; "codes" = $countrys; }
            $rdatas = $rdatas + $rdata
            $rdataInfo.Add(@{"geoInfo" = $geoInfo; "ttl" = $ttl; })
            $last_group_name = $group_name 
            $last_domain = $domain
            $last_poolname = $poolname
        }
    }
}

function UltraDNS_Modify_DIR_Name {
    Param
    (
        [Parameter(Mandatory = $true,
            Position = 0)]
        [string]$domain
    )
    $get_url = $ultradns_url + "zones/" + $domain + "/rrsets/?q=kind:DIR_POOLS"
    $owner_result = Invoke-RestMethod -Uri $get_url -Method GET -Headers @{"Authorization" = "Bearer $UltraDNS_token" } 
    foreach ($owner in $owner_result.rrSets.ownerName) {
        $body_raw = @{ }
        $rdatas = New-Object System.Collections.ArrayList
        $rdataInfo = New-Object System.Collections.ArrayList
        $rdatas = New-Object System.Collections.ArrayList
        $country_codes = New-Object System.Collections.ArrayList
        $country_count = 0
        $group_name = ""
        $get_detial_url = $ultradns_url + "zones/" + $domain + "/rrsets/A/" + $owner
        $get_detial_result = Invoke-RestMethod -Uri $get_detial_url -Method GET -Headers @{"Authorization" = "Bearer $UltraDNS_token" } 
        foreach ($data in $get_detial_result.rrSets.profile.rdataInfo) {
            $data.geoInfo.codes | ConvertTo-Json
            $country_codes = $data.geoInfo.codes
            $country_count = $data.geoInfo.codes.count
            if ($country_count -gt 3) {
                $group_name = "Except_Countrys"
            }
            else {
                $group_name = "Only_"
                foreach ($code in $data.geoInfo.codes) {
                    $group_name = $group_name + "$code"
                    if ($code -ne $data.geoInfo.codes[-1]) {
                        $group_name = $group_name + ","
                    } 
                }
            }      
            $ttl = $data.ttl
            $geoInfo = @{"name" = "$group_name"; "codes" = $country_codes; }
            $rdatas = $get_detial_result.rrSets.rdata
            $rdataInfo.Add(@{"geoInfo" = $geoInfo; "ttl" = $ttl; })   
        }
        $profile = @{"@context" = "http://schemas.ultradns.com/DirPool.jsonschema"; "rdataInfo" = $rdataInfo; }
        $body_raw.Add("rdata", $rdatas)
        $body_raw.Add("profile", $profile)
        $jason_file_name = $JsonFile + "_" + $domain + "_" + $owner + "_" + "zone.json"
        $body_raw | ConvertTo-Json -Depth 10 | Out-File "$jason_file_name"
        $body = $body_raw | ConvertTo-Json -Depth 10
        $modify_url = $ultradns_url + "zones/" + $domain + "/rrsets/A/" + $owner
        $action = "PUT"
        try {
            Invoke-RestMethod -Method $action -Uri $modify_url -Body $body -ContentType "application/json" -Headers @{"Authorization" = "Bearer $UltraDNS_token" }
        }
        catch {
            $errorStatus = Catch_It
        }
        finally {
            if (($errorStatus -eq 400) -or ($errorStatus -eq 404)) {
                Write-Host -ForegroundColor Red "Modify UltraDNS the domain $domain Directional Pool $owner name to standardization fail."
                WriteLog -Message "[error] Modify UltraDNS the domain $domain Directional Pool $owner name to standardization fail."
            }
            else {
                Write-Host -ForegroundColor Green "Modify UltraDNS the domain $domain Directional Pool $owner name to standardization success."
                WriteLog -Message "[ log ] Modify UltraDNS the domain $domain Directional Pool $owner name to standardization success."
            }
        }
    }
}


function UltraDNS_Backup_Record {
    Param
    (
        [Parameter(Mandatory = $true,
            Position = 0)]
        [string]$domain
    )
    $backup_url = $ultradns_url + "zones/" + $domain + "/rrsets/"
    $backup_file = $JsonFile + "_" + $domain + "_" + "zone.backup"
    $backup_result = Invoke-RestMethod -Uri $backup_url -Method GET -Headers @{"Authorization" = "Bearer $UltraDNS_token" }
    $backup_result | ConvertTo-Json -Depth 10 | Out-File "$backup_file"
}

function UltraDNS_Process_Record {
    Write-Host "`n`t`tWill Running Script in $ultradns_url`n"
    if ($zone_ransfer -eq 1) {
        Write-Host "`n`t`tWill try to backup UltraDNS $domain zone file to local first`n"
        UltraDNS_Backup_Record $domain
        Write-Host "`n`t`tStart update GoDaddy record to UltraDNS`n`n"
        foreach ($item in $records) {
            [PSCustomObject]@{
                destination = $item.data
                record      = $item.name
                TTL         = $item.ttl
                type        = $item.type
                priority    = $item.priority
                port        = $item.port
                service     = $item.service
                weight      = $item.weight
            }
            $destination = $item.data
            $record = $item.name
            $action = "POST"
            $TTL = $item.ttl
            $type = $item.type
            $service = $item.service
            $protocol = $item.protocol
            $priority = $item.priority
            $weight = $item.weight
            $port = $item.port
            if (($destination -match "_domainconnect") -or ($destination -match "Parked") -or ($type -eq "NS")) {
                Write-Host "`nThis Rcord will filter! becasue destination $destination is GoDaddy NS or default record!`n"
                WriteLog -Message "[error] This Rcord will filter! becasue destination $destination is GoDaddy NS or default record!"
                Start-Sleep -s 1
                continue
            }
            else {
                UltraDNS_Modify_Record
            }
        }
    }
    else {
        Write-Host "`n`t`tStart Process File $File_Path record to UltraDNS`n`n"
        foreach ($FileContent in Get-Content $File_Path) {
            $action = $FileContent.Split(",")[0]
            $type = $FileContent.Split(",")[1]
            $record = $FileContent.Split(",")[2]
            $destination = $FileContent.Split(",")[3]
            $domain = $FileContent.Split(",")[4]
            $TTL = $FileContent.Split(",")[5]
            $service = $FileContent.Split(",")[6]
            $protocol = $FileContent.Split(",")[7]
            $priority = $FileContent.Split(",")[8]
            $weight = $FileContent.Split(",")[9]
            $port = $FileContent.Split(",")[10]
            if ($domain -ne $last_domain) {
                Write-Host "`n`t`tStart backup UltraDNS $domain zone file to local`n"
                UltraDNS_Backup_Record $domain
                $last_domain = $domain
            }
            $last_domain = $domain
            UltraDNS_Modify_Record
        }
    }
}

function UltraDNS_rollback_pool {
    $backup_url = $ultradns_url + "zones/" + $domain + "/rrsets/A/" + "$poolname" + "?q=kind:DIR_POOLS"
    $backup_result = Invoke-RestMethod -Uri $backup_url -Method GET -Headers @{"Authorization" = "Bearer $UltraDNS_token" }
    $y = $backup_result.rrSets.profile.rdataInfo.geoInfo.count
    for ($x = 0; $x -lt $y; $x++) {
        $backup_country_codes = $backup_result.rrSets.profile.rdataInfo.geoInfo[$x].codes -join ","
        $backup_poolname = $backup_result.rrSets.profile.rdataInfo.geoInfo.name[$x]
        $backup_ip = $backup_result.rrSets.rdata[$x]
        $backup_ttl = $backup_result.rrSets.profile.rdataInfo.ttl[$x]
        $backup_pool = "$backup_country_codes" + ':' + "$backup_poolname" + ':' + "$backup_ip" + ':' + "$backup_ttl" + ':' + "$poolname" + ':' + "$domain"
        Write-Host -ForegroundColor Cyan "Dump $backup_pool to backup rollback pool file"
        $backup_pool >> $rollback_pool_file
    }
}

function UltraDNS_dump_pool {
    $dump_url = $ultradns_url + "zones/" + $dump_domain + "/rrsets/?q=kind:DIR_POOLS"
    $dump_result = Invoke-RestMethod -Uri $dump_url -Method GET -Headers @{"Authorization" = "Bearer $UltraDNS_token" }
    Write-Host -ForegroundColor Yellow "`n`t`tBelow are domain $dump_domain directional pool records.`n"      
    foreach ($owner in $dump_result.rrSets.ownerName) {
        $dump_pool_url = $ultradns_url + "zones/" + $dump_domain + "/rrsets/A/" + $owner
        $dump_pool_result = Invoke-RestMethod -Uri $dump_pool_url -Method GET -Headers @{"Authorization" = "Bearer $UltraDNS_token" } 
        $y = $dump_pool_result.rrSets.profile.rdataInfo.geoInfo.count
        for ($x = 0; $x -lt $y; $x++) {
            $dump_country_codes = $dump_pool_result.rrSets.profile.rdataInfo.geoInfo[$x].codes -join ","
            $dump_poolname = $dump_pool_result.rrSets.profile.rdataInfo.geoInfo.name[$x]
            $dump_ip = $dump_pool_result.rrSets.rdata[$x]
            $dump_ttl = $dump_pool_result.rrSets.profile.rdataInfo.ttl[$x]
            $dump_pool = "$dump_country_codes" + ':' + "$dump_poolname" + ':' + "$dump_ip" + ':' + "$dump_ttl" + ':' + "$owner" + ':' + "$dump_domain"
            Write-Host -ForegroundColor Cyan "$dump_pool"      
        }
    }
}

function UltraDNS_rollback_record {
    if ($zone_ransfer -eq 1) {
        Write-Host -ForegroundColor Cyan "This zone ransfer process so will not create a rollback record file."
        WriteLog -Message "[ log ] This zone ransfer process so will not create a rollback record file."
    } 
    else {
        Write-Host -ForegroundColor Cyan "Create a rollback record file."
        WriteLog -Message "[ log ] Create a rollback record file."
        $data_url = $ultradns_url + "zones/" + $domain + "./rrsets/" + $type + "/" + $record
        if ($action -eq "POST") {
            if ($isIPAddress -eq 1) {
                $old_destination = $destination
            }
            else {
                $old_destination = $destination -replace ".$"
            }
            $old_ttl = $TTL
            $old_action = "DELETE"
        } 
        elseif ($action -eq "DELETE") {
            $response = Invoke-RestMethod -Method GET -Uri $data_url -ContentType "application/json" -Headers @{"Authorization" = "Bearer $UltraDNS_token" }
            $old_ttl = $response.rrSets.ttl
            $old_destination = $response.rrSets.rdata
            if ($old_destination -as [IPAddress] -as [Bool]) {
                $old_destination = $old_destination
            }
            else {
                $old_destination = $old_destination -replace ".$"
            }
            $old_action = "POST"
        }  
        elseif ($action -eq "PATCH") {
            $response = Invoke-RestMethod -Method GET -Uri $data_url -ContentType "application/json" -Headers @{"Authorization" = "Bearer $UltraDNS_token" }
            $old_ttl = $response.rrSets.ttl
            $old_destination = $response.rrSets.rdata
            if ($old_destination -as [IPAddress] -as [Bool]) {
                $old_destination = $old_destination
            }
            else {
                $old_destination = $old_destination -replace ".$"
            }
            $old_action = "PATCH"
        }
        #Write-Host -ForegroundColor Cyan "$old_action,$type,$record,$old_destination,$domain,$old_ttl"
        "$old_action,$type,$record,$old_destination,$domain,$old_ttl" >> $rollback_file
    }
}

function UltraDNS_Modify_Record {
    if ($record -eq "@" ) {
        Write-Host -ForegroundColor Cyan "Will replace record $record to $domain"
        WriteLog -Message "[ log ] replace record $record to $domain"
        $record = $domain
        Start-Sleep -s 1
    }
    if ($destination -eq '@') {
        Write-Host -ForegroundColor Cyan "Will replace destination $destination to $domain"
        WriteLog -Message "[ log ] replace destination $destination to $domain"
        $destination = $domain
        Start-Sleep -s 1
    }
    if ($type -eq 'TXT') {
        $type = "16"
    }
    $modify_url = $ultradns_url + "zones/" + $domain + "./rrsets/" + $type + "/" + $record
    if ($destination -as [IPAddress] -as [Bool]) {
        #Write-Host $destination is IPAddress
        $isIPAddress = 1
    }
    else {
        $destination = $destination + "."
    }
    if ($type -eq 'A') {
        if ($destination -as [IPAddress] -as [Bool]) {
            #Write-Host $destination is IPAddress
            $isIPAddress = 1
        }
        else {
            Write-Host -ForegroundColor Red "The type A record destination should be the IP Address. This record to destination $destination will be filtered.`n"
            WriteLog -Message "[error] The type A record destination should be the IP Address. This record to destination $destination will be filtered."
            continue
        }
    }
    if ($type -eq 'MX') {
        $destination = "$priority" + " " + "$destination"
    }
    if ($type -eq 'SRV') {
        $destination = "$priority" + " " + "$weight" + " " + "$port" + " " + "$destination" + "$domain"
        $record = "$service" + "." + "$protocol" + "." + "$domain"
    } 
    $modify_body = @{
        "ttl"   = $TTL
        "rdata" = @("$destination")
    }
    if ($action -eq "POST") {
        $url_action = "Add"
    }
    elseif ($action -eq "PATCH") {
        $url_action = "Update"
    }
    elseif ($action -eq "DELETE") {
        $url_action = "Delete"
    }
    UltraDNS_rollback_record
    Write-Host -ForegroundColor Cyan "($action) Star $url_action type $type reocrd $record to/with $destination and TTL $TTL in UltraDNS domain $domain.`n"
    try {
        Invoke-RestMethod -Method $action -Uri $modify_url -Body (ConvertTo-Json $modify_body) -ContentType "application/json" -Headers @{"Authorization" = "Bearer $UltraDNS_token" }
    }
    catch {
        $errorStatus = Catch_It
    }
    finally {
        if ($errorStatus -eq 400) {
            Write-Host -ForegroundColor Red "($action) Try $url_action a type $type record $record to/with $destination and TTL $TTL in UltraDNS domain $domain fail"
            Write-Host -ForegroundColor Red "The record already exist or config data is wrong fromat`n"
            WriteLog -Message "[error] ($action) Try $url_action a type $type record $record to/with $destination and TTL $TTL in UltraDNS domain $domain fail"
        }
        elseif ($errorStatus -eq 404) {
            Write-Host -ForegroundColor Red "($action) Try $url_action a type $type record $record to/with $destination and TTL $TTL in UltraDNS domain $domain fail"
            Write-Host -ForegroundColor Red "The record not exist`n"
            WriteLog -Message "[error] ($action) Try $url_action a type $type record $record to/with $destination and TTL $TTL in UltraDNS domain $domain fail"
        }
        else {
            Write-Host -ForegroundColor Green "($action) $url_action a type $type record $record to/with $destination and TTL $TTL in UltraDNS domain $domain success`n"
            WriteLog -Message "[ log ] ($action) $url_action a type $type record $record to/with $destination and TTL $TTL in UltraDNS domain $domain success"
            Start-Sleep -s 1
        }
    }
    return 
}

function UltraDNS_Check_Record {
    $getdata = 1
    GoDaddyDNS_Get_Record $domain
    $Types = "A", "CNAME ", "MX", "16", "SRV"
    foreach ($i in $Types) {
        $record_num = 0
        $Check_url = $ultradns_url + "zones/" + $domain + "./rrsets/$i"
        try {
            $result = Invoke-RestMethod -Uri $Check_url -Method Get -Headers @{"Authorization" = "Bearer $UltraDNS_token" } | Select-Object rrSets
            $record_num = ($result.rrSets.rdata | Measure-Object | Select-Object Count ).count
        }
        catch {
            $errorStatus = Catch_It
        }
        finally {
            if ($i -eq "16") {
                $i = "TXT"
            }
            Start-Sleep -s 1
            Write-Host -ForegroundColor Green "$domain in UltraDNS have $i Type Record $record_num.`n"
            WriteLog -Message "[ log ] $domain in UltraDNS have $i Type Record $record_num."
        }
    }
}

function UltraDNS_Check_Domain_Expiration {
    Begin { 
        $url = $ultradns_url + "zones/" + $domain
        try {
            $result = Invoke-RestMethod -Uri $url -Method GET -Headers @{"Authorization" = "Bearer $UltraDNS_token" } 
            $result | ConvertTo-Json
        }
        catch {
            $errorStatus = Catch_It
        }
        finally {
            if ($errorStatus -eq 60001) {
                $UltraDNS_Login, $UltraDNS_token, $UltraDNS_AuthHeader = UltraDNS_Auth
            }
            #$domain = $domain -replace ".$"
            $doamin_date = $result.registrarInfo.whoisExpiration
            $now_date = (Get-Date).ToString("yyyy-MM-dd HH:MM:ssss")
        }
    }
    Process {
        if ($doamin_date) {
            $domain_expir_days = (NEW-TIMESPAN $doamin_date $now_date).Days
            $expir_days = - ($domain_expir_days)
            if ($domain_expir_days -gt 0) {
                if ($domain_expir_days -le 90) {
                    $domain_expir = 1
                    Write-Host -ForegroundColor Red "This domain $domain already expire $domain_expir_days days but not over 90 days."
                    WriteLog -Message "[ log ] This domain $domain already expire $domain_expir_days days but not over 90 days."
                    return $domain_expir
                }
                else {
                    $domain_expir = 1
                    Write-Host -ForegroundColor Red "This domain $domain already expire $domain_expir_days days."
                    WriteLog -Message "[ log ] This domain $domain already expire $domain_expir_days days."
                    return $domain_expir
                    
                }
            }
            else {
                $domain_expir = 0
                Write-Host -ForegroundColor Green "This domain $domain does not expire yet, there still have $expir_days days."
                WriteLog -Message "[ log ] This domain $domain does not expire yet, there still have $expir_days days."
                return $domain_expir
                
            }
        } 
        else {
            $domain_expir = 1
            Write-Host -ForegroundColor Red "This domain $domain could not get expiration info."
            WriteLog -Message "[error] This domain $domain could not get expiration info."
            return $domain_expir
            
        }
    }
    end {
        return $domain_expir
    }
}

function UltraDNS_Get_Domains {
    $domains = @()
    $get_url = $ultradns_url + "zones/"
    $result = Invoke-RestMethod -Uri $get_url -Method GET -Headers @{"Authorization" = "Bearer $UltraDNS_token" } 
    $y = $result.resultInfo.totalCount
    #$y = 50
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    for ($x = 1; $x -lt $y; $x = $x + 500) {
        #for ($x = 1; $x -lt $y; $x = $x + 50) {
        $process_time = $stopwatch.Elapsed.Minutes
        Write-Host -ForegroundColor yellow "The process running $process_time mins"
        if ($process_time -ge 5) {
            Write-Host -ForegroundColor Green "Need renew token"
            $UltraDNS_Login, $UltraDNS_token, $UltraDNS_AuthHeader = UltraDNS_Auth
            $stopwatch.Stop()
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        }
        $url = $ultradns_url + "zones/?limit=500&offset=" + $x
        #$url = $ultradns_url + "zones/?limit=" + $y + "&offset=" + $x
        $result = Invoke-RestMethod -Uri $url -Method GET -Headers @{"Authorization" = "Bearer $UltraDNS_token" } 
        $respon_domains = $result.zones.properties.name
        foreach ( $domain in $respon_domains) {
            $process_time = $stopwatch.Elapsed.Minutes
            if ($process_time -ge 5) {
                Write-Host -ForegroundColor Green "Renew token"
                $UltraDNS_Login, $UltraDNS_token, $UltraDNS_AuthHeader = UltraDNS_Auth
                $stopwatch.Stop()
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            }
            $domain = $domain -replace ".$"
            $domain_expir, $domain_expir = UltraDNS_Check_Domain_Expiration $domain
            #write-Host -ForegroundColor Green "domain_expir is $domain_expir"
            if ($domain_expir -eq 0) {
                $domains = $domains + $domain
                #Write-Host -ForegroundColor Green "Add domain $domain to list."
                WriteLog -Message "[ log ] Add domain $domain to list."
            }
            else {
                #Write-Host -ForegroundColor Red "Will not add domain $domain to list."
                WriteLog -Message "[ log ] Will not add domain $domain to list."
                "$domain,$domain_expir_days" >> $domain_expir_file
            }
        }
    }
    return $domains
}

function UltraDNS_Get_Domain_Records {
    $process_time = $stopwatch.Elapsed.Minutes
    if ($process_time -ge 5) {
        Write-Host -ForegroundColor Green "Renew token"
        $UltraDNS_Login, $UltraDNS_token, $UltraDNS_AuthHeader = UltraDNS_Auth
        $stopwatch.Stop()
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    }
    $UltraDNS_Records = @()
    $types = "A", "CNAME"
    foreach ($i in $types) {
        $record_num = 0
        $url = $ultradns_url + "zones/" + $domain + "./rrsets/$i"
        try {
            $result = Invoke-RestMethod -Uri $url -Method GET -Headers @{"Authorization" = "Bearer $UltraDNS_token" } #-ContentType "application/x-www-form-urlencoded"
            $record_num = ($result.rrSets.rdata | Measure-Object | Select-Object Count ).count
            $Records = $result.rrSets.ownerName
        }
        catch {
            $errorStatus = Catch_It
        }
        finally {
            Write-Host -ForegroundColor Green "Domain $domain in UltraDNS have $i Type Record $record_num.`n"
            WriteLog -Message "[ log ] Domain $domain in UltraDNS have $i Type Record $record_num."
            $UltraDNS_Records = $UltraDNS_Records + $Records
        }
    }
    return $UltraDNS_Records , $record_num
}

function UltraDNS_Check_Domain_SSl_Status {
    Begin { 
        $ssl_expdays = ""
        # Don't stop at errors
        $ErrorActionPreference = 'silentlycontinue'
        # Allow 10 secs timeout 
        $timeoutInMilliseconds = 10000
        # Construct URL to check
        $URL = "https://$record"
        # Get current date and time
        $now = Get-Date
        # Disable certificate validation check
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
    Process {
        try {
            $request = [System.Net.WebRequest]::Create($URL)
            [System.Net.WebResponse] $response = $request.GetResponse();
        }
        catch {
            $errorStatus = Catch_It
        }
        finally {
            if ($response.StatusCode -eq "200" -or $response.StatusCode -eq "OK") {
                # Get certificate expiration date and time
                $ssl_expdate_time = $request.ServicePoint.Certificate.GetExpirationDateString()
                # Now get days remaining
                $ssl_expdays = (New-TimeSpan -Start $now -End $ssl_expdate_time).Days
                Write-Host -ForegroundColor Green "Site - $URL is up (Return code: $($response.StatusCode) - $([int] $response.StatusCode))"
                if ($ssl_expdays -lt 0) {
                    $expdays = - ($ssl_expdays)
                    Write-Host -ForegroundColor Red "Site - $URL SSL certificate already expired $expdays days"
                    "$URL,$ssl_expdays" >> $ssl_expir_file
                }
                else {
                    # Print Message
                    Write-Host -ForegroundColor Green "`Site - $URL SSL certificate still hvae $ssl_expdays days expire"
                    "$URL,$ssl_expdays" >> $ssl_domain_file
                }
            }
            else {
                Write-Host -ForegroundColor Red "Site - $URL is not accessible."
                $URL >> $ssl_fail_connect_file
            }
        }
    }
    End {
    }
}

function Main_Menu {
    $mainMenu = 'X'
    while ($mainMenu -ne '') {
        Clear-Host
        $security_file = ".\security.ini"
        $valid_ini = Test-Path $security_file
        if ($valid_ini) {
            $security_content = Get-Content $security_file | ConvertFrom-Json
            $ultradns_secureID = $security_content.UltraDNS.secureID
            $ultradns_securePwd = $security_content.UltraDNS.securePwd | ConvertTo-SecureString -Key (1..16)
            if ($ultradns_securePwd) {
                $ultradns_plainPwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ultradns_securePwd))
            } 
            else {
                Write-Host -ForegroundColor Red "`n Wrong format security file"
                $security = 0
            }
            $ini_godaddy_api_key = $security_content.GoDaddy.api_key
            $ini_godaddy_secret = $security_content.GoDaddy.api_secret | ConvertTo-SecureString -Key (1..16)
            if ($ini_godaddy_secret) {
                $ini_gogaddy_api_secret = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ini_godaddy_secret))
                $security = 1
            } 
            else {
                Write-Host -ForegroundColor Red "`n Wrong format security file"
                $security = 0
            }
            
        } 
        else {
            $security = 0
        }
        Write-Host -ForegroundColor Green "`n`t`t This is UltraDNS and Godaddy DNS records modify script`n"
        Write-Host -ForegroundColor Cyan "Main Menu"
        Write-Host -ForegroundColor Yellow -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor Yellow -NoNewline "]"; `
            Write-Host -ForegroundColor Yellow -NoNewline " Modify UltraDNS testing portal DNS records "; Write-Host -ForegroundColor Red -NoNewline "(test-api.ultradns.com)"
        Write-Host -ForegroundColor Yellow -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor Yellow -NoNewline "]"; `
            Write-Host -ForegroundColor Yellow -NoNewline " Modify UltraDNS production portal DNS records "; Write-Host -ForegroundColor Red "(api.ultradns.com) "
        Write-Host -ForegroundColor Gray "`n`t`t[ Suggestion running process in testing portal first ]"
        $mainMenu = Read-Host "`nSelection (leave blank to quit)"
        $ValidPath = Test-Path .\logfiles
        If ($ValidPath -ne $True) {
            New-Item -Path . -Name "logfiles" -ItemType "directory"
        }
        $FileName = Get-Date -Format "yyyy_MM_dd_HHMMss"
        $rollback_file = ".\logfiles\" + $FileName + "_" + "rollback_record" + ".txt"
        $rollback_pool_file = ".\logfiles\" + $FileName + "_" + "rollback_pool_record" + ".txt"
        $LogFile = ".\logfiles\" + $FileName + ".log"
        $JsonFile = ".\logfiles\" + $FileName
        $domain_expir_file = ".\logfiles\" + $FileName + "_" + "domain_expir" + ".txt"
        $ssl_domain_file = ".\logfiles\" + $FileName + "_" + "ssl_domain" + ".txt"
        $ssl_expir_file = ".\logfiles\" + $FileName + "_" + "ssl_expir" + ".txt"
        $ssl_fail_connect_file = ".\logfiles\" + $FileName + "_" + "ssl_expir" + ".txt"
        #running by choose URL
        if ($mainMenu -eq 1) {
            $ultradns_url = "https://test-api.ultradns.com/"
            $ultradns = "UltraDNS testing API"
            $GoDaddy_Menu = 0
            if ($security -eq 1) {
                Write-Host -ForegroundColor Gray "`n`t`t Will use security.ini file info login! `n"
                $UltraDNS_Login, $UltraDNS_token, $UltraDNS_AuthHeader = UltraDNS_Auth
            } 
            else {
                $UltraDNS_Login, $UltraDNS_token, $UltraDNS_AuthHeader = UltraDNS_Auth
            }
            WriteLog -Message "[info ] This process is running in $url by account $ultradns_secureID"
            $zone_ransfer = ""
            if ($UltraDNS_Login -eq 0) { 
                Start-Sleep -s 3
                continue 
            }
            $domain = ''
            Start-Sleep -s 3
            subMenu
        }
        if ($mainMenu -eq 2) {
            $ultradns_url = "https://api.ultradns.com/"
            $ultradns = "UltraDNS production API"
            $GoDaddy_Menu = 1
            if ($security -eq 1) {
                Write-Host -ForegroundColor Gray "`n`t`tWill use security.ini file info login!"
                $UltraDNS_Login, $UltraDNS_token, $UltraDNS_AuthHeader = UltraDNS_Auth
            } 
            else {
                $UltraDNS_Login, $UltraDNS_token, $UltraDNS_AuthHeader = UltraDNS_Auth
            }
            WriteLog -Message "[info ] This process is running in $ultradns_url by account $ultradns_secureID"
            if ($UltraDNS_Login -eq 0) { 
                Start-Sleep -s 3
                continue 
            }
            $domain = ''
            Start-Sleep -s 3
            subMenu
        }
        if ($mainMenu -eq "ini") {
            $security_ini = @{ }
            $ultradns_secureID = Read-Host "`nPlease Enter Your UltraDNS ID"
            $ultradns_securePwd = Read-Host "Please Enter Your UltraDNS password" -AsSecureString
            $ultradns_encrypted = ConvertFrom-SecureString -SecureString $ultradns_securePwd -Key (1..16)
            $ultradns_data = @{"secureID" = "$ultradns_secureID"; "securePwd" = "$ultradns_encrypted"; }
            Write-Host -ForegroundColor Gray "`n`t`t[ Wrtie UltraDNS login info to security.ini ]`n"
            $godaddy_api_key = Read-Host "`nPlease Enter Your GoDaddy API_Key"
            $godaddy_secret = Read-Host "Please Enter Your GoDaddy API Secret" -AsSecureString
            $gogaddy_encrypted = ConvertFrom-SecureString -SecureString $godaddy_secret -Key (1..16)
            $godaddy_data = @{"api_key" = "$godaddy_api_key"; "api_secret" = "$gogaddy_encrypted"; }
            $security_ini.Add("UltraDNS", $ultradns_data)
            $security_ini.Add("GoDaddy", $godaddy_data)
            Write-Host -ForegroundColor Gray "`n`t`t[ Wrtie GoDaddy login API info to security.ini ]"
            $security_ini | ConvertTo-Json -Depth 10 | Out-File ".\security.ini"
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
    }
}


function subMenu {
    $subMenu1 = 'X'
    while ($subMenu1 -ne '') {
        Clear-Host
        Write-Host -ForegroundColor Green "`n`t`t Running tasks by $ultradns ($ultradns_url)`n"
        Write-Host -ForegroundColor Cyan "Process Menu"
        Write-Host -ForegroundColor Yellow -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor Yellow -NoNewline "]"; `
            Write-Host -ForegroundColor Yellow -NoNewline " Process "; Write-Host "UltraDNS DNS records modify" -ForegroundColor White -NoNewline; Write-Host -ForegroundColor Yellow " Tasks"
        Write-Host -ForegroundColor Yellow -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor Yellow -NoNewline "]"; `
            Write-Host -ForegroundColor Yellow -NoNewline " Process "; Write-Host "UltraDNS DNS Directional Pool Records query" -ForegroundColor White -NoNewline; Write-Host -ForegroundColor Yellow " Tasks"		
        Write-Host -ForegroundColor Yellow -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor Yellow -NoNewline "]"; `
            Write-Host -ForegroundColor Yellow -NoNewline " Process "; Write-Host "UltraDNS DNS Directional Pool Records modify" -ForegroundColor White -NoNewline; Write-Host -ForegroundColor Yellow " Tasks"		
        Write-Host -ForegroundColor Yellow -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor Yellow -NoNewline "]"; `
            Write-Host -ForegroundColor Yellow -NoNewline " Process "; Write-Host "UltraDNS DNS Directional Pool Group Name modify" -ForegroundColor White -NoNewline; Write-Host -ForegroundColor Yellow " Tasks"		
        Write-Host -ForegroundColor Yellow -NoNewline "`n["; Write-Host -NoNewline "5"; Write-Host -ForegroundColor Yellow -NoNewline "]"; `
            Write-Host -ForegroundColor Yellow -NoNewline " Process "; Write-Host "Clean UltraDNS Zone which already expired in GoDaddy" -ForegroundColor White -NoNewline; Write-Host -ForegroundColor Yellow " Tasks"		
        Write-Host -ForegroundColor Yellow -NoNewline "`n["; Write-Host -NoNewline "6"; Write-Host -ForegroundColor Yellow -NoNewline "]"; `
            Write-Host -ForegroundColor Yellow -NoNewline " Process "; Write-Host "Copy DNS Records from GoDaddy to UltraDNS" -ForegroundColor White -NoNewline; Write-Host -ForegroundColor Yellow " Tasks"
        Write-Host -ForegroundColor Yellow -NoNewline "`n["; Write-Host -NoNewline "7"; Write-Host -ForegroundColor Yellow -NoNewline "]"; `
            Write-Host -ForegroundColor Yellow -NoNewline " Process "; Write-Host "Check UltraDNS domains' records SSL status by file" -ForegroundColor White -NoNewline; Write-Host -ForegroundColor Yellow " Tasks"
        Write-Host -ForegroundColor Yellow -NoNewline "`n["; Write-Host -NoNewline "8"; Write-Host -ForegroundColor Yellow -NoNewline "]"; `
            Write-Host -ForegroundColor Yellow -NoNewline " Process "; Write-Host "Check all UltraDNS domains' records SSL status" -ForegroundColor White -NoNewline; Write-Host -ForegroundColor Yellow " Tasks"
        if ($GoDaddy_Menu -eq 1) {
            Write-Host -ForegroundColor Yellow -NoNewline "`n["; Write-Host -NoNewline "9"; Write-Host -ForegroundColor Yellow -NoNewline "]"; `
                Write-Host -ForegroundColor Yellow -NoNewline " Process "; Write-Host "Change GoDaddy Name Server(NS) Records to UltraDNS" -ForegroundColor White -NoNewline; Write-Host -ForegroundColor Yellow " Tasks"
        }
        $subMenu1 = Read-Host "`nSelection (leave blank to quit)"
        if ($subMenu1 -eq 1) {
            $zone_ransfer = 0
            Write-Host -ForegroundColor Green "`n`t`tModify UltraDNS DNS records.`n"
            $File_Exists, $File_Path = Check_file "Please enter the file name which you want to process"
            if ($File_Exists -eq 0) {
                Start-Sleep -s 2
                continue
            }
            else {
                Write-Host -ForegroundColor Green "`nProcess modify UltraDNS Record from file $File_Path."
                WriteLog -Message "[info ] Srat modify DNS records frome file $File_Path"
                UltraDNS_Process_Record $File_Path
                Write-Host "`nPress any key to return to the previous menu"
                [void][System.Console]::ReadKey($true)
            }
        }
        if ($subMenu1 -eq 2) {
            Write-Host -ForegroundColor Green "`n`t`tQuery UltraDNS specific domain directional pool records.`n"
            $dump_domain = Read-Host "`nWhich domain you want query directional pool records"
            UltraDNS_dump_pool $dump_domain
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
            
        }
        if ($subMenu1 -eq 3) {
            Write-Host -ForegroundColor Green "`n`t`tUltraDNS DNS Directional Pool records modify.`n"
            $File_Exists, $File_Path = Check_file "Please enter the file name which you want to process"
            if ($File_Exists -eq 0) {
                Start-Sleep -s 2
                continue
            }
            else {
                Write-Host -ForegroundColor Green "`nProcess modify UltraDNS Directional Pool records from file $File_Path.."
                WriteLog -Message "[info ] Srat DNS Directional Pool Records modify frome file $File_Path"
                UltraDNS_Modify_DIR_Pool $File_Path
                Write-Host "`nPress any key to return to the previous menu"
                [void][System.Console]::ReadKey($true)
            }
        }
        if ($subMenu1 -eq 4) {
            Write-Host -ForegroundColor Green "`n`t`tUltraDNS DNS Directional Pool name modify.`n"
            $File_Exists, $File_Path = Check_file "Please enter the file name which you want to process"
            if ($File_Exists -eq 0) {
                Start-Sleep -s 2
                continue
            } 
            else {
                Write-Host "`nProcess modify UltraDNS Directional Pool name by file $File_Path."
                WriteLog -Message "[info ] Srat DNS Directional Pool name modify by file $File_Path"
                foreach ($domain in Get-Content $File_Path) {
                    UltraDNS_Modify_DIR_Name $domain
                }
                Write-Host "`nPress any key to return to the previous menu"
                [void][System.Console]::ReadKey($true)
            }
            
        }
        if ($subMenu1 -eq 5) {
            Write-Host -ForegroundColor Green "`n`t`tClean UltraDNS Zone which already expired in GoDaddy.`n"
            $GoDaddy_Login, $godaddy_api_key, $gogaddy_api_secret, $godaddy_headers = GoDaddy_Auth $ini_godaddy_api_key $ini_gogaddy_api_secret
            if ($GoDaddy_Login -eq 0) {
                Start-Sleep -s 2
                continue
            }
            $File_Exists, $File_Path = Check_file "Please enter the file name which you want to process"
            if ($File_Exists -eq 0) {                
                Start-Sleep -s 2
                continue
            } 
            else {
                $check_status = 1
                WriteLog -Message "[info ] Start Clean UltraDNS Zone which already expired in GoDaddy by file $File_Path"
                foreach ($domain in Get-Content $File_Path) {
                    $GoDaddy_expired = GoDaddyDNS_Check_Domain_Status $domain
                    if ($GoDaddy_expired -eq 1) {
                        $UltraDNS_Zone_Status = UltraDNS_Check_Zone $domain
                        if ($UltraDNS_Zone_Status -eq 1) {
                            UltraDNS_Delete_Zone
                        }
                    }
                    else {
                        Write-Host -ForegroundColor Red "The Doamin $domain not expired in GoDaddy"
                        WriteLog -Message "[info ] The Doamin $domain not expired in GoDaddy"
                    }                
                }
                Write-Host "`nPress any key to return to the previous menu"
                [void][System.Console]::ReadKey($true)
            }
        }
        if ($subMenu1 -eq 6) {
            $zone_ransfer = 1
            Write-Host -ForegroundColor Green "`n`t`tCopy DNS records from GoDaddy to UltraDNS.`n"
            $GoDaddy_Login, $godaddy_api_key, $gogaddy_api_secret, $godaddy_headers = GoDaddy_Auth $ini_godaddy_api_key $ini_gogaddy_api_secret
            if ($GoDaddy_Login -eq 0) {
                Start-Sleep -s 2
                continue
            }
            $File_Exists, $File_Path = Check_file "Please enter the file name which you want to process"
            if ($File_Exists -eq 0) {    
                Start-Sleep -s 2
                continue
            } 
            else {
                WriteLog -Message "[info ] Start copy DNS records from GoDaddy by file $File_Path"
                foreach ($domain in Get-Content $File_Path) {
                    $getdata = 0
                    UltraDNS_Check_Zone $domain
                    $GoDaddy_Migrated = UltraDNS_Check_TXT $domain
                    if ($GoDaddy_Migrated -eq 1) {
                        continue
                    }
                    $records, $NoRecords = GoDaddyDNS_Get_Record $domain
                    if ($NoRecords -eq 1) {
                        continue
                    }
                    else {
                        UltraDNS_Process_Record $records
                        UltraDNS_Check_Record $domain
                    }
                }
                Write-Host "`nPress any key to return to the previous menu"
                [void][System.Console]::ReadKey($true)
            }
        }
        if ($subMenu1 -eq 9) {
            if ($GoDaddy_Menu -ne 1) {
                continue
            }
            Write-Host -ForegroundColor Green "`n`t`tChange GoDaddy domain NS records to UltraDNS.`n"
            $GoDaddy_Login, $godaddy_api_key, $gogaddy_api_secret, $godaddy_headers = GoDaddy_Auth $godaddy_api_key $gogaddy_api_secret
            if ($GoDaddy_Login -eq 0) {
                Start-Sleep -s 2
                continue
            }
            $File_Exists, $File_Path = Check_file "Please enter the file name which you want to process"
            if ($File_Exists -eq 0) {
                Start-Sleep -s 2
                continue
            }
            else {
                $zone_ransfer = 1
                $add_txt = 0
                WriteLog -Message "[info ] Start transfer DNS records from GoDaddy by file $File_Path"
                foreach ($domain in Get-Content $File_Path) {
                    UltraDNS_Check_Zone $domain
                    $GoDaddy_Migrated = UltraDNS_Check_TXT $domain
                    if ($GoDaddy_Migrated -eq 1) {
                        continue
                    } 
                    GoDaddyDNS_Modify_Record $domain
                }
                Write-Host "`nPress any key to return to the previous menu"
                [void][System.Console]::ReadKey($true)
            }
        }
        if ($subMenu1 -eq 7) {
            $domain_expir = ""
            $records = @()
            $File_Exists, $File_Path = Check_file "Please enter the file name which you want to process"
            if ($File_Exists -eq 0) {                
                Start-Sleep -s 2
                continue
            } 
            else {
                WriteLog -Message "[info ] Start check UltraDNS domains SSL status by file $File_Path"
                foreach ($domain in Get-Content $File_Path) {
                    $UltraDNS_Records, $record_num = UltraDNS_Get_Domain_Records $domain
                    if ($record_num) {
                        foreach ($record in $UltraDNS_Records) {
                            $record = $record.Substring(0, $record.Length - 1)
                            Write-Host -ForegroundColor Green "Add record $record to list."
                            $records = $records + $record
                        }
                        $records_num = ($records | Measure-Object | Select-Object Count ).count
                        Write-Host -ForegroundColor Green "There have $records_num records in the list."
                        Write-Host -ForegroundColor Green "Start to check these records SSL status."
                        foreach ($record in $records) {
                            UltraDNS_Check_Domain_SSl_Status $record
                        }
                        Write-Host -ForegroundColor Green "There have $records_num records in the list."
                    }
                    else {
                        Write-Host -ForegroundColor Red "There is no records in this domain."
                    }
                }
            }

            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        if ($subMenu1 -eq 8) {
            $domain_expir = ""
            $records = @()
            WriteLog -Message "[info ] Start check UltraDNS all domains SSL status"
            $domains = UltraDNS_Get_Domains
            foreach ($domain in $domains) {
                $UltraDNS_Records, $record_num = UltraDNS_Get_Domain_Records $domain
                if ($record_num) {
                    foreach ($record in $UltraDNS_Records) {
                        $record = $record.Substring(0, $record.Length - 1)
                        Write-Host -ForegroundColor Green "Add record $record to list."
                        $records = $records + $record
                    }
                }
                else {
                    Write-Host -ForegroundColor Red "There is no records in this domain."
                }
            }
            $records_num = ($records | Measure-Object | Select-Object Count ).count
            Write-Host -ForegroundColor Green "There have $records_num records in the list."
            Write-Host -ForegroundColor Green "Start to check these records SSL status."
            foreach ($record in $records) {
                UltraDNS_Check_Domain_SSl_Status $record
            }
            Write-Host -ForegroundColor Green "There have $records_num records in the list."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
    }
}

if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host -ForegroundColor Green "`n`t`tThis script needs PowerShell 5.1 higher version.`n"
    $PSVersionTable
} 
else {
    Main_Menu
}