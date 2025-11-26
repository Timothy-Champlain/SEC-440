clear

function compress-directory([string]$dir, [string]$output)
{
    $ddf = ".OPTION EXPLICIT
.Set CabinetNameTemplate=$output
.Set DiskDirectory1=.
.Set CompressionType=MSZIP
.Set Cabinet=on
.Set Compress=on
.Set CabinetFileCountThreshold=0
.Set FolderFileCountThreshold=0
.Set FolderSizeThreshold=0
.Set MaxCabinetSize=0
.Set MaxDiskFileCount=0
.Set MaxDiskSize=0
"
    $dirfullname = (get-item $dir).fullname
    $ddfpath = ($env:TEMP+"\temp.ddf")
    $ddf += (ls -recurse $dir | where { !$_.PSIsContainer } | select -ExpandProperty FullName | foreach { '"' + $_ + '" "' + ($_ | Split-Path -Leaf) + '"' }) -join "`r`n"
    $ddf
    $ddf | Out-File -Encoding UTF8 $ddfpath
    makecab.exe /F $ddfpath
    rm $ddfpath
    rm setup.inf
    rm setup.rpt
} <# credit to Jerry Cote on Stack Overflow https://stackoverflow.com/questions/19411440/makecab-create-a-cab-file-from-all-the-files-in-a-folder #>

$commands=@(
    'whoami' # List current authenticated user
    'whoami /priv' # Enumerate the privileges of the authenticated user
    'hostname' # Enumerate the hostname
    'netstat -n' # List all network sockets
    'netstat -s' # List network statistics for protocols used
    'netstat -b' # List the full path to executables listening on each network socket
    'Get-Process | Select-Object ProcessName' # List all running processes (powershell, cmd)
    'Get-Process | Format-List Path' # List all running processes and the full path they are running from
    'Get-Process -IncludeUserName | Select-Object -Property Username, ProcessName' # Enumerate the user that owns the process
    'Get-Process | Select-Object -Property ProcessName, Modules | Format-Table -Wrap -Autosize' # List all loaded modules with running processes
    '$processes = Get-Process | Select-Object ProcessName;$eater = ""; foreach($badname in $processes){$atless = $badname -replace "@{ProcessName=", ""; $goodname = $atless -replace "}"; if($eater -eq $goodname){$bestname = ""} else{$bestname = "*"+$goodname+"*"; $eater = $goodname} get-wmiobject Win32_Service | where-object {$_.PathName -ilike "$bestname"} | Select Name}' # List all Services associated with running processes and yes I'm doing fantastic how are you?
    'net accounts' # Enumerate the password policies
    'net user' # Enumerate all users
    'Get-LocalGroup' # Enumerate all groups
    '$groups = Get-LocalGroup | Select-Object Name; foreach($guh in $groups){$gwah = $guh -replace "@{Name=", ""; $gwahgwah = $gwah -replace "}", ""; Get-LocalGroupMember -Group $gwahgwah}' # Enumerate all users in each group
    'Get-Service' # Enumerate all registered services
    'Get-Service | Where-Object {$_.Status -eq "Running"}' # Enumerate all running services
    'Get-Service | Where-Object {$_.Status -eq "Stopped"}' # Enumerate all stopped services
    '$services = Get-Service | Select-Object Name; foreach($foo in $services){$bar = $foo -replace "@{Name=", ""; $foobar = $bar -replace "}"; $barfoo = "*"+$foobar+"*"; get-wmiobject Win32_Service | where-object {$_.Name -ilike "$barfoo"} | select Name, PathName | Format-Table -Wrap -Autosize}' # Enumerate the full path of the executable for all registered services (running or stopped)
    '$ProgFiles = Get-ChildItem -Directory "C:\Program Files" | Select-Object Name; foreach($wee in $ProgFiles){$woo = $wee -replace "@{Name=", ""; $weewoo = $woo -replace "}", ""; Get-Acl "C:\Program Files\$weewoo"}' # Enumerate the permissions for each folder under Program Files
    'Get-Acl C:\Users\Public' # Enumerate the permissions for the folder C:\Users\Public
    'Get-Acl C:\ProgramData' # Enumerate the permissions for the folder C:\ProgramData
    'Get-ScheduledTask' # Enumerate all scheduled tasks
    'systeminfo' # Enumerate system information about the Windows host (this command will list a lot of details about the host)
    'tree C:\' # Generate a tree outline of the c:\ drive. (Hint: The command is on this line.)
    #'' # After compressing with the makecab command, show that you can decompress it and show the decompressed file. (this is done outside the array)
    )

foreach($i in $commands){
    $j = $i -replace '\s',''
    $k = $j -replace '/',''
    $l = $k -replace ':', ''
    $m = $l -replace '"', ''
    $n = $m -replace '\|', ''
    $o = $n -replace '_\.', ''
    $p = $o -replace '\\', ''
    $q = $p -replace '\*', ''
    $count = $q.length
    if($count -gt 215){
        $subtractor = $count - 215
        $r = $q -replace ".{$subtractor}$"
    }
    else{
        $r = $q
    }
    Invoke-Expression $i | Tee-Object -FilePath "C:\Users\IEUser\Baselines\Tim_enumerate-$r.txt"
    Write-Host "_______________________________________________________________________"
    Write-Host ""
}

compress-directory C:\Users\IEUser\Baselines .\Tim_Enumerate.cab

move-item -Path .\Tim_Enumerate.cab -Destination C:\Users\IEUser\Baselines\Tim_Enumerate.cab -Force

