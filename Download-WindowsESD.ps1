# Parse Params:
[CmdletBinding()]
Param(
    [Parameter(
        Position=1,
        Mandatory=$False
        )]
        [ValidateNotNull()]
        [string]$Path = "C:\Temp\ESDDownloader",
    [Parameter(
        Position=2,
        Mandatory=$False
        )]
        [ValidateSet('Win10', 'Win11', 'Server2016', 'Server2019', 'Server2022', 'Server2025')]
        [string]$OSVer = "Win11",
    [Parameter(
        Position=3,
        Mandatory=$False
        )]
        [ValidateSet('x64', 'ARM64', 'AMD64', 'ARM')]
        [string]$Arch = "x64",
    [Parameter(
        Position=4,
        Mandatory=$False
        )]
        [ValidateNotNull()]
        [string]$Lang = "en-us"
    )


#Requires -RunAsAdministrator


# Get script start time (will be used to determine how long execution takes)
$Script_Start_Time = (Get-Date).ToShortDateString()+", "+(Get-Date).ToLongTimeString()

# Warn the user - this script was cobbled together from functions in other unrelated scripts in ~30 minutes on a whim and edited once just to add Server ISO support, so only the most basic error handling is here
Clear-Host
Write-Host "If downloading a Windows client ESD, this script *requires* the Windows 10/11 ADK and 7Zip to be installed (due to issues with products.cab downloaded from Microsoft)." -ForegroundColor Yellow
Write-Host "This script also only works on ESD files that contain images that can be parsed as 'Pro' or 'Enterprise' in this scenario." -ForegroundColor Yellow
Write-Host "Please feel free to fork or submit a fix if you want to change that." -ForegroundColor Gray
Write-Host ""
Write-Host "Please press BREAK/CTRL+C to exit within the next 10 seconds if you do not meet both of the pre-requisites or this script will fail." -ForegroundColor Cyan
Write-Host ""
Start-Sleep 10

# Normalize architecture strings
If ($Arch -eq 'AMD64')
{
    $Arch = 'x64'
}
ElseIf ($Arch -eq 'ARM')
{
    $Arch = 'ARM64'
}

# If Server, validate languages/architecture actually available are chosen
If ($OSVer -like "Server*")
{
    $ServerLang = @(
        "en-us",
        "zh-cn",
        "fr-fr",
        "de-de",
        "it-it",
        "ja-jp",
        "ru-ru",
        "es-es"
    )

    If ($Arch -eq 'ARM64')
    {
        Write-Host "ARM64 Server ISOs are not currently available for download.  Please retry with 'x64' or 'AMD64' as the architecture, exiting script." -ForegroundColor Yellow
        EXIT
    }

    If ($ServerLang -notcontains $Lang)
    {
        Write-Host "You have chosen to download $($OSVer) but have not chosen a valid language code.  Please retry with a valid language code, exiting script." -ForegroundColor Yellow
        Write-Host "Valid language codes:" -ForegroundColor Magenta
        ForEach ($Language in $ServerLang)
        {
            Write-Host $Language -ForegroundColor Green
        }
        EXIT
    }
}


# Script wide variables used by *-Log functions:
$TimeStamp = [System.DateTime]::Now.ToString("yyyy-MM-dd_HH-mm-ss")
$LogFile = $env:TEMP + "\" + $env:COMPUTERNAME + "__" + $TimeStamp + "__Download-WindowsESD.log"
$Script:ConsoleOutput = $True
$Script:ForegroundColor = "White"

# Enable or disable console output through Write-Host/Write-Output when calling Write-Log
# Useful for calling PowerShell script when no console is available
Function Set-ConsoleOutput
{
    Param
    (
        [Bool]$Enable = $True
    )

    [Bool]$Script:ConsoleOutput = $Enable
}

# Start logging to the file name specified when Write-Log is called
Function Start-Log
{
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.String]$LogFile
    )

    [String]$Script:LogFile = $LogFile
    Write-Host "Log file is located at $($Script:LogFile)."
}

# Stop logging to file when Write-Log is called
Function Stop-Log
{
    Param()
    
    [String]$Script:LogFile = [System.String]::Empty
}

# Get the current log file used by Write-Log
Function Get-Log
{
    Param()

    Return [String]$Script:LogFile
}

# Log messages to host console and to a log file if specified
# Note: You can't use Write-Host if invoking wihtout a PowerShell console
Function Write-Log
{
    Param
    (
        [Parameter(Mandatory = $false)]
        [String]$Message,

        [Parameter(Mandatory = $false)]
        [String]$LogFile = $Script:LogFile,
        
        [Parameter(Mandatory = $false)]
        [Boolean]$ConsoleOutput = $Script:ConsoleOutput,

        [Parameter(Mandatory = $false)]
        [String]$ForegroundColor = $Script:ForegroundColor
    )

    If (!(Test-Path -Path "$LogFile"))
    {
        Start-Log -LogFile $LogFile
    }

    $Message = $Message + $Input
    If ($Message -ne $null -and $Message.Length -gt 0)
    {
        $TimeStamp = [System.DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
        If ($LogFile -ne $null -and $LogFile -ne [System.String]::Empty)
        {
            Try
            {
                Out-File -Append -FilePath $LogFile -InputObject "[$TimeStamp] $Message" -Encoding unicode -Force
            }
            Catch
            {
                Write-Warning "[$TimeStamp] Error: $_"
            }
        }
        If ($ConsoleOutput -eq $true)
        {
            Write-Host "$Message" -ForegroundColor $ForegroundColor
        }
        Write-Verbose "[$TimeStamp] $Message"
    }
}


# If path does not exist, create it - if it exists, potentially delete it
Function Check-PathExists
{
    Param(
        [String]$Path,
        [Bool]$DeleteIfExists = $False
    )

    If (!(Test-Path $Path))
    {
        Write-Log -Message "$($Path) does not exist.  Creating..."
        Write-Host ""
        Try
        {
            New-Item -Path "$Path" -ItemType Directory | Out-Null
        }
        Catch
        {
            Write-Log -Message "[$TimeStamp] Error: $_"
        }
    }
    ElseIf ((Test-Path "$Path") -and ($DeleteIfExists -eq $True))
    {
        Write-Log -Message "Deleting contents of $($Path)..."
        Write-Host ""
        Try
        {
            Get-ChildItem -Path "$Path" -Recurse | Remove-Item -Force -Recurse
        }
        Catch
        {
            Write-Log -Message "Error: $_"
        }
    }
}


# Fun with file extraction - some systems seem to fail to expand the .CAB file (TODO on root cause) and 7zip does work where expand does not
Function Extract-File
{
    Param
    (
        $File,
        $Path
    )

    $Path = $Path + "\Extract"
    Check-PathExists -Path $Path -DeleteIfExists $True
    $FileExtension = [System.IO.Path]::GetExtension("$File")
    Write-Log -Message "Extracting file $($File) to $($Path)..."
    Write-Log  " "
    If ($FileExtension -eq '.msi')
    {
        Try
        {
            Start-Process "msiexec" -ArgumentList "/a $File /qn TARGETDIR=$Path" -Wait -WindowStyle Hidden
            Write-Log -Message "Completed extraction to $Path."
        }
        Catch
        {
            Write-Log -Message "Error: $_"
        }
    }
    ElseIf ($FileExtension -eq '.cab')
    {
        $7z = "C:\Program Files\7-Zip\7z.exe"
        If (Test-Path $7z)
        {
            $Exe = $7z
            $argumentList = "x $File -o$($Path)"
        }
        Else
        {
            $Exe = "$env:WINDIR\System32\expand.exe"
            $argumentList = '-F:*' + " " + $File + " " + $Path
        }
        Try
        {
            Start-Process -FilePath $Exe -ArgumentList $argumentList -Wait -WindowStyle Hidden
            Write-Log -Message "Completed extraction to $Path."
            Write-Log " "
        }
        Catch
        {
            Write-Log -Message "Error: $_"
        }
        
    }
    ElseIf ($FileExtension -eq '.zip')
    {
        Try
        {
            Expand-Archive -Path $File -DestinationPath $Path
            Write-Log -Message "Completed extraction to $Path."
            Write-Log " "
        }
        Catch
        {
            Write-Log -Message "Error: $_"
        }
    }
}


# Turn redirect URLs into their actual URL
Function Get-RedirectedUrl
{
    Param(
        $URL
    )

    $Request = [System.Net.WebRequest]::Create($URL)
    $Request.AllowAutoRedirect=$false
    $Request.Timeout = 3000
    $Response = $Request.GetResponse()

    If ($Response.ResponseUri)
    {
        $Response.GetResponseHeader("Location")
    }
    $Response.Close()
}


# Download a file from a URL
Function Download-File
{
    Param(
        [Uri]$URL,
        [String]$Path
    )

    # Get file name
    Start-Sleep 1
    If ($URL.Host -like "*aka.ms*")
    {
        $ActualURL = Get-RedirectedUrl -URL "$URL" -ErrorAction Continue -WarningAction Continue
        $FileName = $ActualURL.Substring($ActualURL.LastIndexOf("/") + 1)
    }
    Else
    {
        $ActualURL = $URL
        $FileName = $URL.AbsoluteUri.Substring($URL.AbsoluteUri.LastIndexOf("/") +1)
    }
    
    # If exact file does not exist, download - else skip so as not to download again
    $FileToDownload = "$Path\$Filename"
    If (!(Test-Path -Path "$FileToDownload"))
    {
        Try
        {
            Write-Log -Message "Starting download from $($ActualURL)..." -ConsoleOutput $False
            Import-Module BitsTransfer
            Start-BitsTransfer -Source $ActualURL -Destination "$FileToDownload" -Priority Foreground -RetryTimeout 60 -RetryInterval 120
            Write-Log -Message "Download complete." -ConsoleOutput $False
        }
        Catch
        {
            Write-Log -Message "Error: $_"
        }
    }
    Else
    {
        Write-Log -Message "File $($FileToDownload) already exists, skipping download"
        Write-Log " "
    }


    Return $FileToDownload
}


# Find the latest Windows ESD or ISO file and download it
Function Find-WindowsESDorISO
{
    Param (
        $OSVer,
        $Arch,
        $Lang,
        $Path
    )

    # Server URL language codes for adding to fwlink to get the right Server ISO
    Switch ($Lang)
    {
        "en-us" {$LangCode = "&clcid=0x409&culture=en-us&country=US"}
        "zh-cn" {$LangCode = "&clcid=0x804&culture=zh-cn&country=CN"}
        "fr-fr" {$LangCode = "&clcid=0x40c&culture=fr-fr&country=FR"}
        "de-de" {$LangCode = "&clcid=0x407&culture=de-de&country=DE"}
        "it-it" {$LangCode = "&clcid=0x410&culture=it-it&country=IT"}
        "ja-jp" {$LangCode = "&clcid=0x411&culture=ja-jp&country=JP"}
        "ru-ru" {$LangCode = "&clcid=0x419&culture=ru-ru&country=RU"}
        "es-es" {$LangCode = "&clcid=0x40a&culture=es-es&country=ES"}
    }

    # Set the correct URL and Path
    If ($OSVer -eq 'Win10')
    {
        $URL = "https://go.microsoft.com/fwlink/?LinkId=841361"
        $Path = $Path + "\Win10"
    }
    ElseIf ($OSVer -eq 'Win11')
    {
        $URL = "https://go.microsoft.com/fwlink/?LinkId=2156292"
        $Path = $Path + "\Win11"
    }
    ElseIf ($OSVer -eq 'Server2016')
    {
        $FWLink = "https://go.microsoft.com/fwlink/p/?LinkID=2195174"
        $URL = $FWLink + $LangCode
        $Path = $Path + "\Server2016"
    }
    ElseIf ($OSVer -eq 'Server2019')
    {
        $FWlink = "https://go.microsoft.com/fwlink/p/?LinkID=2195167"
        $URL = $FWLink + $LangCode
        $Path = $Path + "\Server2019"
    }
    ElseIf ($OSVer -eq 'Server2022')
    {
        $FWLink = "https://go.microsoft.com/fwlink/p/?LinkID=2195280"
        $URL = $FWLink + $LangCode
        $Path = $Path + "\Server2022"
    }
    ElseIf ($OSVer -eq 'Server2025')
    {
        $FWLink = "https://go.microsoft.com/fwlink/p/?LinkID=2268694"
        $URL = $FWLink + $LangCode
        $Path = $Path + "\Server2025"
    }
    Check-PathExists -Path $Path
    
    # Download file that contains products.xml (Win10/11) or actual ISO (Server)
    $ActualURL = Get-RedirectedUrl -URL $URL
    $TempDownload = Download-File -URL $ActualURL -Path $Path

    # Extract ESD for Win10/Win11
    If ($OSVer -like "Win*")
    {
        Extract-File -File $TempDownload -Path $Path
        $XmlFile = Get-Item -Path "$Path\Extract\products.xml"

        # Check that $XmlFile actually exists
        If (!(Test-Path -Path $XmlFile))
        {
            Return $Error[0]
        }
        Else
        {
            Write-Log "Parsing file $($XmlFile) to get correct ESD URL..."
            [xml]$Xml=Get-Content -Path $XmlFile
        }

        # Find the ESD link that matches the language and architecture
        $Files = $Xml.MCT.Catalogs.Catalog.PublishedMedia.Files.File
        ForEach ($File in $Files)
        {
            If (($File.FileName -like "*VOL*$($Lang).esd*") -and ($File.Architecture -like $Arch) -and ($File.Edition -notlike "*N"))
            {
                # Download actual ESD file
                Write-Log "Attempting download of $($File.FilePath) to $($Path)..."
                Download-File -URL $File.FilePath -Path $Path
                $Result = $Path + "\" + $File.FileName
            }
        }
    }
    # Just return downloaded ISO for Server
    ElseIf ($OSVer -like "Server*")
    {
        $Result = $TempDownload
    }
    

    Return $Result
}


Function Create-LatestWindowsISO
{
    Param(
        $Path,
        $OSVer,
        $Arch,
        $Lang
    )

    # Make sure we have a working directory
    Check-PathExists -Path $Path

    # Get latest ESD or ISO file for language
    $ESDFiles = Find-WindowsESDorISO -OSVer $OSver -Arch $Arch -Lang $Lang -Path $Path
    #Handle duplicates - TODO figure out why Return sometimes gets Return'd 2x
    $File = $ESDFiles[0]

    # Extra ESD extract work if Win10/Win11 to get to an ISO
    If ($OSVer -like "Win*")
    {
        Write-Log -Message "Windows ESD file located at $($File)"
        $Images = Get-WindowsImage -ImagePath $File

        # Create variables for making image and ISO
        $TempFile = Get-Item $File

        $ImageVersion = $TempFile.BaseName.Substring(0, $TempFile.BaseName.LastIndexOf("."))
        $ImageVersion = $OSVer + "-" + $ImageVersion
        #Write-Log $ImageVersion
        #Write-Log $ImageVersion.Length

        $TempFileName = $TempFile.Name
        $TempFileName = $TempFileName.Replace('.esd','.iso')
        $ISO = $Path + "\" + $TempFileName

        $Mount = "$($env:TEMP)\Mount"

        $TempFile = $null
        $TempFileName = $null

        # Find the ADK
        If (Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots")
        {
            $KitsRoot = Get-ItemPropertyValue -Path "HKLM:\Software\WOW6432Node\Microsoft\Windows Kits\Installed Roots" -Name KitsRoot10
        }
        Else
        {
            $KitsRoot = Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\Windows Kits\Installed Roots" -Name KitsRoot10
        }

        # Create a Mount folder to put extracted contents into
        Check-PathExists -Path $Mount -DeleteIfExists $True

        # Apply the first image (setup media) into Mount folder
        Write-Log -Message "Expanding Setup Media image to $($Mount)..."
        Expand-WindowsImage -ImagePath $File -Index 1 -ApplyPath $Mount
        Write-Host ""

        # Extract the third image (Windows PE + Setup) as boot.wim into the sources folder in Mount
        Write-Log -Message "Exporting Windows PE image to $($Mount) as boot.wim..."
        Export-WindowsImage -SourceImagePath $File -SourceIndex 3 -DestinationImagePath "$Mount\sources\boot.wim" -DestinationName "Microsoft Windows Setup ($Arch)" -Setbootable
        Write-Host ""

        # Find the images in the ESD and export to install.wim
        ForEach ($Image in $Images)
        {
            If ((($Image.ImageName -like "*Pro*") -or ($Image.ImageName -like "*Enterprise*")) -and ($Image.ImageName -notlike "* N"))
            {
                Try
                {
                    $ImageIndex = $Image.ImageIndex
                    $ImageName = $Image.ImageName

                    # Extract the desired OS image into the sources folder as install.wim
                    Write-Log -Message "Expanding selected $($ImageName) image to $($Mount)\sources as install.wim..."
                    Export-WindowsImage -SourceImagePath $File -SourceIndex $ImageIndex -DestinationImagePath "$Mount\sources\install.wim" -DestinationName $ImageName
                    Write-Host ""
                }
                Catch
                {
                    Write-Log -Message "Error: $_"
                }
            }
        }

        # Capture the ISO
        Write-Log -Message "Creating $($ISO) from contents of $($Mount)..."
        Push-Location $Mount
        # This will throw an error, but will work - oscdimg does *not* seem to like being called from Powershell any other way though that I can find...
        & "$($KitsRoot)Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe" "-l$ImageVersion"  '-o' '-u2' '-m' '-udfver102' "-bootdata:1#pEF,e,bEFI\Microsoft\boot\efisys.bin" "$Mount" "$ISO" | Out-Host
        Pop-Location
        Write-Host ""

        # Clean up the temporary folder
        Check-PathExists -Path $Mount -DeleteIfExists $True

        Write-Log "ISO located at $($ISO)"
        Write-Host ""
        Write-Host ""
        Write-Host ""
    }
    ElseIf ($OSVer -like "Server*")
    {
        Write-Log "ISO located at $($File)"
        Write-Host ""
        Write-Host ""
        Write-Host ""
    }
}



########
# MAIN #
########
Write-Log -Message "Script start:    $($Script_Start_Time)"
Write-Log " "


Create-LatestWindowsISO -Path $Path -OSVer $OSVer -Arch $Arch -Lang $Lang


# How long did the whole thing take?
$Script_End_Time = (Get-Date).ToShortDateString()+", "+(Get-Date).ToLongTimeString()
$Script_Time_Taken = New-TimeSpan -Start $Script_Start_Time -End $Script_End_Time
Write-Log -Message "Script start:    $($Script_Start_Time)"
Write-Log -Message "Script end:      $($Script_End_Time)"
Write-Log -Message "Execution time:  $($Script_Time_Taken)"