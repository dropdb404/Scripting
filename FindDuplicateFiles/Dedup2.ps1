function Get-PsOnePartialFileHash
{
    <#
        .SYNOPSIS
        Calculates a unique hash value for file content and strings, and is capable of calculating partial hashes to speed up calculation for large content

        .DESCRIPTION
        Calculates a cryptographic hash for file content and strings to identify identical content. 
        This can take a long time for large files since the entire file content needs to be read.
        In most cases, duplicate files can safely be identified by looking at only part of their content.
        By using parameters -StartPosition and -Length, you can define the partial content that should be used for hash calculation.
        Any file or string exceeding the size specified in -Length plus -StartPosition will be using a partial hash
        unless -Force is specified. This speeds up hash calculation tremendously, especially across the network.
        It is recommended that partial hashes are verified by calculating a full hash once it matters.
        So if indeed two large files share the same hash, you should use -Force to calculate their hash again.
        Even though you need to calculate the hash twice, calculating a partial hash is very fast and makes sure
        you calculate the expensive full hash only for files that have potential duplicates.

        .EXAMPLE
        Get-PsOneFileHash -String "Hello World!" -Algorithm MD5
        Calculates the hash for a string using the MD5 algorithm

        .EXAMPLE
        Get-PSOneFileHash -Path "$home\Documents\largefile.mp4" -StartPosition 1000 -Length 1MB -Algorithm SHA1
        Calculates the hash for the file content. If the file is larger than 1MB+1000, a partial hash is calculated,
        starting at byte position 1000, and using 1MB of data

        .EXAMPLE
        Get-ChildItem -Path $home -Recurse -File -ErrorAction SilentlyContinue | 
            Get-PsOnePartialFileHash -StartPosition 1KB -Length 1MB -BufferSize 1MB -AlgorithmName SHA1 |
            Group-Object -Property Hash, Length | 
            Where-Object Count -gt 1 |
            ForEach-Object {
                $_.Group | Select-Object -Property Length, Hash, Path
            } |
            Out-GridView -Title 'Potential Duplicate Files'
        Takes all files from the user profile and calculates a hash for each. Large files use a partial hash.
        Results are grouped by hash and length. Any group with more than one member contains potential
        duplicates. These are shown in a gridview.

        .LINK
        https://powershell.one
    #>


    [CmdletBinding(DefaultParameterSetName='File')]
    param
    (
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName='File',Position=0)]
        [string]
        [Alias('FullName')]
        # path to file with hashable content
        $Path,

        [Parameter(Mandatory,ValueFromPipeline,ParameterSetName='String',Position=0)]
        [string]
        # path to file with hashable content
        $String,

        [int]
        [ValidateRange(0,1TB)]
        # byte position to start hashing
        $StartPosition = 1000,

        [long]
        [ValidateRange(1KB,1TB)]
        # bytes to hash. Larger length increases accuracy of hash.
        # Smaller length increases hash calculation performance
        $Length = 1MB,

        [int]
        # internal buffer size to read chunks
        # a larger buffer increases raw reading speed but slows down
        # overall performance when too many bytes are read and increases
        # memory pressure
        # Ideally, length should be equally dividable by this
        $BufferSize = 32KB,

        [Security.Cryptography.HashAlgorithmName]
        [ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512')]
        # hash algorithm to use. The fastest algorithm is SHA1. MD5 is second best
        # in terms of speed. Slower algorithms provide more secure hashes with a 
        # lesser chance of duplicates with different content
        $AlgorithmName = 'SHA1',

        [Switch]
        # overrides partial hashing and always calculates the full hash
        $Force
    )

    begin
    {
        # what's the minimum size required for partial hashing?
        $minDataLength = $BufferSize + $StartPosition

        # provide a read buffer. This buffer reads the file content in chunks and feeds the
        # chunks to the hash algorithm:
        $buffer = [Byte[]]::new($BufferSize)

        # are we hashing a file or a string?
        $isFile = $PSCmdlet.ParameterSetName -eq 'File'
    }

    
    process
    {
        # prepare the return object:
        $result = [PSCustomObject]@{
            Path = $Path
            Length = 0
            Algorithm = $AlgorithmName
            Hash = ''
            IsPartialHash = $false
            StartPosition = $StartPosition
            HashedContentSize = $Length
        }
        if ($isFile)
        {
            try
            {
                # check whether the file size is greater than the limit we set:
                $file = [IO.FileInfo]$Path
                $result.Length = $file.Length

                # test whether partial hashes should be used:
                $result.IsPartialHash = ($result.Length -gt $minDataLength) -and (-not $Force.IsPresent)
            }
            catch
            {
                throw "Unable to access $Path"
            }
        }
        else
        {
            $result.Length = $String.Length
            $result.IsPartialHash = ($result.Length -gt $minDataLength) -and (-not $Force.IsPresent)
        }
        # initialize the hash algorithm to use
        # I decided to initialize the hash engine for every file to avoid collisions
        # when using transform blocks. I am not sure whether this is really necessary,
        # or whether initializing the hash engine in the begin() block is safe.
        try
        {
            $algorithm = [Security.Cryptography.HashAlgorithm]::Create($algorithmName)
        }
        catch
        {
            throw "Unable to initialize algorithm $AlgorithmName"
        }
        try
        {
            if ($isFile)
            {
                # read the file, and make sure the file isn't changed while we read it:
                $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)

                # is the file larger than the threshold so that a partial hash
                # should be calculated?
                if ($result.IsPartialHash)
                {
                    # keep a counter of the bytes that were read for this file:
                    $bytesToRead = $Length

                    # move to the requested start position inside the file content:
                    $stream.Position = $StartPosition

                    # read the file content in chunks until the requested data is fed into the
                    # hash algorithm
					$i=1
                    while($bytesToRead -gt 0)
                    {
						$i+=1
                        # either read the full chunk size, or whatever is left to read the desired
                        # total length:
                        $bytesRead = $stream.Read($buffer, 0, [Math]::Min($bytesToRead, $bufferSize))

                        # we should ALWAYS read at least one byte:
                        if ($bytesRead -gt 0)
                        {
                            # subtract the bytes read from the total number of bytes to read
                            # in order to calculate how many bytes need to be read in the next
                            # iteration of this loop:
                            $bytesToRead -= $bytesRead
                            # if there won't be any more bytes to read, this is the last chunk of data,
                            # so we can finalize hash generation:
                            if ($bytesToRead -eq 0)
                            {
                                $null = $algorithm.TransformFinalBlock($buffer, 0, $bytesRead)
                            }
                            # else, if there are more bytes to follow, simply add them to the hash
                            # algorithm:
                            else
                            {
                                $null = $algorithm.TransformBlock($buffer, 0, $bytesRead, $buffer, 0)
                            }
                        }
                        else
                        {
                            throw 'This should never occur: no bytes read.'
                        }
                    }
                }
                else
                {
                    # either the file was smaller than the buffer size, or -Force was used:
                    # the entire file hash is calculated:
                    $null = $algorithm.ComputeHash($stream)
                }
            }
            else
            {
                if ($result.IsPartialHash)
                {
                    $bytes = [Text.Encoding]::UTF8.GetBytes($String.SubString($StartPosition, $Length))
                }
                else
                {
                    $bytes = [Text.Encoding]::UTF8.GetBytes($String)
                }

                $null = $algorithm.ComputeHash($bytes)
            }

            # the calculated hash is stored in the prepared return object:
            $result.Hash = [BitConverter]::ToString($algorithm.Hash).Replace('-','')

            if (!$result.IsPartialHash)
            {
                $result.StartPosition = 0
                $result.HashedContentSize = $result.Length
            }
        }
        catch
        {
            throw "Unable to calculate partial hash: $_"

        }
        finally
        {
            if ($PSCmdlet.ParameterSetName -eq 'File')
            {
                # free stream
                $stream.Close()
                $stream.Dispose()
            }

            # free algorithm and its resources:
            $algorithm.Clear()
            $algorithm.Dispose()
        }
    
        # return result for the file
        return $result
    }
}


function Find-PSOneDuplicateFileFast
{
  <#
      .SYNOPSIS
      Identifies files with duplicate content and uses a partial hash for large files to speed calculation up

      .DESCRIPTION
      Returns a hashtable with the hashes that have at least two files (duplicates). Large files with partial hashes are suffixed with a "P".
      Large files with a partial hash can be falsely positive: they may in fact be different even though the partial hash is the same
      You either need to calculate the full hash for these files to be absolutely sure, or add -TestPartialHash.
      Calculating a full hash for large files may take a very long time though. So you may be better off using other
      strategies to identify duplicate file content, i.e. look at identical creation times, etc.

      .EXAMPLE
      $Path = [Environment]::GetFolderPath('MyDocuments')
      Find-PSOneDuplicateFileFast -Path $Path 
      Find duplicate files in the user documents folder

      .EXAMPLE
      Find-PSOneDuplicateFileFast -Path c:\windows -Filter *.log 
      find log files in the Windows folder with duplicate content

      .LINK
      https://powershell.one
  #>


  param
  (
    # Path of folder to recursively search
    [String]
    [Parameter(Mandatory)]
    $Path,
  
    # Filter to apply. Default is '*' (all Files) 
    [String]
    $Filter = '*',
    
    # when there are multiple files with same partial hash
    # they may still be different. When setting this switch,
    # full hashes are calculated which may take a very long time
    # for large files and/or slow networks
    [switch]
    $TestPartialHash,
    
    # use partial hashes for files larger than this:
    [int64]
    $MaxFileSize = 100KB,
	
	# File size greater than. Default is '0' (Skip empty files) 
    [int64]
    $sizeGreaterThan = 100KB
  )

  # get a hashtable of all files of size greater 0
  # grouped by their length
  
  
  # ENUMERATE ALL FILES RECURSIVELY
  # call scriptblocks directly and pipe them together
  # this is by far the fastest way and much faster than
  # using Foreach-Object:
  & { 
    try
    {
      # try and use the fast API way of enumerating files recursively
      # this FAILS whenever there is any "Access Denied" errors
      Write-Progress -Activity 'Acquiring Files' -Status 'Fast Method'
      [IO.DirectoryInfo]::new($Path).GetFiles('*', 'AllDirectories')
    }
    catch
    {
      # use PowerShell's own (slow) way of enumerating files if any error occurs:
      Write-Progress -Activity 'Acquiring Files' -Status 'Falling Back to Slow Method'
      Get-ChildItem -Path $Path -File -Recurse -ErrorAction Ignore
    }
  } | 
  # EXCLUDE EMPTY FILES:
  # use direct process blocks with IF (which is much faster than Where-Object):
  & {
    process
    {
      # if the file has content...
	  if ($sizeGreaterThan -lt $MaxFileSize){
		  write-host "sizeGreaterThan must greater / equal to MaxFileSize. Align sizeGreaterThan to $MaxFileSize"
		  $sizeGreaterThan = $MaxFileSize
	  }
      if ($_.Length -gt $sizeGreaterThan)
      {
        # let it pass through:
        $_
      }
    }
  } | 
  # GROUP FILES BY LENGTH, AND RETURN ONLY FILES WHERE THERE IS AT LEAST ONE
  # OTHER FILE WITH SAME SIZE
  # use direct scriptblocks with own hashtable (which is much faster than Group-Object)
  & { 
    begin 
    # start with an empty hashtable
    { $hash = @{} } 

    process 
    { 
      # group files by their length
      # (use "length" as hashtable key)
      $file = $_
      $key = $file.Length.toString()
      
      # if we see this key for the first time, create a generic
      # list to hold group items, and store FileInfo objects in this list
      # (specialized generic lists are faster than ArrayList):
      if ($hash.ContainsKey($key) -eq $false) 
      {
        $hash[$key] = [Collections.Generic.List[System.IO.FileInfo]]::new()
      }
      # add file to appropriate hashtable key:
      $hash[$key].Add($file)
    } 
  
    end 
    { 
      # return only the files from groups with at least two files
      # (if there is only one file with a given length, then it 
      # cannot have any duplicates for sure):
      foreach($pile in $hash.Values)
      {
        # are there at least 2 files in this pile?
        if ($pile.Count -gt 1)
        {
          # yes, add it to the candidates
          $pile
        }
      }
    } 
  } | 
  # CALCULATE THE NUMBER OF FILES TO HASH
  # collect all files and hand over en-bloc
  & {
    end { ,@($input) }
  } |
  # GROUP FILES BY HASH, AND RETURN ONLY HASHES THAT HAVE AT LEAST TWO FILES:
  # use a direct scriptblock call with a hashtable (much faster than Group-Object):
  & {
    begin 
    {
      # start with an empty hashtable
      $hash = @{}
      
      # since this is a length procedure, a progress bar is in order
      # keep a counter of processed files:
      $c = 0
    }
      
    process
    {
      $totalNumber = $_.Count
      foreach($file in $_)
      {
      
        # update progress bar
        $c++
      
        # update progress bar every 20 files:
        if ($c % 20 -eq 0 -or $file.Length -gt 100MB)
        {
          $percentComplete = $c * 100 / $totalNumber
          Write-Progress -Activity 'Hashing File Content' -Status $file.Name -PercentComplete $percentComplete
        }
      
        # use the file hash of this file PLUS file length as a key to the hashtable
        # use the fastest algorithm SHA1, and use partial hashes for files larger than 100KB:
        $bufferSize = [Math]::Min(1MB, $MaxFileSize)
        $result = Get-PsOnePartialFileHash -StartPosition 1KB -Length $MaxFileSize -BufferSize $bufferSize -AlgorithmName SHA1 -Path $file.FullName

        # add a "P" to partial hashes:
        if ($result.IsPartialHash) {
          $partialHash = 'P'
        }
        else
        {
          $partialHash = ''
        }
        
        
        $key = '{0}:{1}{2}' -f $result.Hash, $file.Length, $partialHash
      
        # if we see this key the first time, add a generic list to this key:
        if ($hash.ContainsKey($key) -eq $false)
        {
          $hash.Add($key, [Collections.Generic.List[System.IO.FileInfo]]::new())
        }
      
        # add the file to the approriate group:
        $hash[$key].Add($file)
      }
    }
      
    end
    {
      # remove all hashtable keys with only one file in them
      
      
      
      # do a detail check on partial hashes
      if ($TestPartialHash)
      {
        # first, CLONE the list of hashtable keys
        # (we cannot remove hashtable keys while enumerating the live
        # keys list):
        $keys = @($hash.Keys).Clone()
        $i = 0
        Foreach($key in $keys)
        {
          $i++
          $percentComplete = $i * 100 / $keys.Count
          if ($hash[$key].Count -gt 1 -and $key.EndsWith('P'))
          {
            foreach($file in $hash[$key])
            {
              Write-Progress -Activity 'Hashing Full File Content' -Status $file.Name -PercentComplete $percentComplete
              $result = Get-FileHash -Path $file.FullName -Algorithm SHA1
              $newkey = '{0}:{1}' -f $result.Hash, $file.Length
              if ($hash.ContainsKey($newkey) -eq $false)
              {
                $hash.Add($newkey, [Collections.Generic.List[System.IO.FileInfo]]::new())
              }
              $hash[$newkey].Add($file)
            }
            $hash.Remove($key)
          }
        }
      }
      
      # enumerate all keys...
      $keys = @($hash.Keys).Clone()
      
      foreach($key in $keys)
      {
        # ...if key has only one file, remove it:
        if ($hash[$key].Count -eq 1)
        {
          $hash.Remove($key)
        }
      }
       
      
       
      # return the hashtable with only duplicate files left:
      $hash
    }
  }
}

# Change pagecode/encoding to support non-english path and filenames.
$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = New-Object System.Text.UTF8Encoding

# get path to personal documents folder
#$Path = [Environment]::GetFolderPath('MyDocuments')
$path = Read-Host "Please enter the path to find duplicate"

#$result = Find-PSOneDuplicateFileFast -Path $Path -MaxFileSize 50MB -TestPartialHash 
$result = Find-PSOneDuplicateFileFast -Path $Path -MaxFileSize 10MB -sizeGreaterThan 15MB

# output duplicates
& { foreach($key in $result.Keys)
{
    foreach($file in $result[$key])
    {
        $file | Add-Member -MemberType NoteProperty -Name Hash -Value $key -PassThru | Select-Object Hash, Length, FullName,Name 
    }
}
#} | Format-Table -GroupBy Hash -Property FullName
#} | Sort-Object -Property Hash,Name,FullName | Format-table -Property Hash,Name,Length,FullName -AutoSize
} | Sort-Object -Property Hash,Name,FullName | Export-Csv -Append -NoTypeInformation -NoClobber -Force -encoding utf8 -path ".\duplicate.csv"
