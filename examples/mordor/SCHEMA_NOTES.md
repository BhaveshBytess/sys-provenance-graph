# Mordor Schema Notes

Generated on 2026-04-08.

## File: metasploit_logonpasswords_lsass_memory_dump.json

### First 5 lines
```jsonl
{"SourceName":"ESENT","Level":"2","Keywords":"0x80000000000000","Channel":"Application","Hostname":"MKT01.pandalab.com","TimeCreated":"2023-08-15T09:53:59.757Z","@timestamp":"2023-08-15T09:53:59.757Z","EventID":412,"Message":"svchost (2464,R,98) SRUJet: Unable to read the header of logfile C:\\Windows\\system32\\SRU\\SRU.log. Error -501.","Task":"3"}
{"SourceName":"ESENT","Level":"2","Keywords":"0x80000000000000","Channel":"Application","Hostname":"MKT01.pandalab.com","TimeCreated":"2023-08-15T09:54:00.069Z","@timestamp":"2023-08-15T09:54:00.069Z","EventID":412,"Message":"svchost (2464,R,98) SRUJet: Unable to read the header of logfile C:\\Windows\\system32\\SRU\\SRU.log. Error -501.","Task":"3"}
{"SourceName":"ESENT","Level":"2","Keywords":"0x80000000000000","Channel":"Application","Hostname":"MKT01.pandalab.com","TimeCreated":"2023-08-15T09:54:00.174Z","@timestamp":"2023-08-15T09:54:00.174Z","EventID":412,"Message":"svchost (2464,R,98) SRUJet: Unable to read the header of logfile C:\\Windows\\system32\\SRU\\SRU.log. Error -501.","Task":"3"}
{"SourceName":"ESENT","Level":"2","Keywords":"0x80000000000000","Channel":"Application","Hostname":"MKT01.pandalab.com","TimeCreated":"2023-08-15T09:54:00.222Z","@timestamp":"2023-08-15T09:54:00.222Z","EventID":412,"Message":"svchost (2464,R,98) SRUJet: Unable to read the header of logfile C:\\Windows\\system32\\SRU\\SRU.log. Error -501.","Task":"3"}
{"SourceName":"ESENT","Level":"2","Keywords":"0x80000000000000","Channel":"Application","Hostname":"MKT01.pandalab.com","TimeCreated":"2023-08-15T09:54:00.383Z","@timestamp":"2023-08-15T09:54:00.383Z","EventID":412,"Message":"svchost (2464,R,98) SRUJet: Unable to read the header of logfile C:\\Windows\\system32\\SRU\\SRU.log. Error -501.","Task":"3"}
```

### EventID = 1 line count
- 269

### Fields present in EventID = 1 lines
- @timestamp
- Channel
- CommandLine
- Company
- CurrentDirectory
- Description
- EventID
- FileVersion
- Hashes
- Hostname
- Image
- IntegrityLevel
- Keywords
- Level
- LogonGuid
- LogonId
- Message
- OriginalFileName
- ParentCommandLine
- ParentImage
- ParentProcessGuid
- ParentProcessId
- ParentUser
- ProcessGuid
- ProcessId
- Product
- ProviderGuid
- RuleName
- SourceName
- Task
- TerminalSessionId
- TimeCreated
- User
- UtcTime

### Sample EventID = 1 JSON object
```json
{"SourceName":"Microsoft-Windows-Sysmon","ProviderGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","Level":"4","Keywords":"0x8000000000000000","Channel":"Microsoft-Windows-Sysmon/Operational","Hostname":"MKT01.pandalab.com","TimeCreated":"2023-08-15T09:53:48.554Z","@timestamp":"2023-08-15T09:53:48.554Z","EventID":1,"Message":"Process Create:\r\nRuleName: -\r\nUtcTime: 2023-08-16 04:53:48.446\r\nProcessGuid: {81056205-565c-64dc-2304-000000000800}\r\nProcessId: 7448\r\nImage: C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\r\nFileVersion: 92.0.902.67\r\nDescription: Microsoft Edge\r\nProduct: Microsoft Edge\r\nCompany: Microsoft Corporation\r\nOriginalFileName: msedge.exe\r\nCommandLine: \"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --profile-directory=Default\r\nCurrentDirectory: C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\\r\nUser: PANDALAB\\stevie.marie\r\nLogonGuid: {81056205-d113-64d4-2d2f-060000000000}\r\nLogonId: 0x62F2D\r\nTerminalSessionId: 1\r\nIntegrityLevel: Medium\r\nHashes: SHA1=FA9E8B7FB10473A01B8925C4C5B0888924A1147C,MD5=AD8536C7440638D40156E883AC25086E,SHA256=73D84D249F16B943D1D3F9DD9E516FADD323E70939C29B4A640693EB8818EE9A,IMPHASH=3A3DE7172D7A4E00C1867DD2F13AD959\r\nParentProcessGuid: {81056205-d124-64d4-6a00-000000000800}\r\nParentProcessId: 4544\r\nParentImage: C:\\Windows\\explorer.exe\r\nParentCommandLine: C:\\Windows\\Explorer.EXE\r\nParentUser: PANDALAB\\stevie.marie","Task":"1","RuleName":"-","UtcTime":"2023-08-16 04:53:48.446","ProcessGuid":"{81056205-565c-64dc-2304-000000000800}","ProcessId":"7448","Image":"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe","FileVersion":"92.0.902.67","Description":"Microsoft Edge","Product":"Microsoft Edge","Company":"Microsoft Corporation","OriginalFileName":"msedge.exe","CommandLine":"\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --profile-directory=Default","CurrentDirectory":"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\","User":"PANDALAB\\stevie.marie","LogonGuid":"{81056205-d113-64d4-2d2f-060000000000}","LogonId":"0x62f2d","TerminalSessionId":"1","IntegrityLevel":"Medium","Hashes":"SHA1=FA9E8B7FB10473A01B8925C4C5B0888924A1147C,MD5=AD8536C7440638D40156E883AC25086E,SHA256=73D84D249F16B943D1D3F9DD9E516FADD323E70939C29B4A640693EB8818EE9A,IMPHASH=3A3DE7172D7A4E00C1867DD2F13AD959","ParentProcessGuid":"{81056205-d124-64d4-6a00-000000000800}","ParentProcessId":"4544","ParentImage":"C:\\Windows\\explorer.exe","ParentCommandLine":"C:\\Windows\\Explorer.EXE","ParentUser":"PANDALAB\\stevie.marie"}
```

## File: psh_python_webserver_2020-10-2900161507.json

### First 5 lines
```jsonl
{"Message":"The audit log was cleared.\r\nSubject:\r\n\tSecurity ID:\tS-1-5-21-3940915590-64593676-1414006259-500\r\n\tAccount Name:\twardog\r\n\tDomain Name:\tWORKSTATION5\r\n\tLogon ID:\t0xC61D9","EventID":1102,"SourceName":"Microsoft-Windows-Eventlog","TimeCreated":"2020-10-29T12:16:07.900Z","Hostname":"WORKSTATION5","Task":"104","Level":"4","Keywords":"0x4020000000000000","Channel":"Security","ProviderGuid":"{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}","@timestamp":"2020-10-29T12:16:07.900Z"}
{"@timestamp":"2020-10-29T12:16:09.213Z","TimeCreated":"2020-10-29T12:16:09.213Z","ProviderGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","SourcePort":"65353","LayerName":"%%14608","SourceAddress":"0.0.0.0","Level":"0","Channel":"Security","Task":"12810","Protocol":"6","SourceName":"Microsoft-Windows-Security-Auditing","Hostname":"WORKSTATION5","ProcessId":"3304","LayerRTID":"36","FilterRTID":"0","EventID":5158,"Keywords":"0x8020000000000000","Application":"\\device\\harddiskvolume2\\windowsazure\\guestagent_2.7.41491.993_2020-10-08_063613\\waappagent.exe","Message":"The Windows Filtering Platform has permitted a bind to a local port.\r\n\r\nApplication Information:\r\n\tProcess ID:\t\t3304\r\n\tApplication Name:\t\\device\\harddiskvolume2\\windowsazure\\guestagent_2.7.41491.993_2020-10-08_063613\\waappagent.exe\r\n\r\nNetwork Information:\r\n\tSource Address:\t\t0.0.0.0\r\n\tSource Port:\t\t65353\r\n\tProtocol:\t\t6\r\n\r\nFilter Information:\r\n\tFilter Run-Time ID:\t0\r\n\tLayer Name:\t\tResource Assignment\r\n\tLayer Run-Time ID:\t36"}
{"RemoteMachineID":"S-1-0-0","@timestamp":"2020-10-29T12:16:09.213Z","TimeCreated":"2020-10-29T12:16:09.213Z","Direction":"%%14593","DestPort":"80","ProviderGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","RemoteUserID":"S-1-0-0","SourcePort":"65353","LayerName":"%%14611","SourceAddress":"192.168.2.5","Level":"0","Channel":"Security","Task":"12810","Protocol":"6","DestAddress":"168.63.129.16","SourceName":"Microsoft-Windows-Security-Auditing","Hostname":"WORKSTATION5","ProcessID":"3304","LayerRTID":"48","FilterRTID":"69895","EventID":5156,"Keywords":"0x8020000000000000","Application":"\\device\\harddiskvolume2\\windowsazure\\guestagent_2.7.41491.993_2020-10-08_063613\\waappagent.exe","Message":"The Windows Filtering Platform has permitted a connection.\r\n\r\nApplication Information:\r\n\tProcess ID:\t\t3304\r\n\tApplication Name:\t\\device\\harddiskvolume2\\windowsazure\\guestagent_2.7.41491.993_2020-10-08_063613\\waappagent.exe\r\n\r\nNetwork Information:\r\n\tDirection:\t\tOutbound\r\n\tSource Address:\t\t192.168.2.5\r\n\tSource Port:\t\t65353\r\n\tDestination Address:\t168.63.129.16\r\n\tDestination Port:\t\t80\r\n\tProtocol:\t\t6\r\n\r\nFilter Information:\r\n\tFilter Run-Time ID:\t69895\r\n\tLayer Name:\t\tConnect\r\n\tLayer Run-Time ID:\t48"}
{"@timestamp":"2020-10-29T12:16:09.914Z","TimeCreated":"2020-10-29T12:16:09.914Z","CommandLine":"\"C:\\windows\\system32\\netsh.exe\" advfirewall firewall add rule name=python.exe dir=in action=allow description=python.exe program=C:\\users\\wardog\\appdata\\local\\programs\\python\\python39\\python.exe enable=yes localport=any protocol=tcp remoteip=any","SubjectLogonId":"0xc61d9","NewProcessId":"0x2b74","SubjectDomainName":"WORKSTATION5","ProviderGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","TargetLogonId":"0x0","TokenElevationType":"%%1936","SubjectUserSid":"S-1-5-21-3940915590-64593676-1414006259-500","NewProcessName":"C:\\Windows\\System32\\netsh.exe","Level":"0","Channel":"Security","Task":"13312","SourceName":"Microsoft-Windows-Security-Auditing","Hostname":"WORKSTATION5","TargetDomainName":"-","ProcessId":"0x2468","TargetUserName":"-","ParentProcessName":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","TargetUserSid":"S-1-0-0","EventID":4688,"Keywords":"0x8020000000000000","SubjectUserName":"wardog","MandatoryLabel":"S-1-16-12288","Message":"A new process has been created.\r\n\r\nCreator Subject:\r\n\tSecurity ID:\t\tS-1-5-21-3940915590-64593676-1414006259-500\r\n\tAccount Name:\t\twardog\r\n\tAccount Domain:\t\tWORKSTATION5\r\n\tLogon ID:\t\t0xC61D9\r\n\r\nTarget Subject:\r\n\tSecurity ID:\t\tS-1-0-0\r\n\tAccount Name:\t\t-\r\n\tAccount Domain:\t\t-\r\n\tLogon ID:\t\t0x0\r\n\r\nProcess Information:\r\n\tNew Process ID:\t\t0x2b74\r\n\tNew Process Name:\tC:\\Windows\\System32\\netsh.exe\r\n\tToken Elevation Type:\t%%1936\r\n\tMandatory Label:\t\tS-1-16-12288\r\n\tCreator Process ID:\t0x2468\r\n\tCreator Process Name:\tC:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\n\tProcess Command Line:\t\"C:\\windows\\system32\\netsh.exe\" advfirewall firewall add rule name=python.exe dir=in action=allow description=python.exe program=C:\\users\\wardog\\appdata\\local\\programs\\python\\python39\\python.exe enable=yes localport=any protocol=tcp remoteip=any\r\n\r\nToken Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.\r\n\r\nType 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.\r\n\r\nType 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.\r\n\r\nType 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator."}
{"@timestamp":"2020-10-29T12:16:09.928Z","TimeCreated":"2020-10-29T12:16:09.928Z","SubjectLogonId":"0xc61d9","SubjectDomainName":"WORKSTATION5","ProviderGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","SubjectUserSid":"S-1-5-21-3940915590-64593676-1414006259-500","SourceHandleId":"0x90","Level":"0","Channel":"Security","Task":"12807","TargetHandleId":"0x4794","SourceName":"Microsoft-Windows-Security-Auditing","Hostname":"WORKSTATION5","SourceProcessId":"0x2b74","EventID":4690,"Keywords":"0x8020000000000000","TargetProcessId":"0x4","SubjectUserName":"wardog","Message":"An attempt was made to duplicate a handle to an object.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-21-3940915590-64593676-1414006259-500\r\n\tAccount Name:\t\twardog\r\n\tAccount Domain:\t\tWORKSTATION5\r\n\tLogon ID:\t\t0xC61D9\r\n\r\nSource Handle Information:\r\n\tSource Handle ID:\t0x90\r\n\tSource Process ID:\t0x2b74\r\n\r\nNew Handle Information:\r\n\tTarget Handle ID:\t0x4794\r\n\tTarget Process ID:\t0x4"}
```

### EventID = 1 line count
- 3

### Fields present in EventID = 1 lines
- @timestamp
- Channel
- CommandLine
- Company
- CurrentDirectory
- Description
- EventID
- FileVersion
- Hashes
- Hostname
- Image
- IntegrityLevel
- Keywords
- Level
- LogonGuid
- LogonId
- Message
- OriginalFileName
- ParentCommandLine
- ParentImage
- ParentProcessGuid
- ParentProcessId
- ProcessGuid
- ProcessId
- Product
- ProviderGuid
- RuleName
- SourceName
- Task
- TerminalSessionId
- TimeCreated
- User
- UtcTime

### Sample EventID = 1 JSON object
```json
{"Keywords":"0x8000000000000000","Task":"1","Description":"Network Command Shell","CommandLine":"\"C:\\windows\\system32\\netsh.exe\" advfirewall firewall add rule name=python.exe dir=in action=allow description=python.exe program=C:\\users\\wardog\\appdata\\local\\programs\\python\\python39\\python.exe enable=yes localport=any protocol=tcp remoteip=any","TimeCreated":"2020-10-29T12:16:09.918Z","Product":"Microsoft® Windows® Operating System","Company":"Microsoft Corporation","OriginalFileName":"netsh.exe","User":"WORKSTATION5\\wardog","ParentProcessId":"9320","SourceName":"Microsoft-Windows-Sysmon","IntegrityLevel":"High","ProcessGuid":"{39e4a257-4209-5f9a-3d36-000000000700}","CurrentDirectory":"C:\\Users\\wardog\\","Hashes":"SHA1=E7A3B17F625283E3064D91A988D0B1694BA3E9B8,MD5=79CBBF946E797103BED792740AEBFEC1,SHA256=90F0822D26680C8FFD703A080C876F87695580747A3704C169E39E1A8802EA38,IMPHASH=90B4317BE51850B8EF9F14EB56FB7DDC","UtcTime":"2020-10-29 04:16:09.914","ParentCommandLine":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" ","TerminalSessionId":"2","ProcessId":"11124","ParentImage":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","FileVersion":"10.0.18362.1 (WinBuild.160101.0800)","ParentProcessGuid":"{39e4a257-41e0-5f9a-3b36-000000000700}","@timestamp":"2020-10-29T12:16:09.918Z","LogonGuid":"{39e4a257-f1ac-5f8b-d961-0c0000000000}","Image":"C:\\Windows\\System32\\netsh.exe","Hostname":"WORKSTATION5","LogonId":"0xc61d9","Level":"4","EventID":1,"ProviderGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","RuleName":"-","Message":"Process Create:\r\nRuleName: -\r\nUtcTime: 2020-10-29 04:16:09.914\r\nProcessGuid: {39e4a257-4209-5f9a-3d36-000000000700}\r\nProcessId: 11124\r\nImage: C:\\Windows\\System32\\netsh.exe\r\nFileVersion: 10.0.18362.1 (WinBuild.160101.0800)\r\nDescription: Network Command Shell\r\nProduct: Microsoft® Windows® Operating System\r\nCompany: Microsoft Corporation\r\nOriginalFileName: netsh.exe\r\nCommandLine: \"C:\\windows\\system32\\netsh.exe\" advfirewall firewall add rule name=python.exe dir=in action=allow description=python.exe program=C:\\users\\wardog\\appdata\\local\\programs\\python\\python39\\python.exe enable=yes localport=any protocol=tcp remoteip=any\r\nCurrentDirectory: C:\\Users\\wardog\\\r\nUser: WORKSTATION5\\wardog\r\nLogonGuid: {39e4a257-f1ac-5f8b-d961-0c0000000000}\r\nLogonId: 0xC61D9\r\nTerminalSessionId: 2\r\nIntegrityLevel: High\r\nHashes: SHA1=E7A3B17F625283E3064D91A988D0B1694BA3E9B8,MD5=79CBBF946E797103BED792740AEBFEC1,SHA256=90F0822D26680C8FFD703A080C876F87695580747A3704C169E39E1A8802EA38,IMPHASH=90B4317BE51850B8EF9F14EB56FB7DDC\r\nParentProcessGuid: {39e4a257-41e0-5f9a-3b36-000000000700}\r\nParentProcessId: 9320\r\nParentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nParentCommandLine: \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" ","Channel":"Microsoft-Windows-Sysmon/Operational"}
```
