---
title: "Powershell Basics"
last_modified_at: 2020-09-12T14:40:02-05:00
categories:
  - Powershell
author_profile: false
tags:
  - powershell
  - windows
  - beginner
---

## Powershell Fundamentals
In cmd everything is interpreted as strings but not object.  
If I use `dir` then it will list all the folders not as folder but as a string.

But with powershell, everything is object. That gives a lot of control to user for performing multiple tasks.

```
PS C:\users\century1> dir | Sort-Object descending                                                                                                         
                         
    Directory: C:\users\century1                                                                                                                              
                                                                                                                                                              
                                                                                                                                                              
Mode                LastWriteTime         Length Name                                                                                                         
----                -------------         ------ ----                                                                                                         
d-r---        7/16/2016   1:23 PM                Videos                                                                                                       
d-----        7/16/2016   1:23 PM                Saved Games                                                                                                  
d-r---        7/16/2016   1:23 PM                Pictures                                                                                                     
d-r---        7/16/2016   1:23 PM                Music                                                                                                        
d-r---        7/16/2016   1:23 PM                Links                                                                                                        
d-r---        7/16/2016   1:23 PM                Favorites                                                                                                    
d-r---        7/16/2016   1:23 PM                Downloads                                                                                                    
d-r---        8/30/2018   3:09 AM                Documents                                                                                                    
d-r---        7/16/2016   1:23 PM                Desktop 

```

we could use dir here because it is an alias to powershell cmdlet get-childitem.

### Basic Syntax for Powershell
Powershell follows common verb-noun syntax. For example you want to create new object then the command will be create-object.

### Powershell versions
Up until powershell 5.1, they run on top of .NET Framework, but the current powershell which is v6 which runs on top of .NET core which is cross platform and can run on mac or linux boxes.

```
PS C:\users\century1> $psversiontable                                                                                                                         
                                                                                                                                                              
Name                           Value                                                                                                                          
----                           -----                                                                                                                          
PSVersion                      5.1.14393.3866                                                                                                                 
PSEdition                      Desktop                                                                                                                        
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0...}                                                                                                        
BuildVersion                   10.0.14393.3866                                                                                                                
CLRVersion                     4.0.30319.42000                                                                                                                
WSManStackVersion              3.0                                                                                                                            
PSRemotingProtocolVersion      2.3                                                                                                                            
SerializationVersion           1.1.0.1 
```
