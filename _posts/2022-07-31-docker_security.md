---
title: "Docker security best practices"
last_modified_at: 2022-07-31T23:59:00-05:00
categories:
  - docker
author_profile: false
tags:
  - docker
  - security
  - Best practices
  - trivy
  - container security
  - minimal base images
  - updating packages
  - trusted images
  - low privileged accounts
  - Dockerignore
  - Docker breakout
  - docker
  - secrets management
  - privileged mode
  - read only file system
  - logging and monitoring
  - limiting capabilities
  - limiting outbound connection
---

<img alt="image" src="/assets/images/docker/docker.png" width="200px" height="150px">


Containers have a lot of advantages and make our life so much easier but container which are deployed insecurely might cause many serious problems. In this blog post I am going to discuss a few security practices that we should consider while building a docker image and running the containers using that image.

## Using minimal base images
It is always an good idea to use mininal base images. Not only the base images like alpine, slim-buster are lightweight but also contains very less things compared to normal images which decreases the attack surface.

I have created a basic web application on a flask and I will dockerize this application.

**app.py**
```python
from flask import Flask,make_response,json
import os

app = Flask(__name__)

@app.route('/')
def index():
    u = os.getenv('username')
    p = os.getenv('password')
    data = {"username":u, "password": p}
    
    response = app.response_class(
        response=json.dumps(data),
        status=200,
        mimetype='application/json'
    )
    return response


app.run(host='0.0.0.0', port=8000)
```
**Requirements.py**
```
flask
```

**Dockerfile**
```
From python:latest

ADD . /app
WORKDIR /app

ENV username=test
ENV password=test
ENV FLASK_APP=app.py

RUN pip3 install -r requirements.txt

CMD ["python3","app.py"]
```
Let us use this Dockerfile to create an image and let us again use the minimal alpine base image to create another image and check the difference in size between them
```bash
test                 debian            c3a0374eb4f0   8 minutes ago   879MB
```

**Changed Dockerfile**
```
From python:3.7-alpine
```
After creating the docker image with the new alpine image:
```
test                 alpine            2a0472c2aafc   7 minutes ago   60.5MB
```

We can notice a huge difference in size between the two images. The image built with debian image is **879MB** whereas the image built with alpine image is just **60.5MB**.

## Use fixed tags and update your docker image periodically
Using the `latest` tag on our docker image might break your application on production. So we should always use specific tag on the applications that are deployed in production. But if you have to ensure manually if the image used is older and vulnerable and upgrade to the latest version whenever possible.
**In Dockerfile**
```
From python:3.7-alpine
```

## Use trusted Images
We should always use trusted and verified images from dockerhub. We might not know what we are running if we use custom, untrusted images from the dockerhub. The custom images might contain code for crypto mining which will drain the resources of the host, monitor all the activites that are running inside the container and send it to the attacker. The use cases are almost limitless on what an attacker can do. 


## Updating the packages while building the images
It is always a good idea to update all the packages during the build time of the images. This will update the image with the latest security patches.
**For debian image**
```
RUN apt-get update -y && apt-get upgrade -y
```
**For alpine images**
```
RUN apk update && apk upgrade
```


## Keep docker host up to date
Keeping the host up to date is as important as keeping the packages inside docker images up to date. It does not make sense if your docker image is running with latest security patches and the host on which the docker container are running is very very old and contains a lot of vulnerabilities. An attacker will just exploit the vulnerabilities on the host and will get access to all the containers eventually.

## Root User Account
By default Docker run everything as root. So, if an attacker found a command injection vulnerability on your web application that is running as root, they will be able to run commands on the container as root. Unless absolutely needed, we should run everything inside a container as low privileged user.

**Changing the previous Dockerfile**
```
RUN chown -R nobody:nobody /app && chmod 700 -R /app
USER nobody
```
Debain based images have `www-data` local service account and the alpine images have user called `nobody`. 

If you want to create a new user for your application, you can use the following command on your Dockerfile.
```
RUN adduser --shell /usr/sbin/nologin --disabled-password --no-create-home  --system test-user
```
This will create an user called `test-user` which is a service account in the linux system without creating a home directory, disabling the password for this account and setting the default shell of this account to `/usr/sbin/nologin`.


## Dockerignore to ignore files
Like `.gitignore` we can use `.Dockerfile` file to exclude the files that are used to create a docker image. It will be very wise if we ignore folder like `.git` and files which contains sensitive informations.
**Dockerignore**
```
.git
.env*
.cache*
Dockerfile
```

## Never mount sensitive files/directories inside a container
We should always be aware of the things that we mount inside docker container. An attacker who already have a foothold on the docker container might use the contents inside the mounted directories to escape out of the container.

Few directories that we should avoid mounting inside docker containers
- `/root` or `/home/user/`  - Both of these directories might contain `.ssh` directory which can be used by an attacker to add an entry on `~/.ssh/authorized_keys`
- `/etc` - An attacker can modify the contents of `/etc/crontab` and execute commands on the host
- `/var/run/docker.sock` - This socket file can be used to send HTTP requests to docker daemon. If this is mounted inside a docker container, an attacker can simply break out of the docker container. Check [here](https://shishirsubedi.com.np/htb/feline/#bash_history) to find out how docker socket can be used to break out of docker containers.
- `/bin` - An attacker can create an backdoor by modifying `/bin/bash` binary to execute commands whenever someone logs into the system

Few other directories that we should avoid mounting are `/dev`, `/proc` and `/sys`.

## Never hardcode secret in Dockerfile
We should avoid hardcoding secrets on the Dockerfile while building the image. Sensitive information might be exposed if we leave the credentials on the dockerfile and file might get mistakely pushed into public repository where it is accessible to everyone.

We can mount secrets inside the container directly as a volume rather than using sensitive information on the Dockerfile. 

Learn how to manage secrets properly from [this](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout#managing-secrets) article.

## Scanning docker images periodically
We should always scan for the docker images for security vulnerabilities. We can use an open source tool called [trivy](https://github.com/aquasecurity/trivy) by aquasecurity to scan our docker images. Let us check the images that we have created earlier for vulnerabilites.

### Scanning the debian based image
```bash
╭─ubuntu@ubuntu ~
╰─$ trivy --quiet image --severity=CRITICAL test:debian                                                                     

test:debian (debian 11.4)
=========================
Total: 42 (CRITICAL: 42)

+-----------------------+------------------+----------+---------------------+---------------+---------------------------------------+
|        LIBRARY        | VULNERABILITY ID | SEVERITY |  INSTALLED VERSION  | FIXED VERSION |                 TITLE                 |
+-----------------------+------------------+----------+---------------------+---------------+---------------------------------------+
| curl                  | CVE-2021-22945   | CRITICAL | 7.74.0-1.3+deb11u1  |               | curl: use-after-free and              |
|                       |                  |          |                     |               | double-free in MQTT sending           |
|                       |                  |          |                     |               | -->avd.aquasec.com/nvd/cve-2021-22945 |
+                       +------------------+          +                     +---------------+---------------------------------------+
|                       | CVE-2022-32207   |          |                     |               | curl: Unpreserved file permissions    |
|                       |                  |          |                     |               | -->avd.aquasec.com/nvd/cve-2022-32207 |
+-----------------------+------------------+          +---------------------+---------------+---------------------------------------+
| libaom0               | CVE-2021-30473   |          | 1.0.0.errata1-3     |               | aom_image.c in libaom in              |
|                       |                  |          |                     |               | AOMedia before 2021-04-07             |
|                       |                  |          |                     |               | frees memory that i ......            |
|                       |                  |          |                     |               | -->avd.aquasec.com/nvd/cve-2021-30473 |
+                       +------------------+          +                     +---------------+---------------------------------------+
|                       | CVE-2021-30474   |          |                     |               | aom_dsp/grain_table.c in              |
|                       |                  |          |                     |               | libaom in AOMedia before              |
|                       |                  |          |                     |               | 2021-03-30 has a use ...              |
|                       |                  |          |                     |               | -->avd.aquasec.com/nvd/cve-2021-30474 |
+                       +------------------+          +                     +---------------+---------------------------------------+
|                       | CVE-2021-30475   |          |                     |               | aom_dsp/noise_model.c in              |
|                       |                  |          |                     |               | libaom in AOMedia before              |
|                       |                  |          |                     |               | 2021-03-24 has a buf ...              |
|                       |                  |          |                     |               | -->avd.aquasec.com/nvd/cve-2021-30475 |
+-----------------------+------------------+          +---------------------+---------------+---------------------------------------+

..............[snip]............
```
Trivy found 42 vulnerabilites with critical severity. 

### Scanning the alpine image
```bash
╭─ubuntu@ubuntu ~
╰─$ trivy --quiet image --severity=CRITICAL test:alpine

test:alpine (alpine 3.16.1)
===========================
Total: 0 (CRITICAL: 0)


Python (python-pkg)
===================
Total: 0 (CRITICAL: 0)

```
No any vulerabilities are found for the image created from alpine base image.

## Never run docker containers in privileged mode
We should never run docker containers in privileged mode. Running the container in privileged mode, bypasses all the restriction like memory isolation(cgroups) that are used to run containers in an isolated environment and adds all the capabilities. This means that we can easily break out from the docker containers into the host system. 

Find out more on how you can break out of privileged docker container on [this](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#escape-from-privileged-containers) article.

## Read only file system if possible
If the application inside the docker container does not have to write any files inside the container, we can start the container's filesystem as read only.
**Running container with read only file system:**
```bash
╭─ubuntu@ubuntu ~
╰─$ docker run -ti  --rm --read-only  test:debian bash        
root@4b424ce2c99d:/app# ls
Dockerfile  app.py  image_vulnerabilites  pod.yaml  requirements.txt
root@4b424ce2c99d:/app# touch test
touch: cannot touch 'test': Read-only file system
```

If we feel the need to create temporary files while the docker container is running, we can also specify `--tmpfs` in which we can write files temporarily. 
```bash
╭─ubuntu@ubuntu ~
╰─$ docker run -ti  --rm --read-only --tmpfs /tmp  test:debian bash 
root@31a9d9218276:/app# touch /tmp/test
root@31a9d9218276:/app# touch test
touch: cannot touch 'test': Read-only file system
root@31a9d9218276:/app#
```

Reference : https://docs.datadoghq.com/security_platform/default_rules/cis-docker-1.2.0-5.12/

## Dropping the risky capabilities
We should not mount the capabilities that are not required by the application as it can be used by an attacker to break out for the container. Some of the risky capabilities are as follows:
- CAP_SYS_ADMIN
- CAP_SYS_PTRACE
- CAP_SYS_MODULE
- DAC_READ_SEARCH

**Drop all privileges while running a docker container and provide just the needed privileges:**
```
docker run -it --rm --cap-drop=ALL --cap-add=CAP_NET_RAW test:alpine
```

Reference : [Hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#capabilities-abuse-escape)

## Logging and monitoring
It is always a good idea to implement proper logging on the application running inside a docker container. By default, the logs from docker container are send to standard output(`/dev/stdout`) as well as standard error(`/dev/stderr`) and the logs do not persist if the container dies. So from the security standpoint, it is absolutely critical that there is proper logging implemented on the docker containers and the logs are brought into SIEM solution so that we can create alert rules for monitoring.

**Viewing logs in a docker container:**
```bash
╭─ubuntu@ubuntu ~
╰─$ docker container ls
CONTAINER ID   IMAGE                  COMMAND                  CREATED         STATUS         PORTS                       NAMES
5729acf6a278   test:alpine            "python3 app.py"         9 seconds ago   Up 7 seconds                               tender_swartz

╭─ubuntu@ubuntu ~
╰─$ docker logs -f 5729acf6a278
 * Serving Flask app 'app' (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
 * Running on all addresses (0.0.0.0)
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://127.0.0.1:8000
 * Running on http://172.17.0.2:8000 (Press CTRL+C to quit)
```


## Limiting the out bound connection
If the docker container does not need to connect to the internet, it would be wise just to block all the outgoing traffic to the internet. Even if the attacker has gotten a foothold on the container, it would make there job very difficult to exfiltrate the data, escalate privileges, install binaries and this will slow down the attackers.


### Creating network to block the internet access
```bash
docker network create --internal --subnet 10.0.0.0/8 no-internet
```

We have to apply this network to the container.
```bash
docker network connect no-internet container-name
```

### Limiting outbound connect on our test image
```bash
╭─ubuntu@ubuntu ~
╰─$ docker network create --internal --subnet 10.0.0.0/8 no-internet
```

```bash
╭─ubuntu@ubuntu ~
╰─$ docker run -ti --rm --network no-internet test:debian bash
root@bac41d1d88c9:/app# curl https://google.com -I
curl: (6) Could not resolve host: google.com
root@bac41d1d88c9:/app#
```


Reference: [https://stackoverflow.com/questions/39913757/restrict-internet-access-docker-container](https://stackoverflow.com/questions/39913757/restrict-internet-access-docker-container)