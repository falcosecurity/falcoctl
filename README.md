<p align="center"><img src="https://raw.githubusercontent.com/falcosecurity/community/master/logo/primary-logo.png" width="360"></p>
<p align="center"><b>Cloud Native Runtime Security.</b></p>

<hr>

# 🧰 falcoctl

> A CLI tool to work with Falco, and perform useful tasks.

## 📣 Call for contributors/maintainers

This is a Go project that has a lot of potential in the Falco ecosystem, but needs contributions and even a maintainer or two.

If you would like to get involved with contributing to this specific project, please check out [the Falco community](https://github.com/falcosecurity/community) to get involved.

## Installation
### Install falcoctl manually
You can download and install *falcoctl* manually following the appropriate instructions based on your operating system architecture.
#### Linux
##### AMD64
```bash
LATEST=$(curl -sI https://github.com/falcosecurity/falcoctl/releases/latest | awk '/location: /{gsub("\r","",$2);split($2,v,"/");print substr(v[8],2)}')
curl --fail -LS "https://github.com/falcosecurity/falcoctl/releases/download/v${LATEST}/falcoctl_${LATEST}_linux_amd64.tar.gz" | tar -xz
sudo install -o root -g root -m 0755 falcoctl /usr/local/bin/falcoctl
```
##### ARM64
```bash
LATEST=$(curl -sI https://github.com/falcosecurity/falcoctl/releases/latest | awk '/location: /{gsub("\r","",$2);split($2,v,"/");print substr(v[8],2)}')
curl --fail -LS "https://github.com/falcosecurity/falcoctl/releases/download/v${LATEST}/falcoctl_${LATEST}_linux_arm64.tar.gz" | tar -xz
sudo install -o root -g root -m 0755 falcoctl /usr/local/bin/falcoctl
```
> NOTE: Make sure */usr/local/bin* is in your PATH environment variable.

#### MacOS
##### Intel
```bash
LATEST=$(curl -sI https://github.com/falcosecurity/falcoctl/releases/latest | awk '/location: /{gsub("\r","",$2);split($2,v,"/");print substr(v[8],2)}')
curl --fail -LS "https://github.com/falcosecurity/falcoctl/releases/download/v${LATEST}/falcoctl_${LATEST}_darwin_amd64.tar.gz" | tar -xz
chmod +x falcoctl
sudo mv falcoctl /usr/local/bin/falcoctl
```
##### Apple Silicon
```bash
LATEST=$(curl -sI https://github.com/falcosecurity/falcoctl/releases/latest | awk '/location: /{gsub("\r","",$2);split($2,v,"/");print substr(v[8],2)}')
curl --fail -LS "https://github.com/falcosecurity/falcoctl/releases/download/v${LATEST}/falcoctl_${LATEST}_darwin_arm64.tar.gz" | tar -xz
chmod +x falcoctl
sudo mv falcoctl /usr/local/bin/falcoctl
```

Alternatively, you can manually download *falcoctl* from the [falcoctl releases](https://github.com/falcosecurity/falcoctl/releases) page on GitHub.

### Install falcoctl from source
You can install *falcoctl* from source. First thing clone the *falcoctl* repository, build the *falcoctl* binary, and move it to a file location in your system **PATH**.
```bash
git clone https://github.com/falcosecurity/falcoctl.git
cd falcoctl
make falcoctl
sudo mv falcoctl /usr/local/bin/falcoctl
```

# Getting Started

## Installing an artifact

This tutorial aims at presenting how to install a Falco artifact. The next few steps will present us with the fundamental commands of *falcoctl* and how to use them.

First thing, we need to add a new `index` to *falcoctl*:
```bash
falcoctl index add falcosecurity https://falcosecurity.github.io/falcoctl/index.yaml
```
We just downloaded the metadata of the **artifacts** hosted and distributed by the **falcosecurity** organization and made them available to the *falcoctl* tool.
Now let's check that the `index` file is in place by running:
```
falcoctl index list
```
We should get an output similar to this one:
```
NAME            URL                                                     ADDED                   UPDATED            
falcosecurity   https://falcosecurity.github.io/falcoctl/index.yaml     2022-10-25 15:01:25     2022-10-25 15:01:25
```
Now let's search all the artifacts related to *cloudtrail*:
```
❯ falcoctl artifact search cloudtrail
INDEX           ARTIFACT                TYPE            REGISTRY        REPOSITORY                              
falcosecurity   cloudtrail              plugin          ghcr.io         falcosecurity/plugins/plugin/cloudtrail 
falcosecurity   cloudtrail-rules        rulesfile       ghcr.io         falcosecurity/plugins/ruleset/cloudtrail
```
Lets install the *cloudtrail plugin*:
```
❯ falcoctl artifact install cloudtrail --plugins-dir=./
 INFO  Reading all configured index files from "/home/aldo/.config/falcoctl/indexes.yaml"
 INFO  Preparing to pull "ghcr.io/falcosecurity/plugins/plugin/cloudtrail:latest"
 INFO  Remote registry "ghcr.io" implements docker registry API V2
 INFO  Pulling 44136fa355b3: ############################################# 100% 
 INFO  Pulling 80e0c33f30c0: ############################################# 100% 
 INFO  Pulling b024dd7a2a63: ############################################# 100% 
 INFO  Artifact successfully installed in "./" 
```
Install the *cloudtrail-rules* rulesfile:
```
❯ ./falcoctl artifact install cloudtrail-rules --rulesfiles-dir=./
 INFO  Reading all configured index files from "/home/aldo/.config/falcoctl/indexes.yaml"
 INFO  Preparing to pull "ghcr.io/falcosecurity/plugins/ruleset/cloudtrail:latest"
 INFO  Remote registry "ghcr.io" implements docker registry API V2
 INFO  Pulling 44136fa355b3: ############################################# 100% 
 INFO  Pulling e0dccb7b0f1d: ############################################# 100% 
 INFO  Pulling 575bced78731: ############################################# 100% 
 INFO  Artifact successfully installed in "./"
```

We should have now two new files in the current directory: `aws_cloudtrail_rules.yaml` and `libcloudtrail.so`.
# Falcoctl Commands

## Falcoctl index

The `index` file is a yaml file that contains some metadata about the Falco **artifacts**. Each entry carries information such as the name, type, registry, repository and other info for the given **artifact**. Different *falcoctl* commands rely on the metadata contained in the `index` file for their operation.
This is an example of an index file:
```yaml
- name: okta
  type: plugin
  registry: ghcr.io
  repository: falcosecurity/plugins/plugin/okta
  description: Okta Log Events
  home: https://github.com/falcosecurity/plugins/tree/master/plugins/okta
  keywords:
    - audit
    - log-events
    - okta
  license: Apache-2.0
  maintainers:
    - email: cncf-falco-dev@lists.cncf.io
      name: The Falco Authors
  sources:
    - https://github.com/falcosecurity/plugins/tree/master/plugins/okta
- name: okta-rules
  type: rulesfile
  registry: ghcr.io
  repository: falcosecurity/plugins/ruleset/okta
  description: Okta Log Events
  home: https://github.com/falcosecurity/plugins/tree/master/plugins/okta
  keywords:
    - audit
    - log-events
    - okta
    - okta-rules
  license: Apache-2.0
  maintainers:
    - email: cncf-falco-dev@lists.cncf.io
      name: The Falco Authors
  sources:
    - https://github.com/falcosecurity/plugins/tree/master/plugins/okta/rules
```
#### falcoctl index add
New indexes are configured to be used by the *falcoctl* tool by adding them through the `index add` command. The current implementation requires a valid HTTP URL from where to download the `index` file. There are no limits to the number of indexes that can be added to the *falcoctl* tool. When adding a new index the tool adds a new entry in a file called **indexes.yaml** and downloads the *index* file in `~/.config/falcoctl`. The same folder is used to store the **indexes.yaml** file, too.
The following command adds a new index named *falcosecurity*:
```bash
falcoctl index add falcosecurity https://falcosecurity.github.io/falcoctl/index.yaml
```
#### falcoctl index list
Using the `index list` command you can check the configured `indexes` in your local system:
```bash
❯ falcoctl index list
NAME            URL                                                     ADDED                   UPDATED            
falcosecurity   https://falcosecurity.github.io/falcoctl/index.yaml     2022-10-25 15:01:25     2022-10-25 15:01:25
```
#### falcoctl index update
The `index update` allows to update a previously configured `index` file by syncing the local one with the remote one:
```bash
falcoctl index update falcosecurity
```
#### falcoctl index remove
When we want to remove an `index` file that we configured previously, the `index remove` command is the one we need:
```bash
falcoctl index remove falcosecurity
```
The above command will remove the **falcosecurity** index from the local system.

## Falcoctl artifact
The *falcoctl* tool provides different commands to interact with Falco **artifacts**. It makes easy to *seach*, *install* and get *info* for the **artifacts** provided by a given `index` file. For these commands to properly work we need to configure at least an `index` file in our system as shown in the previus section.
#### Falcoctl artifact search
The `artifact search` command allows to search for **artifacts** provided by the `index` files configured in *falcoctl*. The command supports searches by name or by keywords and displays all the **artifacts** that match the search. Assuming that we have already configured the `index` provided by the `falcosecurity` organization, the following command shows all the **artifacts** that work with **Kubernetes**:
```bash
❯ falcoctl artifact search kubernetes
INDEX           ARTIFACT        TYPE            REGISTRY        REPOSITORY                            
falcosecurity   k8saudit        plugin          ghcr.io         falcosecurity/plugins/plugin/k8saudit 
falcosecurity   k8saudit-rules  rulesfile       ghcr.io         falcosecurity/plugins/ruleset/k8saudit
```

#### Falcoctl artifact info
As per the name, `artifact info` prints some info for a given **artifact**:
```bash
❯ falcoctl artifact info k8saudit
REF                                             TAGS                                          
ghcr.io/falcosecurity/plugins/plugin/k8saudit   0.1.0 0.2.0 0.2.1 0.3.0 0.4.0-rc1 0.4.0 latest
```
It shows the OCI **reference** and **tags** for the **artifact** of interest. Thot info is usually used with other commands.

#### Falcoctl artifact install
The above commands help us to find all the necessary info for a given **artifact**. The `artifact install` command installs an **artifact**. It pulls the **artifact** from remote repository, and saves it in a given directory. The following command installs the *k8saudit* plugin in the default path:
```bash
❯ falcoctl artifact install k8saudit
 INFO  Reading all configured index files from "/home/aldo/.config/falcoctl/indexes.yaml"
 INFO  Preparing to pull "ghcr.io/falcosecurity/plugins/plugin/k8saudit:latest"
 INFO  Remote registry "ghcr.io" implements docker registry API V2                                                                                                                                              
 INFO  Pulling 44136fa355b3: ############################################# 100% 
 INFO  Pulling ded0b5419f40: ############################################# 100% 
 INFO  Pulling 107d1230f3f0: ############################################# 100% 
 INFO  Artifact successfully installed in "/usr/share/falco/plugins"
 ```
 By default, if we give the name of an **artifact** it will search for the **artifact** in the configured `index` files and downlaod the `latest` version. The commands accepts also the OCI **reference** of an **artifact**. In this case, it will ignore the local `index` files.
 The command has two flags:
 * `--plugins-dir`: directory where to install plugins. Defaults to `/usr/share/falco/plugins`;
 * `--rulesfiles-dir`: directory where to install rules. Defaults to `/etc/falco`.

 > If the repositories of the **artifacts** your are trying to install are not public then you need to authenticate to the remote registry.

 ## Falcoctl registry

 The `registry` commands interact with OCI registries allowing the user to authenticate, pull and push artifacts. We have tested the *falcoctl* tool with the **ghcr.io** registry, but it should work with all the registries that support the OCI artifacts.

### Falcoctl registry auth
The `registry auth` command authenticates a user to a given OCI registry.

#### Falcoctl registry auth basic
The `registry auth basic` command authenticates a user to a given OCI registry using HTTP Basic Authentication. Run the command in advance for any private registries.

#### Falcoctl registry auth oauth
The `registry auth oauth` command retrieves access and refresh tokens for OAuth2.0 client credentials flow authentication. Run the command in advance for any private registries.

### Falcoctl registry push
It pushes local files and references the artifact uniquely. The following command shows how to push a local file to a remote registry:
```bash
falcoctl registry push --type=plugin ghcr.io/falcosecurity/plugins/plugin/cloudtrail:0.3.0 clouddrail-0.3.0-linux-x86_64.tar.gz --platform linux/amd64
```
The type denotes the **artifact** type in this case *plugins*. The `ghcr.io/falcosecurity/plugins/plugin/cloudtrail:0.3.0` is the unique reference that points to the **artifact**.
Currently, *falcoctl* supports only two types of artifacts: **plugin** and **rulesfile**. Based on **artifact type** the commands accepts different flags:
* `--annotation-source`: set annotation source for the artifact;
* `--depends-on`: set an artifact dependency (can be specified multiple times). Example: `--depends-on my-plugin:1.2.3`
* `--tag`: additional artifact tag. Can be repeated multiple time 
* `--type`: type of artifact to be pushed. Allowed values: `rulesfile`, `plugin`

### Falcoctl registry pull
Pulling **artifacts** involves specifying the reference. The type of **artifact** is not required since the tool will implicitly extract it from the OCI **artifact**:
```
falcoctl registry pull ghcr.io/falcosecurity/plugins/plugin/cloudtrail:0.3.0                                        
```
