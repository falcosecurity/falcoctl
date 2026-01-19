# 🧰 falcoctl

[![Falco Core Repository](https://github.com/falcosecurity/evolution/blob/main/repos/badges/falco-core-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#core-scope) [![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#stable) [![License](https://img.shields.io/github/license/falcosecurity/falcoctl?style=for-the-badge)](./LICENSE)

The official CLI tool for working with [Falco](https://github.com/falcosecurity/falco) and its [ecosystem components](https://falco.org/docs/#what-are-the-ecosystem-projects-that-can-interact-with-falco).

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
The easiest way to install on MacOS is via `Homebrew`:
```bash
brew install falcoctl
```

Alternatively, you can download directly from the source:

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
$ falcoctl index add falcosecurity https://falcosecurity.github.io/falcoctl/index.yaml
```
We just downloaded the metadata of the **artifacts** hosted and distributed by the **falcosecurity** organization and made them available to the *falcoctl* tool.
Now let's check that the `index` file is in place by running:
```
$ falcoctl index list
```
We should get an output similar to this one:
```
NAME            URL                                                     ADDED                   UPDATED            
falcosecurity   https://falcosecurity.github.io/falcoctl/index.yaml     2022-10-25 15:01:25     2022-10-25 15:01:25
```
Now let's search all the artifacts related to *cloudtrail*:
```
$ falcoctl artifact search cloudtrail
INDEX           ARTIFACT                TYPE            REGISTRY        REPOSITORY                              
falcosecurity   cloudtrail              plugin          ghcr.io         falcosecurity/plugins/plugin/cloudtrail 
falcosecurity   cloudtrail-rules        rulesfile       ghcr.io         falcosecurity/plugins/ruleset/cloudtrail
```
Lets install the *cloudtrail plugin*:
```
$ falcoctl artifact install cloudtrail --plugins-dir=./
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
$ ./falcoctl artifact install cloudtrail-rules --rulesfiles-dir=./
 INFO  Reading all configured index files from "/home/aldo/.config/falcoctl/indexes.yaml"
 INFO  Preparing to pull "ghcr.io/falcosecurity/plugins/ruleset/cloudtrail:latest"
 INFO  Remote registry "ghcr.io" implements docker registry API V2
 INFO  Pulling 44136fa355b3: ############################################# 100% 
 INFO  Pulling e0dccb7b0f1d: ############################################# 100% 
 INFO  Pulling 575bced78731: ############################################# 100% 
 INFO  Artifact successfully installed in "./"
```

We should have now two new files in the current directory: `aws_cloudtrail_rules.yaml` and `libcloudtrail.so`.

# Falcoctl Configuration Files

## `/etc/falcoctl/falcoctl.yaml`

The `falco configuration file` is a yaml file that contains some metadata about the `falcoctl` behaviour.
It contains the list of the indexes where the artifacts are listed, how often and which artifacts needed to be updated periodically.
The default configuration is stored in `/etc/falcoctl/falcoctl.yaml`.
This is an example of a falcoctl configuration file:

``` yaml
artifact:
  follow:
    every: 6h0m0s
    falcoVersions: http://localhost:8765/versions
    refs:
    - falco-rules:0
    - my-rules:1
  install:
    refs:
      - cloudtrail-rules:latest
      - cloudtrail:latest
    rulesfilesdir: /tmp/rules
    pluginsdir: /tmp/plugins
indexes:
- name: falcosecurity
  url: https://falcosecurity.github.io/falcoctl/index.yaml
- name: my-index
  url: https://example.com/falcoctl/index.yaml
registry:
  auth:
    basic:
    - password: password
      registry: myregistry.example.com:5000
      user: user
    oauth:
    - registry: myregistry.example.com:5001
      clientsecret: "999999"
      clientid: "000000"
      tokenurl: http://myregistry.example.com:9096/token
    gcp:
    - registry: europe-docker.pkg.dev
```

## `~/.config/falcoctl/`

The `~/.config/falcoctl/` directory contains:
- *cache objects*
- *OAuth2 client credentials*

### `~/.config/falcoctl/indexes.yaml`

This file is used for cache purposes and contains the *index refs* added by the command `falcoctl index add [name] [ref]`. The *index ref* is enriched with two timestamps to track when it was added and the last time is was updated. Once the *index ref* is added, `falcoctl` will download the real index in the `~/.config/falcoctl/indexes/` directory. Moreover, every time the index is fetched, the `updated_timestamp` is updated.

### `~/.config/falcoctl/clientcredentials.json`

The command `falcoctl registry auth oauth` will add the `clientcredentials.json` file to the `~/.config/falcoctl/` directory. That file will contain all the needed information for the OAuth2 authetication.

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

### Index Storage Backends

Indices for *falcoctl* can be retrieved from various storage backends. The supported index storage backends are listed in the table below. Note if you do not specify a backend type when adding a new index *falcoctl* will try to guess based on the `URI Scheme`:

| Name  | URI Scheme | Description                                                                                   |
| ----- | ---------- | --------------------------------------------------------------------------------------------- |
| http  | http://    | Can be used to retrieve indices via simple HTTP GET requests.                                 |
| https | https://   | Convenience alias for the HTTP backend.                                                       |
| gcs   | gs://      | For indices stored as Google Cloud Storage objects. Supports application default credentials. |
| file  | file://    | For indices stored on the local file system.                                                  |
| s3    | s3://      | For indices stored as AWS S3 objects. Supports default credentials, IRSA.                     |


#### falcoctl index add
New indexes are configured to be used by the *falcoctl* tool by adding them through the `index add` command. There are no limits to the number of indexes that can be added to the *falcoctl* tool. When adding a new index the tool adds a new entry in a file called **indexes.yaml** and downloads the *index* file in `~/.config/falcoctl`. The same folder is used to store the **indexes.yaml** file, too.
The following command adds a new index named *falcosecurity*:
```bash
$ falcoctl index add falcosecurity https://falcosecurity.github.io/falcoctl/index.yaml
```

The following command adds the same index *falcosecurity*, but explicitly sets the storage backend to `https`:
```bash
$ falcoctl index add falcosecurity https://falcosecurity.github.io/falcoctl/index.yaml https
```
#### falcoctl index list
Using the `index list` command you can check the configured `indexes` in your local system:
```bash
$ falcoctl index list
NAME            URL                                                     ADDED                   UPDATED            
$ falcosecurity   https://falcosecurity.github.io/falcoctl/index.yaml     2022-10-25 15:01:25     2022-10-25 15:01:25
```
#### falcoctl index update
The `index update` allows to update a previously configured `index` file by syncing the local one with the remote one:
```bash
$ falcoctl index update falcosecurity
```
#### falcoctl index remove
When we want to remove an `index` file that we configured previously, the `index remove` command is the one we need:
```bash
$ falcoctl index remove falcosecurity
```
The above command will remove the **falcosecurity** index from the local system.

## Falcoctl artifact
The *falcoctl* tool provides different commands to interact with Falco **artifacts**. It makes easy to *seach*, *install* and get *info* for the **artifacts** provided by a given `index` file. For these commands to properly work we need to configure at least an `index` file in our system as shown in the previus section.

### Artifact References and Versions

Falcoctl supports multiple ways to reference artifacts. Understanding these formats is essential for installing, pushing, and managing artifacts.

#### Reference Formats

| Format | Example | Description |
| ------ | ------- | ----------- |
| Simple name | `cloudtrail` | Artifact name only. Requires an index to resolve the full OCI reference. Defaults to `latest` tag. |
| Simple name with tag | `cloudtrail:0.6.0` | Artifact name with version tag. Requires an index to resolve the full OCI reference. |
| Full OCI reference | `ghcr.io/falcosecurity/plugins/plugin/cloudtrail:latest` | Complete registry/repository path with tag. Bypasses the index entirely. |
| Full OCI reference with digest | `ghcr.io/falcosecurity/plugins/plugin/cloudtrail@sha256:abc123...` | Complete reference with content digest. Immutable reference to a specific artifact. |

#### How Reference Resolution Works

When you use a **simple name** (e.g., `cloudtrail` or `cloudtrail:0.6.0`), falcoctl:
1. Searches configured index files for a matching artifact name
2. Uses the index entry to build the full OCI reference (registry + repository)
3. Appends the tag (or `latest` if not specified)

When you use a **full OCI reference** (e.g., `ghcr.io/myregistry/myartifact:1.0.0`), falcoctl:
1. Uses the reference directly without consulting any index
2. Pulls directly from the specified registry and repository

#### OCI Tags vs Artifact Version

It's important to understand the difference between the **OCI tag** and the **artifact version**:

| Concept | Example | Purpose |
| ------- | ------- | ------- |
| OCI Tag | `:latest`, `:0.6.0`, `:stable` | Identifies the artifact in the registry. Can be any string. Mutable (can be moved to different content). |
| Artifact Version | `--version "1.0.0"` | Stored in the artifact's config layer metadata. Must be valid semver. Used for dependency resolution. |

**Example:** An artifact pushed as `myregistry/myrules:latest` with `--version "2.0.0"` has:
- OCI tag: `latest` (used to pull the artifact)
- Artifact version: `2.0.0` (used for dependency resolution and compatibility checks)

#### Version Requirements

When **pushing** artifacts with `falcoctl registry push`:
- The `--version` flag is **required**
- Must be a valid [Semantic Version](https://semver.org/) (e.g., `1.0.0`, `2.1.3-rc1`)
- Short versions like `1` or `1.0` are **not valid** and will be rejected
- The version is stored in the artifact's OCI config layer

When **installing** artifacts with `falcoctl artifact install`:
- The tool accepts **tolerant semver formats** for maximum flexibility:
  - Full semver: `1.2.3`, `0.6.0`
  - Major-only: `1`, `4`, `0` (normalized to `1.0.0`, `4.0.0`, `0.0.0`)
  - Major.minor: `1.2`, `0.6` (normalized to `1.2.0`, `0.6.0`)
  - With v-prefix: `v1.2.3` (normalized to `1.2.3`)
- The version in the artifact's config layer is used for dependency resolution
- If multiple artifacts depend on different versions of the same dependency, the highest compatible version is selected
- Major version mismatches between dependencies will cause an error

**Note:** This tolerant parsing allows you to pin to major versions (e.g., `falco-rules:0` or `custom-rules:1`) and the tool automatically handles version normalization.

#### Examples

**Install using simple name (uses index):**
```bash
# Installs latest version
$ falcoctl artifact install cloudtrail

# Installs specific version (tag)
$ falcoctl artifact install cloudtrail:0.6.0

# Installs using major-only version
$ falcoctl artifact install falco-rules:0
$ falcoctl artifact install cloudtrail:1
```

**Install using full OCI reference (bypasses index):**
```bash
# Using tag
$ falcoctl artifact install ghcr.io/falcosecurity/plugins/plugin/cloudtrail:latest

# Using digest (immutable)
$ falcoctl artifact install ghcr.io/falcosecurity/plugins/plugin/cloudtrail@sha256:abc123...
```

**Push with proper versioning:**
```bash
# Push with semver version (stored in metadata) and OCI tag
$ falcoctl registry push --type rulesfile --version "1.0.0" \
    ghcr.io/myregistry/myrules:latest myrules.tar.gz

# Push with floating tags for major/minor versions
$ falcoctl registry push --type rulesfile --version "1.2.3" \
    --add-floating-tags ghcr.io/myregistry/myrules:1.2.3 myrules.tar.gz
# This creates tags: 1.2.3, 1.2, 1
```

#### Falcoctl artifact search
The `artifact search` command allows to search for **artifacts** provided by the `index` files configured in *falcoctl*. The command supports searches by name or by keywords and displays all the **artifacts** that match the search. Assuming that we have already configured the `index` provided by the `falcosecurity` organization, the following command shows all the **artifacts** that work with **Kubernetes**:
```bash
$ falcoctl artifact search kubernetes
INDEX           ARTIFACT        TYPE            REGISTRY        REPOSITORY                            
falcosecurity   k8saudit        plugin          ghcr.io         falcosecurity/plugins/plugin/k8saudit 
falcosecurity   k8saudit-rules  rulesfile       ghcr.io         falcosecurity/plugins/ruleset/k8saudit
```

#### Falcoctl artifact info
As per the name, `artifact info` prints some info for a given **artifact**:
```bash
$ falcoctl artifact info k8saudit
REF                                             TAGS                                          
ghcr.io/falcosecurity/plugins/plugin/k8saudit   0.1.0 0.2.0 0.2.1 0.3.0 0.4.0-rc1 0.4.0 latest
```
It shows the OCI **reference** and **tags** for the **artifact** of interest. Thot info is usually used with other commands.

#### Falcoctl artifact install
The above commands help us to find all the necessary info for a given **artifact**. The `artifact install` command installs an **artifact**. It pulls the **artifact** from remote repository, and saves it in a given directory. The following command installs the *k8saudit* plugin in the default path:
```bash
$ falcoctl artifact install k8saudit
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

##### Handling Multiple Versions

Starting from version `v0.12.0`, when multiple versions of the same artifact are specified (e.g., `falcoctl artifact install foo:1.0.0 foo:2.0.0`), the command will automatically keep only the **highest version** and discard the others. A warning message will be displayed to inform you which version was kept and which were discarded. This behavior also applies when resolving dependencies: if different artifacts require different versions of the same dependency, the highest compatible version will be selected.

#### Falcoctl artifact follow
The above commands allow us to keep up-to-date one or more given **artifacts**. The `artifact follow` command checks for updates on a periodic basis and then downloads and installs the latest version, as specified by the passed tags. 
It pulls the **artifact** from remote repository, and saves it in a given directory. The following command installs the *github-rules* rulesfile in the default path:
```bash
 $ falcoctl artifact follow github-rules
 WARN  falcosecurity already exists with the same configuration, skipping
 INFO  Reading all configured index files from "/root/.config/falcoctl/indexes.yaml"
INFO: Creating follower for "github-rules", with check every 6h0m0s
 INFO  Starting follower for "ghcr.io/falcosecurity/plugins/ruleset/github:latest"
 INFO   (ghcr.io/falcosecurity/plugins/ruleset/github:latest) found new version under tag "latest"
 INFO   (ghcr.io/falcosecurity/plugins/ruleset/github:latest) artifact with tag "latest" correctly installed

```

By default, if we give the name of an **artifact** it will search for the **artifact** in the configured `index` files and downlaod the `latest` version. The commands accepts also the OCI **reference** of an **artifact**. In this case, it will ignore the local `index` files.
 The command can specify the directory where to install the *rulesfile* artifacts through the `--rulesfiles-dir` flag (defaults to `/etc/falco`).

 > If the repositories of the **artifacts** your are trying to install are not public then you need to authenticate to the remote registry.
 
 > Please note that only **rulesfile** artifact can be followed.

 ## Falcoctl registry

 The `registry` commands interact with OCI registries allowing the user to authenticate, pull and push artifacts. We have tested the *falcoctl* tool with the **ghcr.io** registry, but it should work with all the registries that support the OCI artifacts.

### Falcoctl registry auth
The `registry auth` command authenticates a user to a given OCI registry.

#### Falcoctl registry auth basic
The `registry auth basic` command authenticates a user to a given OCI registry using HTTP Basic Authentication. Run the command in advance for any private registries.

#### Falcoctl registry auth oauth
The `registry auth oauth` command retrieves access and refresh tokens for OAuth2.0 client credentials flow authentication. Run the command in advance for any private registries.

#### Falcoctl registry auth gcp
The `registry auth gcp` command retrieves access tokens using [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials). In particular, it supports access token retrieval using Google Compute Engine metadata server and Workload Identity, useful to authenticate your deployed Falco workloads. Run the command in advance for Artifact Registry authentication.

Two typical use cases:

1. You are manipulating some rules or plugins and use `falcoctl` to pull or push to an Artifact Registry:
   1. run `gcloud auth application-default login` to generate a JSON credential file that will be used by applications.
   2. run `falcoctl registry auth gcp europe-docker.pkg.dev` for instance to use Application Default Credentials to connect to any repository hosted at `europe-docker.pkg.dev`.
2. You have a Falco instance with Falcoctl as a side car, running in a GKE cluster with Workload Identity enabled:
   1. Workload Identity is correctly set up for the Falco instance (see the [documentation](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)).
   2. Add an environment variable like `FALCOCTL_REGISTRY_AUTH_GCP=europe-docker.pkg.dev` to enable GCP authentication for the `europe-docker.pkg.dev` registry.
   3. The Falcoctl instance will get access tokens from the metadata server and use them to authenticate to the registry and download your rules.

### Falcoctl registry push
It pushes local files and references the artifact uniquely. The following command shows how to push a local file to a remote registry:
```bash
$ falcoctl registry push --type=plugin --version "0.3.0" ghcr.io/falcosecurity/plugins/plugin/cloudtrail:0.3.0 clouddrail-0.3.0-linux-x86_64.tar.gz --platform linux/amd64
```
The type denotes the **artifact** type in this case *plugins*. The `ghcr.io/falcosecurity/plugins/plugin/cloudtrail:0.3.0` is the unique reference that points to the **artifact**.
Currently, *falcoctl* supports only two types of artifacts: **plugin** and **rulesfile**. Based on **artifact type** the commands accepts different flags:
* `--add-floating-tags`: add the floating tags for the major and minor versions
* `--annotation-source`: set annotation source for the artifact;
* `--depends-on`: set an artifact dependency (can be specified multiple times). Example: `--depends-on my-plugin:1.2.3`
* `--tag`: additional artifact tag. Can be repeated multiple time
* `--type`: type of artifact to be pushed. Allowed values: `rulesfile`, `plugin`, `asset`
* `--version`: (**required**) artifact version in semver format (e.g., `1.0.0`, `0.1.2-rc1`). See [Artifact References and Versions](#artifact-references-and-versions) for details.

### Falcoctl registry pull
Pulling **artifacts** involves specifying the reference. The type of **artifact** is not required since the tool will implicitly extract it from the OCI **artifact**:
```
$ falcoctl registry pull ghcr.io/falcosecurity/plugins/plugin/cloudtrail:0.3.0
```

# Falcoctl Environment Variables

The arguments of `falcoctl` can passed as arguments through:
 - command line options
 - environment variables
 - configuration file

The `falcoctl` arguments can be passed through these different modalities are prioritized in the following order: command line options, environment variables, and finally the configuration file. This means that if an argument is passed through multiple modalities, the value set in the command line options will take precedence over the value set in environment variables, which will in turn take precedence over the value set in the configuration file.

This is the list of the environment variable that `falcoctl` will use:

| Name                                      | Content                                                          |
| ----------------------------------------- | ---------------------------------------------------------------- |
| `FALCOCTL_REGISTRY_AUTH_BASIC`            | `registry,username,password;registry1,username1,password1`       |
| `FALCOCTL_REGISTRY_AUTH_OAUTH`            | `registry,client-id,client-secret,token-url;registry1`           |
| `FALCOCTL_REGISTRY_AUTH_GCP`              | `registry;registry1`                                             |
| `FALCOCTL_INDEXES`                        | `index-name,https://falcosecurity.github.io/falcoctl/index.yaml` |
| `FALCOCTL_ARTIFACT_FOLLOW_EVERY`          | `6h0m0s`                                                         |
| `FALCOCTL_ARTIFACT_FOLLOW_CRON`           | `cron-formatted-string`                                          |
| `FALCOCTL_ARTIFACT_FOLLOW_REFS`           | `ref1;ref2`                                                      |
| `FALCOCTL_ARTIFACT_FOLLOW_FALCOVERSIONS`  | `falco-version-url`                                              |
| `FALCOCTL_ARTIFACT_FOLLOW_RULESFILEDIR`   | `rules-directory-path`                                           |
| `FALCOCTL_ARTIFACT_FOLLOW_PLUGINSDIR`     | `plugins-directory-path`                                         |
| `FALCOCTL_ARTIFACT_FOLLOW_TMPDIR`         | `tmp-directory-path`                                             |
| `FALCOCTL_ARTIFACT_INSTALL_REFS`          | `ref1;ref2`                                                      |
| `FALCOCTL_ARTIFACT_INSTALL_RULESFILESDIR` | `rules-directory-path`                                           |
| `FALCOCTL_ARTIFACT_INSTALL_PLUGINSDIR`    | `plugins-directory-path`                                         |
| `FALCOCTL_ARTIFACT_NOVERIFY`              |                                                                  | 

Please note that when passing multiple arguments via an environment variable, they must be separated by a semicolon. Moreover, multiple fields of the same argument must be separated by a comma.

Here is an example of `falcoctl` usage with environment variables:

```bash
$ export FALCOCTL_REGISTRY_AUTH_OAUTH="localhost:6000,000000,999999,http://localhost:9096/token"
$ falcoctl registry oauth 
```

# Container image signature verification

Official container images for Falcoctl, starting from version 0.5.0, are signed with [cosign](https://github.com/sigstore/cosign) v2. To verify the signature run:

```bash
$ FALCOCTL_VERSION=x.y.z # e.g. 0.5.0
$ cosign verify docker.io/falcosecurity/falcoctl:$FALCOCTL_VERSION --certificate-oidc-issuer=https://token.actions.githubusercontent.com --certificate-identity-regexp=https://github.com/falcosecurity/falcoctl/ --certificate-github-workflow-ref=refs/tags/v$FALCOCTL_VERSION
```
