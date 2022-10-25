<p align="center"><img src="https://raw.githubusercontent.com/falcosecurity/community/master/logo/primary-logo.png" width="360"></p>
<p align="center"><b>Cloud Native Runtime Security.</b></p>

<hr>

# 🧰 falcoctl

> A CLI tool to work with Falco, and perform useful tasks.

## 📣 Call for contributors/maintainers

This is a Go project that has a lot of potential in the Falco ecosystem, but needs contributions and even a maintainer or two.

If you would like to get involved with contributing to this specific project, please check out [the Falco community](https://github.com/falcosecurity/community) to get involved.

## ⚠️ Current status

👷‍♀️ **Under active development** 👷‍♂️

So `falcoctl` was born out of a need to encapsulate common logic for the project.
Right now there are a lot of scripts, in many languages, and even container images that perform ad-hoc tasks.
We hope to make `falcoctl` the source of truth for these tasks or chores and give operators a first class experience.

Recently, we started an effort to revamp this project and make it a first-class citizen in the Falco ecosystem. As the first step, we are currently working on implementing a [proposal](proposals/20220916-rules-and-plugin-distribution.md) to allow our users to consume and install distributed plugins and rules files easily.

## Installation
### Install falcoctl manually
You can download and install *falcoctl* manually following the appropriate instructions based on your operating system architecture.
#### Linux
##### AMD64
```bash
curl --fail -LS "https://github.com/falcosecurity/falcoctl/releases/download/v0.2.0-rc1/falcoctl_0.2.0-rc1_linux_amd64.tar.gz" | tar -xz
sudo install -o root -g root -m 0755 falcoctl /usr/local/bin/falcoctl
```
##### ARM64
```bash
curl --fail -LS "https://github.com/falcosecurity/falcoctl/releases/download/v0.2.0-rc1/falcoctl_0.2.0-rc1_linux_arm64.tar.gz" | tar -xz
sudo install -o root -g root -m 0755 falcoctl /usr/local/bin/falcoctl
```
> NOTE: Make sure */usr/local/bin* is in your PATH environment variable.

#### MacOS
##### Intel
```bash
curl --fail -LS "https://github.com/falcosecurity/falcoctl/releases/download/v0.2.0-rc1/falcoctl_0.2.0-rc1_darwin_amd64.tar.gz" | tar -xz
chmod +x falcoctl
sudo mv falcoctl /usr/local/bin/falcoctl
```
##### Apple Silicon
```bash
curl --fail -LS "https://github.com/falcosecurity/falcoctl/releases/download/v0.2.0-rc1/falcoctl_0.2.0-rc1_darwin_arm64.tar.gz" | tar -xz
chmod +x falcoctl
sudo mv falcoctl /usr/local/bin/falcoctl
```
#### Windows
```bash
curl --fail -LS "https://github.com/falcosecurity/falcoctl/releases/download/v0.2.0-rc1/falcoctl_0.2.0-rc1_windows_amd64.tar.gz" | tar -xz
```
And move it to a file location in your system **PATH**

Alternatively, you can manually download *falcoctl* from the [falcoctl releases](https://github.com/falcosecurity/falcoctl/releases) page on GitHub.

### Install falcoctl from source
You can install *falcoctl* from source. First thing clone the *falcoctl* repository, build the *falcoctl* binary, and move it to a file location in you system **PATH**.
```bash
git clone https://github.com/falcosecurity/falcoctl.git
cd falcoctl
make falcoctl
sudo mv falcoctl /usr/local/bin/falcoctl
```