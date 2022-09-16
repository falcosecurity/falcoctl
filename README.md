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
