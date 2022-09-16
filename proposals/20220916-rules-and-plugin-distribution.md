# Falco Rules and Plugin distribution
This proposal aims to implement a client and related infrastructure code that allows users quickly consume and install rules and plugins distributed by the Falcosecurity organization. 

This is a first step in the long-term plan to revamp `falcoctl` to make it a first citizen of the Falco ecosystem (see https://github.com/falcosecurity/falcoctl/issues/136).

## Background

Currently, installing **plugins** is a rather involved operation, as it requires manually finding and downloading the compiled plugin for the right architecture and then manually copying it somewhere where it can be accessed by the target Falco installation. Note that Falco could be installed in several ways (according to https://falco.org/docs/getting-started/installation/), mainly:
* Locally on various Linux distributions
* On Kubernetes (with Helm or by other means)

Especially in the Kubernetes case, this is rather painful and involved operation since the helm chart doesn't help the user place the plugin files on the nodes.

For **rules files**, the problem is similar, since it's a matter of copying a specific file into a location accessible by Falco before the main executable is started.

Both rules and plugins are potentially interconnected since some ruleset require specific plugins (or a class of plugins) to exist.

## Goals (in scope)

We want to help DevOps/DevSecOps/Security engineers who use Falco performing the following operations:

* **Search** interesting plugins and rulesets for their use case, such as monitoring cloudwatch, kubernetes logs for their managed system (EKS, GCP, ...)
* **Specify a list of plugins and rules** that need to be installed from _repositories_ (which could be managed by the Falco Organization, provided by third parties or custom, both public or private) in such a way that they could be installed locally or added to Helm configuration for easy automated deployment of a Falco installation that contain the requested plugins and rules. Additionally, this functionality could enable _subscribing_ to rule repositories that may change over time and could be updated and synced without needing to redeploy Falco.

Also, we want to allow repository maintainers and advanced users to:

* **Manage their repositories** so they can upload versioned rulesets and plugins in a public or private repository that they own

Moreover, the intent is to create a future-proof implementation (it must be enough generic to support other kinds of **artifacts** in the future).

## Non-Goals (out of scope)

This effort currently **does not aim** to provide automated ways to:
* Manage a Falco installation, in terms of installing/uninstalling/upgrading/starting/stopping the Falco binary or process
* Modify the state of an existing and running Falco installation such as remotely adding/removing/upgrading plugins on a target cluster

## Implementation

We're going to use `falcoctl` as the helper tool that every user or script interacts with to achieve the goals above.

Artifacts are **plugin**s or **rules file**s.

The artifacts can be stored in any OCI compliant registry (they work like container image registries) such as GitHub packages. Registries can store artifacts for different platforms in the same way container images are distributed for different platforms (e.g. both linux+x86_64, linux+arm64 ...)

Since registries can hold repos (e.g. `ghcr.io/falcosecurity/awesome-plugins`) with tags but do not have features to get a list of the repos we are going to use **index files** served over HTTPS to make it easier to locate the repo. Both registries and indexes can be public or private, using OCI repository login and http basic auth respectively.

Users can supply a list of registries that can be used.

### Index file overview

The index will be implemented as a YAML file containing a list of entries. Each entry represents an artifact, and its structure should be like the following:

```yaml
  - name: k8saudit # mandatory
    registry: ghcr.io # mandatory
    repository: falcosecurity/k8saudit # mandatory****
    type: plugin # # mandatory, can be (plugin|rulesfile) (e.g. `application/vnd.cncf.falco.*<type>*.layer.v1+tar.gz`)
    description: Read Kubernetes Audit Events and monitor Kubernetes Clusters from EKS # mandatory because of the "search"
    license: Apache-2.0 # License IDs refer to the SPDX License List at https://spdx.org/licenses
    keywords: # mandatory because of the "search"
      - monitoring
      - security
      - alerting
      - metric
      - troubleshooting
      - run-time
    home: https://falco.org
    sources:
      - https://github.com/falcosecurity/falco
    maintainers:
      - name: The Falco Authors
        email: cncf-falco-dev@lists.cncf.io  
```

Notes:
 - Artifact's releases and versions metadata are stored in the related artifact repository.
 - References to artifacts are similar to references to a container image (see the section below).

### Reference to an artifact

It can be one of:
- name (es. `k8saudit`) -> need to use the index for lookup
- `ghcr.io/falcosecurity/k8saudit` -> use the registry only and look for the `latest` tag
- `ghcr.io/falcosecurity/k8saudit:tag` -> use the registry only and use the given tag (ie. the version)
- `ghcr.io/falcosecurity/k8saudit@sha..` -> use the registry only and use the digets

N.B.: except for the first point, all other must be OCI compliant

### Examples of `falcoctl` commands

Index management:
- `falcoctl index add [NAME] [URL] [flags]`
- `falcoctl index remove [INDEX1 [INDEX2 ...]] [flags]`
- `falcoctl index list [flags]`
- `falcoctl index update [INDEX1 [INDEX2 ...]] [flags]`

Repository management:
- `falcoctl repo push <artifact-refs> [flags]`
- `falcoctl repo pull <artifact-refs>`
- `falcoctl repo login`
- `falcoctl repo logout`

Artifacts actions:
- `falcoctl artifact search [keyword1 [keyword2 ...]] [flags]`
- `falcoctl artifact info [--type=...] <artifact-refs>`
- `falcoctl artifact install [--type=...] <artifact-refs>`
