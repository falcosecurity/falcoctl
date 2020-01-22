# Falcoctl

A Go CLI tool to interface with Falco, and perform useful tasks in the Falco Runtime Security ecosystem. 

## Call for contributors/maintainers 

This is a Go project that has a lot of potential in the Falco ecosystem, but needs contributions and even a maintainer or two. 

If you would like to get involved with contributing to this specific project, please check out [the Falco community](https://github.com/falcosecurity/community) to get involved.

# The Paradigms 

So `falcoctl` was born out of a need to encapsulate common logic for the project.
Right now there are a lot of scripts, in many languages, and even container images that perform ad-hoc tasks. 
We hope to make `falcoctl` the source of truth for these tasks or chores and give operators a first class experience. 
There are two main avenues in which we perform these tasks with `falcoctl`

 - Locally
 - Remote (Kubernetes)
 
For instance, `falcoctl` supports generating TLS certificate material. 
Installing these certificates for use "locally" has many different implications than remotely installing secrets in Kuberentes.  

## Local

This implies taking action directly on a system. 
If you look in the `/cmd` directory [you can see](https://github.com/falcosecurity/falcoctl/blob/master/cmd/install_tls.go#L1) various examples where the commands are compiled differently for different architectures. 

## Remote

Here is where we would use local configuration to perform basic tasks in Kubernetes with `falco`. 
For instance, installing falco, updating rules, etc.

 