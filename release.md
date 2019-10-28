# Release Process

Our release process is automated using [goreleaser](https://github.com/goreleaser/goreleaser).

When we release we do the following process:

1. We decide together (usually in the #falco channel in [slack](https://sysdig.slack.com)) what's the next version to tag
2. A person with repository rights does the tag
3. The same person runs goreleaser in their machine following the "Release commands" section below
4. The tag is live on Github with the artifacts
5. Travis builds the tag and push the related docker images

## Release commands

Tag the version

```bash
git tag -a v0.1.0-rc.0 -m "v0.1.0-rc.0"
git push origin v0.1.0-rc.0
```

Run goreleaser, make sure to export your GitHub token first.

```
export GITHUB_TOKEN=<YOUR_GH_TOKEN>
goreleaser --rm-dist
```

