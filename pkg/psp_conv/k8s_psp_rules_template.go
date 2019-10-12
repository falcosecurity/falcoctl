/*
Copyright © 2019 The Falco Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package converter

var (
	K8sPspRulesTemplate string = `
- required_engine_version: 5

- list: psp_images
  items: {{index .Annotations "falco-rules-psp-images"}}

# K8s audit specific macros here
- macro: psp_ka_always_true
  condition: (jevt.rawtime exists)

- macro: psp_ka_never_true
  condition: (jevt.rawtime=0)

- macro: psp_ka_enabled
  condition: (psp_ka_always_true)

- macro: psp_kevt
  condition: (jevt.value[/stage] in ("ResponseComplete"))

- macro: psp_ka_pod
  condition: (ka.target.resource=pods and not ka.target.subresource exists)

- macro: psp_ka_container
  condition: (psp_ka_enabled and psp_kevt and psp_ka_pod and ka.verb=create and ka.req.pod.containers.image.repository in (psp_images))

# syscall audit specific macros here
- macro: psp_always_true
  condition: (evt.num>=0)

- macro: psp_never_true
  condition: (evt.num=0)

- macro: psp_enabled
  condition: (psp_always_true)

- macro: psp_container
  condition: (psp_enabled and container.image.repository in (psp_images))

- macro: psp_open_write
  condition: (evt.type=open or evt.type=openat) and evt.is_open_write=true and fd.typechar='f' and fd.num>=0

{{ if not .Spec.Privileged }}
#########################################
# Rule(s) for PSP privileged property
#########################################
- rule: PSP Violation (privileged) K8s Audit
  desc: >
    Detect a psp validation failure for a privileged pod using k8s audit logs
  condition: psp_ka_container and ka.req.pod.containers.privileged intersects (true)
  output: Pod Security Policy {{ .Name }} validation failure--pod with privileged=true (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec])
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]

- rule: PSP Violation (privileged) System Activity
  desc: Detect a psp validation failure for a privileged pod using syscalls
  condition: psp_container and evt.type=container and container.privileged intersects (true)
  output: Pod Security Policy {{ .Name }} validation failure--container with privileged=true created (user=%user.name command=%proc.cmdline %container.info images=%container.image.repository:%container.image.tag)
  priority: WARNING
  source: syscall
  tags: [k8s-psp]

{{ end }}{{ if not .Spec.HostPID }}
#########################################
# Rule(s) for PSP hostPID property
#########################################
- rule: PSP Violation (hostPID)
  desc: >
    Detect a psp validation failure for a hostPID pod using k8s audit logs
  condition: psp_ka_container and ka.req.pod.host_pid intersects (true)
  output: Pod Security Policy {{ .Name }} validation failure--pod with hostpid=true (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec])
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]
{{ end }}{{ if not .Spec.HostIPC }}
#########################################
# Rule(s) for PSP hostIPC property
#########################################
- rule: PSP Violation (hostIPC)
  desc: >
    Detect a psp validation failure for a hostIPC pod using k8s audit logs
  condition: psp_ka_container and ka.req.pod.host_ipc intersects (true)
  output: Pod Security Policy {{ .Name }} validation failure--pod with hostipc=true (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec])
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]
{{ end }}{{ if not .Spec.HostNetwork }}
#########################################
# Rule(s) for PSP hostNetwork property
#########################################
- rule: PSP Violation (hostNetwork)
  desc: >
    Detect a psp validation failure for a hostNetwork pod using k8s audit logs
  condition: psp_ka_container and ka.req.pod.host_network intersects (true)
  output: Pod Security Policy {{ .Name }} validation failure--pod with hostnetwork=true (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec])
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]
{{ end }}{{ if gt (len .Spec.HostPorts) 0 }}
#########################################
# Rule(s) for PSP hostPorts ranges
#########################################
- rule: PSP Violation (hostPorts)
  desc: >
    Detect a psp validation failure for a hostnetwork port outside of the allowed set using k8s audit logs
  condition: psp_ka_container and not ka.req.pod.containers.host_port in ({{ JoinHostPortRanges .Spec.HostPorts }},"<NA>")
  output: Pod Security Policy {{ .Name }} validation failure--hostnetwork port outside of allowed ranges ({{ JoinHostPortRanges .Spec.HostPorts }}) (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec])
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]
{{ end }}{{ if gt (len .Spec.Volumes) 0 }}
#########################################
# Rule(s) for PSP volumes property
#########################################
- rule: PSP Violation (volumes)
  desc: >
    Detect a psp validation failure for a volume type outside of the allowed set using k8s audit logs
  condition: psp_ka_container and not ka.req.pod.volumes.volume_type in ({{ JoinFSTypes .Spec.Volumes}},"<NA>")
  output: Pod Security Policy {{ .Name }} validation failure--volume type outside of allowed set ({{ JoinFSTypes .Spec.Volumes }}) (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec])
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]
{{ end }}{{ if gt (len .Spec.AllowedHostPaths) 0 }}
#########################################
# Rule(s) for PSP allowedHostPaths property
#########################################
- rule: PSP Violation (allowedHostPaths)
  desc: >
    Detect a psp validation failure for a hostPath volume with a path outside of the allowed set using k8s audit logs
  condition: psp_ka_container and not ka.req.pod.volumes.hostpath pmatch ({{ JoinHostPaths .Spec.AllowedHostPaths }},"<NA>")
  output: Pod Security Policy {{ .Name }} validation failure--hostPath volume mounting path outside of allowed set ({{ JoinHostPaths .Spec.AllowedHostPaths }}) (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec])
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]
{{ end }}{{ if gt (len .Spec.AllowedFlexVolumes) 0 }}
#########################################
# Rule(s) for PSP allowedFlexVolumes property
#########################################
- rule: PSP Violation (allowedFlexVolumes)
  desc: >
    Detect a psp validation failure for a FlexVolume driver outside of the allowed set using k8s audit logs
  condition: psp_ka_container and not ka.req.pod.volumes.flexvolume_driver in ({{JoinFlexvolumes .Spec.AllowedFlexVolumes}},"<NA>")
  output: Pod Security Policy {{ .Name }} validation failure--Flexvolume driver outside of allowed set ({{JoinFlexvolumes .Spec.AllowedFlexVolumes}}) (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec])
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]
{{ end }}{{ if ne .Spec.FSGroup.Rule "RunAsAny" }}
#########################################
# Rule(s) for PSP fsGroup property
#########################################
- macro: psp_fs_group_must_run_matches
{{ if eq .Spec.FSGroup.Rule "MustRunAs" }}  condition: ka.req.pod.fs_group in ({{ JoinIDRanges .Spec.FSGroup.Ranges }})
{{ else }}  condition: (psp_ka_always_true)
{{ end }}
- macro: psp_fs_group_may_run_matches
{{ if eq .Spec.FSGroup.Rule "MayRunAs" }}  condition: ka.req.pod.fs_group in ({{ JoinIDRanges .Spec.FSGroup.Ranges }},"<NA>")
{{ else }}  condition: (psp_ka_always_true)
{{ end }}
- macro: psp_fs_group
  condition: (psp_fs_group_must_run_matches and psp_fs_group_may_run_matches)

- rule: PSP Violation (fsGroup)
  desc: >
    Detect a psp validation failure for a fsGroup gid outside of the allowed set using k8s audit logs
  condition: psp_ka_container and not psp_fs_group
  output: Pod Security Policy {{ .Name }} validation failure--fsGroup outside of allowed set. Rule={{ .Spec.FSGroup.Rule}} ranges= ({{ JoinIDRanges .Spec.FSGroup.Ranges }}) (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec])
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]
{{ end }}{{ if .Spec.ReadOnlyRootFilesystem }}
#########################################
# Rule(s) for PSP readOnlyRootFilesystem property
#########################################
- rule: PSP Violation (readOnlyRootFilesystem) K8s Audit
  desc: >
    Detect a psp validation failure for a readOnlyRootFilesystem pod using k8s audit logs
  condition: psp_ka_container and not ka.req.pod.containers.read_only_fs in (true)
  output: Pod Security Policy {{ .Name }} validation failure--pod without readOnlyRootFilesystem=true (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec])
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]

- rule: PSP Violation (readOnlyRootFilesystem) System Activity
  desc: >
    Detect a psp validation failure for a readOnlyRootFilesystem pod using syscalls
  condition: psp_container and psp_open_write
  output: >
    Pod Security Policy {{ .Name }} validation failure--write in container with readOnlyRootFilesystem=true
    (user=%user.name command=%proc.cmdline file=%fd.name parent=%proc.pname container_id=%container.id images=%container.image.repository)
  priority: WARNING
  source: syscall
  tags: [k8s-psp]
{{ end }}{{ if eq .Spec.RunAsUser.Rule "MustRunAs" }}
#########################################
# Rule(s) for PSP runAsUser property: MustRunAs + list of uids
#########################################
- rule: PSP Violation (runAsUser=MustRunAs) K8s Audit
  desc: >
    Detect a psp validation failure for a runAsUser outside of the allowed set using k8s audit logs
  condition: psp_ka_container and not (ka.req.pod.containers.eff_run_as_user in ({{ JoinIDRanges .Spec.RunAsUser.Ranges }}))
  output: Pod Security Policy {{ .Name }} validation failure--runAsUser outside of allowed set. runAsUser set=({{ JoinIDRanges .Spec.RunAsUser.Ranges }}) (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec]FOO=%ka.req.pod.containers.eff_run_as_user)
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]

- macro: psp_allowed_uids
  condition: >
   (
     {{ range $idx, $range := .Spec.RunAsUser.Ranges }} {{ if $idx}} or {{ end }}(user.uid >= {{ $range.Min }} and user.uid <= {{ $range.Max }}){{ end }}
   )

- rule: PSP Violation (runAsUser=MustRunAs) System Activity
  desc: >
    Detect a psp validation failure for a runAsUser outside of the allowed set using syscalls
  condition: psp_container and evt.type in (execve, setuid) and evt.dir=< and not psp_allowed_uids
  output: Pod Security Policy {{ .Name }} validation failure--runAsUser outside of allowed set. runAsUser set=({{ JoinIDRanges .Spec.RunAsUser.Ranges }}) (command=%proc.cmdline uid=%user.uid container_id=%container.id images=%container.image.repository)
  priority: WARNING
  source: syscall
  tags: [k8s-psp]
{{ end }}{{ if eq .Spec.RunAsUser.Rule "MustRunAsNonRoot" }}
#########################################
# Rule(s) for PSP runAsUser property: MustRunAsNonRoot
#########################################
- rule: PSP Violation (runAsUser=MustRunAsNonRoot) K8s Audit
  desc: >
    Detect a psp validation failure for a uid=0 runAsUser when MustRunAsNonRoot is set using k8s audit logs
  condition: psp_ka_container and (ka.req.pod.containers.eff_run_as_user intersects ("0:0"))
  output: Pod Security Policy {{ .Name }} validation failure--uid 0 runAsUser when MustRunAsNonRoot is set (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec])
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]

- rule: PSP Violation (runAsUser=MustRunAsNonRoot) System Activity
  desc: >
    Detect a psp validation failure for a uid=0 user when MustRunAsNonRoot is set using syscalls
  condition: psp_container and evt.type in (execve, setuid) and evt.dir=< and user.uid=0
  output: Pod Security Policy {{ .Name }} validation failure--root user when MustRunAsNonRoot is set (command=%proc.cmdline uid=%user.uid container_id=%container.id images=%container.image.repository)
  priority: WARNING
  source: syscall
  tags: [k8s-psp]
{{ end }}{{ if .Spec.RunAsGroup }}{{ if eq .Spec.RunAsGroup.Rule "MustRunAs" }}
#########################################
# Rule(s) for PSP runAsGroup property: MustRunAs + list of gids
#########################################
- rule: PSP Violation (runAsGroup=MustRunAs) K8s Audit
  desc: >
    Detect a psp validation failure for a runAsGroup outside of the MustRunAs allowed set using k8s audit logs
  condition: psp_ka_container and not (ka.req.pod.containers.eff_run_as_group in ({{ JoinIDRanges .Spec.RunAsGroup.Ranges }}))
  output: Pod Security Policy {{ .Name }} validation failure--runAsGroup outside of the MustRunAs allowed set. runAsGroup MustRunAs set=({{ JoinIDRanges .Spec.RunAsUser.Ranges }}) (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec])
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]

- macro: psp_allowed_gids
  condition: >
   (
     {{ range $idx, $range := .Spec.RunAsGroup.Ranges }}{{ if $idx }} or {{ end }}(group.gid >= {{ $range.Min }} and group.gid <= {{ $range.Max }}){{ end }}
   )

- rule: PSP Violation (runAsGroup=MustRunAs) System Activity
  desc: >
    Detect a psp validation failure for a runAsGroup outside of the allowed set using syscalls
  condition: psp_container and evt.type in (execve, setgid) and evt.dir=< and not psp_allowed_gids
  output: Pod Security Policy {{ .Name }} validation failure--runAsGroup outside of allowed set. runAsGroup set=({{ JoinIDRanges .Spec.RunAsGroup.Ranges }}) (command=%proc.cmdline user=%user.uid gid=%group.gid container_id=%container.id images=%container.image.repository)
  priority: WARNING
  source: syscall
  tags: [k8s-psp]
{{ end }}{{ if eq .Spec.RunAsGroup.Rule "MayRunAs" }}
#########################################
# Rule(s) for PSP runAsGroup property: MayRunAs + list of gids
#########################################
- rule: PSP Violation (runAsGroup=MayRunAs)
  desc: >
    Detect a psp validation failure for a runAsGroup outside of the MayRunAs allowed set using k8s audit logs
  condition: psp_ka_container and not ka.req.pod.containers.eff_run_as_group in ({{ JoinIDRanges .Spec.RunAsGroup.Ranges }}) and not (ka.req.pod.containers.run_as_group in ("<NA>") and ka.req.pod.run_as_group="<NA>")
  output: Pod Security Policy {{ .Name }} validation failure--runAsGroup outside of the MayRunAs allowed set. runAsGroup MayRunAs set=({{ JoinIDRanges .Spec.RunAsGroup.Ranges }}) (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec])
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]
{{ end }}{{end}}{{ if eq .Spec.SupplementalGroups.Rule "MustRunAs" }}
#########################################
# Rule(s) for PSP supplementalGroups property: MustRunAs + list of gids
#########################################
- rule: PSP Violation (supplementalGroups=MustRunAs)
  desc: >
    Detect a psp validation failure for supplementalGroups outside of the MustRunAs allowed set using k8s audit logs
  condition: psp_ka_container and not ka.req.pod.supplemental_groups in ({{ JoinIDRanges .Spec.SupplementalGroups.Ranges }})
  output: Pod Security Policy {{ .Name }} validation failure--supplementalGroups outside of the MustRunAs allowed set. supplementalGroups MustRunAs set=({{ JoinIDRanges .Spec.SupplementalGroups.Ranges }}) (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec])
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]
{{ end }}{{ if eq .Spec.SupplementalGroups.Rule "MayRunAs" }}
#########################################
# Rule(s) for PSP supplementalGroups property: MayRunAs + list of gids
#########################################
- rule: PSP Violation (supplementalGroups=MayRunAs)
  desc: >
    Detect a psp validation failure for a supplementalGroups outside of the MayRunAs allowed set using k8s audit logs
  condition: psp_ka_container and not ka.req.pod.supplemental_groups in ({{ JoinIDRanges .Spec.SupplementalGroups.Ranges }},"<NA>")
  output: Pod Security Policy {{ .Name }} validation failure--supplementalGroups outside of the MayRunAs allowed set. supplementalGroups MayRunAs set=({{ JoinIDRanges .Spec.SupplementalGroups.Ranges }}) (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec])
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]
{{ end }}{{if not (AllowPrivilegeEscalation .Spec)}}
#########################################
# Rule(s) for PSP allowPrivilegeEscalation property
#########################################

- macro: psp_allow_privilege_escalation
  condition: (ka.req.pod.containers.allow_privilege_escalation intersects (true))

- rule: PSP Violation (allowPrivilegeEscalation)
  desc: >
    Detect a psp validation failure for allowPrivilegeEscalation using k8s audit logs
  condition: psp_ka_container and psp_allow_privilege_escalation
  output: Pod Security Policy {{ .Name }} validation failure--pod with allowPrivilegeEscalation=true (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec])
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]
{{ end }}{{ if gt (len .Spec.AllowedCapabilities) 0 }}
#########################################
# Rule(s) for PSP allowedCapabilities property
#########################################
- rule: PSP Violation (allowedCapabilities)
  desc: >
    Detect a psp validation failure for Allowed Capabilities using k8s audit logs
  condition: psp_ka_container and not ka.req.pod.containers.add_capabilities in ({{ JoinCapabilities .Spec.AllowedCapabilities }},"<NA>")
  output: Pod Security Policy {{ .Name }} validation failure--pod added capabilities outside of allowed set "({{ JoinCapabilities .Spec.AllowedCapabilities }})" (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec])
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]
{{ end }}{{ if gt (len .Spec.AllowedProcMountTypes) 0 }}
#########################################
# Rule(s) for PSP allowedProcMountTypes property
#########################################
- rule: PSP Violation (allowedProcMountTypes)
  desc: >
    Detect a psp validation failure for Allowed Proc Mount Types using k8s audit logs
  condition: psp_ka_container and not ka.req.pod.containers.proc_mount in ({{ JoinProcMountTypes .Spec.AllowedProcMountTypes }},"<NA>")
  output: Pod Security Policy {{ .Name }} validation failure--pod with proc mounts outside of allowed set "({{ JoinProcMountTypes .Spec.AllowedProcMountTypes }})" (user=%ka.user.name pod=%ka.resp.name ns=%ka.target.namespace images=%ka.req.pod.containers.image spec=%jevt.value[/requestObject/spec])
  priority: WARNING
  source: k8s_audit
  tags: [k8s-psp]
{{ end }}
`
)
