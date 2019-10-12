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

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/ghodss/yaml"

	"k8s.io/api/extensions/v1beta1"

	"strconv"
	"strings"

	"text/template"

	v1 "k8s.io/api/core/v1"
)

type LogFunc func(format string, args ...interface{})

type Converter struct{
	pspTmpl *template.Template
	debugLog LogFunc
	infoLog LogFunc
	errorLog LogFunc
}

func joinProcMountTypes(procMountTypes []v1.ProcMountType) string {
	var sb strings.Builder

	for  idx, procMountType := range procMountTypes {
		if idx > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(string(procMountType))
	}

	return sb.String()
}

func joinCapabilities(capabilities []v1.Capability) string {
	var sb strings.Builder

	for  idx, cap := range capabilities {
		if idx > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(string(cap))
	}

	return sb.String()
}

func joinFSTypes(fsTypes []v1beta1.FSType) string {
	var sb strings.Builder

	for  idx, fsType := range fsTypes {
		if idx > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(string(fsType))
	}

	return sb.String()
}

func joinIDRanges(ranges []v1beta1.IDRange) string {

	var sb strings.Builder

	for idx, idRange := range ranges {
		if idx > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("\"")
		sb.WriteString(strconv.Itoa(int(idRange.Min)))
		sb.WriteString(":")
		sb.WriteString(strconv.Itoa(int(idRange.Max)))
		sb.WriteString("\"")
	}

	return sb.String()
}

func joinHostPortRanges(ranges []v1beta1.HostPortRange) string {

	var sb strings.Builder

	for  idx, portRange := range ranges {
		if idx > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("\"")
		sb.WriteString(strconv.Itoa(int(portRange.Min)))
		sb.WriteString(":")
		sb.WriteString(strconv.Itoa(int(portRange.Max)))
		sb.WriteString("\"")
	}

	return sb.String()
}

func joinHostPaths(ranges []v1beta1.AllowedHostPath) string {

	var sb strings.Builder

	for  idx, path := range ranges {
		if idx > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(path.PathPrefix)
	}

	return sb.String()
}

func joinFlexvolumes(ranges []v1beta1.AllowedFlexVolume) string {

	var sb strings.Builder

	for  idx, path := range ranges {
		if idx > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(path.Driver)
	}

	return sb.String()
}

func allowPrivilegeEscalation(spec v1beta1.PodSecurityPolicySpec) bool {
	if spec.AllowPrivilegeEscalation != nil {
		return *spec.AllowPrivilegeEscalation
	}

	return true
}

func NewConverter(debugLog LogFunc, infoLog LogFunc, errorLog LogFunc) (*Converter, error) {

	tmpl := template.New("pspRules")

	tmpl = tmpl.Funcs(template.FuncMap{
		"JoinProcMountTypes": joinProcMountTypes,
		"JoinCapabilities": joinCapabilities,
		"JoinFSTypes": joinFSTypes,
		"JoinIDRanges": joinIDRanges,
		"JoinHostPortRanges": joinHostPortRanges,
		"JoinHostPaths": joinHostPaths,
		"JoinFlexvolumes": joinFlexvolumes,
		"AllowPrivilegeEscalation": allowPrivilegeEscalation,
	})

	tmpl, err := tmpl.Parse(K8sPspRulesTemplate)

	if err != nil {
		return nil, fmt.Errorf("Could not create rules template: %v", err)
	}

	return &Converter{
		pspTmpl: tmpl,
		debugLog: debugLog,
		infoLog: infoLog,
		errorLog: errorLog,
	}, nil
}

func (c *Converter) GenerateRules(pspString string) (string, error) {

	psp := v1beta1.PodSecurityPolicy{}

	c.debugLog("GenerateRules() pspString=%s", pspString)

	pspJson, err := yaml.YAMLToJSON([]byte(pspString)); if err != nil {
		return "", fmt.Errorf("Could not convert generic yaml document to json: %v", err)
	}

	err = json.Unmarshal(pspJson, &psp)

	if err != nil {
		return "", fmt.Errorf("Could not unmarshal json document: %v", err)
	}

	c.debugLog("PSP Object: %v", psp)

	// The generated rules need a set of images for which
	// to scope the rules. A annotation with the key
	// "falco-rules-psp-images" provides the list of images.
	if _, ok := psp.Annotations["falco-rules-psp-images"]; !ok {
		return "", fmt.Errorf("PSP Yaml Document does not have an annotation \"falco-rules-psp-images\" that lists the images for which the generated rules should apply");
	}

	c.debugLog("Images %v", psp.Annotations["falco-rules-psp-images"])

	var rulesB bytes.Buffer

	err = c.pspTmpl.Execute(&rulesB, psp)

	if err != nil {
		return "", fmt.Errorf("Could not convert PSP to Falco Rules: %v", err)
	}

	c.debugLog("Resulting rules: %s", rulesB.String())

	return rulesB.String(), nil
}
