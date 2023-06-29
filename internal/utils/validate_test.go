package utils

import "testing"

func TestNameFromRef(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		want    string
		wantErr bool
	}{
		{"reg_repo_tag", "ghcr.io/falcosecurity/rules/my_rule:0.1.0", "my_rule", false},
		{"reg_repo_hash", "ghcr.io/falcosecurity/rules/my_rule@sha256:67df5990affad0d8f0b13c6e611733f3b5725029135368207ed0e4d58341b5d7", "my_rule", false},
		{"reg_repo_tag_hash", "ghcr.io/falcosecurity/rules/my_rule:0.1.0@sha256:67df5990affad0d8f0b13c6e611733f3b5725029135368207ed0e4d58341b5d7", "my_rule", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NameFromRef(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("NameFromRef() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NameFromRef() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRepositoryFromRef(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		want    string
		wantErr bool
	}{
		{"reg_repo_tag", "ghcr.io/falcosecurity/rules/my_rule:0.1.0", "ghcr.io/falcosecurity/rules/my_rule", false},
		{"reg_repo_hash", "ghcr.io/falcosecurity/rules/my_rule@sha256:67df5990affad0d8f0b13c6e611733f3b5725029135368207ed0e4d58341b5d7", "ghcr.io/falcosecurity/rules/my_rule", false},
		{"reg_repo_tag_hash", "ghcr.io/falcosecurity/rules/my_rule:0.1.0@sha256:67df5990affad0d8f0b13c6e611733f3b5725029135368207ed0e4d58341b5d7", "ghcr.io/falcosecurity/rules/my_rule", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RepositoryFromRef(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("RepositoryFromRef() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("RepositoryFromRef() got = %v, want %v", got, tt.want)
			}
		})
	}
}
