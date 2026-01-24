package main

import (
	"testing"
)
func ptr[T any](v T) *T {
    return &v
}
func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name string
		conf *config
		want error
	}{
		{
			name: "minimum valid config",
			conf: &config{
				TailscaleSock: ptr("/var/sock"),
				DomainName:    ptr("example.com"),
				Port:          ptr("10999"),
			},
			want: nil,
		},
	}
for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.conf.validateConfig()
			if got != tt.want {
				t.Errorf("%v.validateConfig, want %v", *tt.conf, tt.want)
			}
		})
	}

}
