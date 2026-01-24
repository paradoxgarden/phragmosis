package main
import(
	"testing"
)

func TestGetRandBytes(t *testing.T){
	tests:= []struct {
		name string
		size int
		want int
	}{
		{"happy path", 12, 12},
		{"happy path large", 128, 128},
		{"happy path very large", 512, 512},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := getRandBytes(tt.size)
			if len(got) != tt.want {
				t.Errorf("getRandBytes(%q), want %v", tt.size, tt.want)
			}
		})
	}
}
