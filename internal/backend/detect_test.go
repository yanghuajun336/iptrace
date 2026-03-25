package backend

import "testing"

func TestDetectFromLookups(t *testing.T) {
	tests := []struct {
		name             string
		firewalldActive  bool
		hasNFTSave       bool
		hasLegacySave    bool
		expectBackend    Backend
	}{
		{
			name:            "firewalld 优先",
			firewalldActive: true,
			hasNFTSave:      true,
			hasLegacySave:   true,
			expectBackend:   BackendFirewalld,
		},
		{
			name:            "nft 次优先",
			hasNFTSave:      true,
			hasLegacySave:   true,
			expectBackend:   BackendNFT,
		},
		{
			name:          "legacy 回退",
			hasLegacySave: true,
			expectBackend: BackendLegacy,
		},
		{
			name:          "未知后端",
			expectBackend: BackendUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectFromLookups(tt.firewalldActive, tt.hasNFTSave, tt.hasLegacySave)
			if got != tt.expectBackend {
				t.Fatalf("expect %q, got %q", tt.expectBackend, got)
			}
		})
	}
}
