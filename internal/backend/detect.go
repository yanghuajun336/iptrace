package backend

type Backend string

const (
	BackendLegacy    Backend = "iptables-legacy"
	BackendNFT       Backend = "iptables-nft"
	BackendFirewalld Backend = "firewalld"
	BackendUnknown   Backend = "unknown"
)

func DetectFromLookups(firewalldActive, hasNFTSave, hasLegacySave bool) Backend {
	if firewalldActive {
		return BackendFirewalld
	}
	if hasNFTSave {
		return BackendNFT
	}
	if hasLegacySave {
		return BackendLegacy
	}
	return BackendUnknown
}
