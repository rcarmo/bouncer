package config

// IngressConfig binds a transport to an explicit set of sites.
// Secrets are references only; node identity lives outside the JSON file.
type IngressConfig struct {
	ID      string        `json:"id"`
	Type    string        `json:"type"`
	Enabled *bool         `json:"enabled,omitempty"`
	SiteIDs []string      `json:"siteIds"`
	Local   *LocalIngress `json:"local,omitempty"`
	TSNet   *TSNetIngress `json:"tsnet,omitempty"`
}

func (i IngressConfig) IsEnabled() bool { return i.Enabled == nil || *i.Enabled }

type LocalIngress struct {
	Listen         string     `json:"listen"`
	TLS            string     `json:"tls,omitempty"`
	Bootstrap      bool       `json:"bootstrap,omitempty"`
	TrustedProxies []string   `json:"trustedProxies,omitempty"`
	MDNS           MDNSConfig `json:"mdns,omitempty"`
}

type TSNetIngress struct {
	Hostname   string `json:"hostname"`
	Port       int    `json:"port,omitempty"`
	FunnelOnly bool   `json:"funnelOnly,omitempty"`
	StateDir   string `json:"stateDir,omitempty"`
	AuthKeyEnv string `json:"authKeyEnv,omitempty"`
}
