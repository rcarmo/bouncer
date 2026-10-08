package config

// IngressConfig binds a transport to an explicit set of sites.
// Secrets are references only; node identity lives outside the JSON file.
type IngressConfig struct {
	ID      string        `json:"id" yaml:"id"`
	Type    string        `json:"type" yaml:"type"`
	Enabled *bool         `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	SiteIDs []string      `json:"siteIds" yaml:"siteIds"`
	Local   *LocalIngress `json:"local,omitempty" yaml:"local,omitempty"`
	TSNet   *TSNetIngress `json:"tsnet,omitempty" yaml:"tsnet,omitempty"`
}

func (i IngressConfig) IsEnabled() bool { return i.Enabled == nil || *i.Enabled }

type LocalIngress struct {
	Listen         string     `json:"listen" yaml:"listen"`
	TLS            string     `json:"tls,omitempty" yaml:"tls,omitempty"`
	Bootstrap      bool       `json:"bootstrap,omitempty" yaml:"bootstrap,omitempty"`
	TrustedProxies []string   `json:"trustedProxies,omitempty" yaml:"trustedProxies,omitempty"`
	MDNS           MDNSConfig `json:"mdns,omitempty" yaml:"mdns,omitempty"`
}

type TSNetIngress struct {
	Hostname   string `json:"hostname" yaml:"hostname"`
	Port       int    `json:"port,omitempty" yaml:"port,omitempty"`
	FunnelOnly bool   `json:"funnelOnly,omitempty" yaml:"funnelOnly,omitempty"`
	StateDir   string `json:"stateDir,omitempty" yaml:"stateDir,omitempty"`
	AuthKeyEnv string `json:"authKeyEnv,omitempty" yaml:"authKeyEnv,omitempty"`
}
