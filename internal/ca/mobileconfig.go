// Package ca provides mobileconfig profile generation.
package ca

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/rcarmo/bouncer/internal/config"
)

// GenerateMobileconfig returns an unsigned .mobileconfig XML payload
// containing the root CA certificate for iOS/macOS trust.
func GenerateMobileconfig(cfg *config.Config) ([]byte, error) {
	derBytes, err := CACertDER(cfg)
	if err != nil {
		return nil, fmt.Errorf("mobileconfig: %w", err)
	}
	certBase64 := base64.StdEncoding.EncodeToString(derBytes)

	outerUUID, err := randomUUID()
	if err != nil {
		return nil, err
	}
	innerUUID, err := randomUUID()
	if err != nil {
		return nil, err
	}

	xml := strings.ReplaceAll(mobileconfigTemplate, "{{OUTER_UUID}}", outerUUID)
	xml = strings.ReplaceAll(xml, "{{INNER_UUID}}", innerUUID)
	xml = strings.ReplaceAll(xml, "{{CERT_BASE64}}", certBase64)

	return []byte(xml), nil
}

func randomUUID() (string, error) {
	var buf [16]byte
	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return "", fmt.Errorf("mobileconfig: uuid: %w", err)
	}
	buf[6] = (buf[6] & 0x0f) | 0x40 // Version 4
	buf[8] = (buf[8] & 0x3f) | 0x80 // Variant 1
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16]), nil
}

const mobileconfigTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>PayloadIdentifier</key>
	<string>local.bouncer.rootca</string>
	<key>PayloadUUID</key>
	<string>{{OUTER_UUID}}</string>
	<key>PayloadDisplayName</key>
	<string>Bouncer Local CA</string>
	<key>PayloadDescription</key>
	<string>Installs the Bouncer local root CA so your device trusts the local HTTPS server.</string>
	<key>PayloadOrganization</key>
	<string>Bouncer</string>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>PayloadIdentifier</key>
			<string>local.bouncer.rootca.cert</string>
			<key>PayloadUUID</key>
			<string>{{INNER_UUID}}</string>
			<key>PayloadDisplayName</key>
			<string>Bouncer Root CA</string>
			<key>PayloadContent</key>
			<data>
			{{CERT_BASE64}}
			</data>
		</dict>
	</array>
</dict>
</plist>
`
