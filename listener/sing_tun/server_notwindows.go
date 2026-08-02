//go:build !windows

package sing_tun

import (
	tun "github.com/metacubex/sing-tun"
)

func tunNew(options tun.Options) (tun.Tun, error) {
	if tunIf, embedded, err := embeddedTunFactory(options); embedded {
		return tunIf, err
	}
	return tun.New(options)
}
