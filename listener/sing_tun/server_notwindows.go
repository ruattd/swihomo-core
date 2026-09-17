//go:build !windows

package sing_tun

import (
	"github.com/metacubex/mihomo/bridge/packetflow"
	tun "github.com/metacubex/sing-tun"
)

func tunNew(options tun.Options) (tun.Tun, error) {
	if tunIf, embedded, err := packetflow.EmbeddedTunFactory(options); embedded {
		return tunIf, err
	}
	return tun.New(options)
}
