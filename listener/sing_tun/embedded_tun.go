package sing_tun

import (
	"net/netip"
	"sync"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	tun "github.com/metacubex/sing-tun"
)

type TunFactory func(tun.Options) (tun.Tun, error)

var embeddedTun = struct {
	sync.RWMutex
	factory TunFactory
}{}

// SetTunFactory lets an embedding host provide a packet device instead of
// creating a platform TUN interface. The returned function restores the
// previous factory and must run after the listener has stopped.
func SetTunFactory(factory TunFactory) func() {
	embeddedTun.Lock()
	previous := embeddedTun.factory
	embeddedTun.factory = factory
	embeddedTun.Unlock()

	return func() {
		embeddedTun.Lock()
		embeddedTun.factory = previous
		embeddedTun.Unlock()
	}
}

func embeddedTunFactory(options tun.Options) (tun.Tun, bool, error) {
	embeddedTun.RLock()
	factory := embeddedTun.factory
	embeddedTun.RUnlock()
	if factory == nil {
		return nil, false, nil
	}

	tunIf, err := factory(options)
	return tunIf, true, err
}

func hasEmbeddedTunFactory() bool {
	embeddedTun.RLock()
	defer embeddedTun.RUnlock()
	return embeddedTun.factory != nil
}

// NormalizeForEmbeddedTun ignores TUN fields that only make sense when
// mihomo owns the operating system interface. Profile routing behavior and
// DNS hijacking remain configured by the user's YAML.
func NormalizeForEmbeddedTun(options LC.Tun) LC.Tun {
	if !hasEmbeddedTunFactory() {
		return options
	}

	options.Enable = true
	options.Device = "swihomo-packet-flow"
	options.Stack = C.TunGvisor
	options.AutoRoute = false
	options.AutoDetectInterface = false
	options.AutoRedirect = false
	options.AutoRedirectInputMark = 0
	options.AutoRedirectOutputMark = 0
	options.AutoRedirectIPRoute2FallbackRuleIndex = 0
	options.FileDescriptor = 0
	options.GSO = false
	options.RecvMsgX = false
	options.SendMsgX = false
	options.StrictRoute = false
	options.IncludeInterface = nil
	options.ExcludeInterface = nil
	options.IncludeUID = nil
	options.IncludeUIDRange = nil
	options.ExcludeUID = nil
	options.ExcludeUIDRange = nil
	options.IncludeAndroidUser = nil
	options.IncludePackage = nil
	options.ExcludePackage = nil
	options.IncludeMACAddress = nil
	options.ExcludeMACAddress = nil
	options.Inet4Address = []netip.Prefix{netip.MustParsePrefix("198.18.0.1/24")}
	options.Inet6Address = []netip.Prefix{netip.MustParsePrefix("fd00::1/64")}
	options.Inet4RouteAddress = nil
	options.Inet6RouteAddress = nil
	options.Inet4RouteExcludeAddress = nil
	options.Inet6RouteExcludeAddress = nil

	return options
}
