//go:build with_gvisor && (darwin || ios)

package sing_tun

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	tun "github.com/metacubex/sing-tun"
)

const (
	packetFlowIPv4 = 2
	packetFlowIPv6 = 30
)

// PacketFlowTun adapts raw packets from a Network Extension packet flow to
// mihomo's gVisor TUN stack without opening another utun interface.
type PacketFlowTun struct {
	endpoint *channel.Endpoint
	context  context.Context
	cancel   context.CancelFunc
	emit     func([]byte, int) error
	close    sync.Once
}

var _ tun.GVisorTun = (*PacketFlowTun)(nil)

func NewPacketFlowTun(mtu uint32, emit func([]byte, int) error) *PacketFlowTun {
	if mtu == 0 {
		mtu = 1500
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &PacketFlowTun{
		endpoint: channel.New(1024, mtu, ""),
		context:  ctx,
		cancel:   cancel,
		emit:     emit,
	}
	go p.drainOutboundPackets()
	return p
}

func (p *PacketFlowTun) InjectPacket(packet []byte, family int) error {
	protocol, err := packetFlowProtocol(packet, family)
	if err != nil {
		return err
	}

	// gVisor owns the buffer after InjectInbound returns. Copy the FFI input
	// so neither side retains memory owned by the other runtime.
	payload := buffer.MakeWithData(append([]byte(nil), packet...))
	p.endpoint.InjectInbound(protocol, stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: payload}))
	return nil
}

func (p *PacketFlowTun) Read([]byte) (int, error) {
	<-p.context.Done()
	return 0, io.ErrClosedPipe
}

func (p *PacketFlowTun) Write(packet []byte) (int, error) {
	family := packetFlowIPv4
	if len(packet) > 0 && packet[0]>>4 == 6 {
		family = packetFlowIPv6
	}
	if err := p.emit(append([]byte(nil), packet...), family); err != nil {
		return 0, err
	}
	return len(packet), nil
}

func (p *PacketFlowTun) Close() error {
	p.close.Do(func() {
		p.cancel()
		p.endpoint.Close()
	})
	return nil
}

func (p *PacketFlowTun) WritePacket(packet *stack.PacketBuffer) (int, error) {
	data, family := packetData(packet)
	if len(data) == 0 {
		return 0, nil
	}
	if err := p.emit(data, family); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (p *PacketFlowTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return p.endpoint, stack.NICOptions{}, nil
}

func (p *PacketFlowTun) drainOutboundPackets() {
	for {
		packet := p.endpoint.ReadContext(p.context)
		if packet == nil {
			return
		}
		data, family := packetData(packet)
		packet.DecRef()
		if len(data) > 0 {
			_ = p.emit(data, family)
		}
	}
}

func packetFlowProtocol(packet []byte, family int) (tcpip.NetworkProtocolNumber, error) {
	switch family {
	case packetFlowIPv4:
		return header.IPv4ProtocolNumber, nil
	case packetFlowIPv6:
		return header.IPv6ProtocolNumber, nil
	default:
		if len(packet) > 0 {
			switch packet[0] >> 4 {
			case 4:
				return header.IPv4ProtocolNumber, nil
			case 6:
				return header.IPv6ProtocolNumber, nil
			}
		}
		return 0, fmt.Errorf("unsupported packet family %d", family)
	}
}

func packetData(packet *stack.PacketBuffer) ([]byte, int) {
	view := packet.ToView()
	if view == nil {
		return nil, 0
	}
	defer view.Release()

	family := packetFlowIPv4
	if packet.NetworkProtocolNumber == header.IPv6ProtocolNumber {
		family = packetFlowIPv6
	}
	return append([]byte(nil), view.AsSlice()...), family
}
