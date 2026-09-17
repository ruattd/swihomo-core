//go:build with_gvisor && (darwin || ios)

package packetflow

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
	C "github.com/metacubex/mihomo/constant"
	tun "github.com/metacubex/sing-tun"
)

const (
	packetFlowIPv4 = 2
	packetFlowIPv6 = 30

	// inboundQueueSize bounds packets buffered between InjectPacket and the
	// raw stack's read loop. Sized like the gVisor channel endpoint.
	inboundQueueSize = 1024
)

// PacketFlowTun adapts raw packets from a Network Extension packet flow to
// mihomo's TUN stacks without opening another utun interface. In gVisor mode
// packets are injected into a channel endpoint; in raw mode (mips stack)
// they queue for Read instead.
type PacketFlowTun struct {
	endpoint *channel.Endpoint
	inbound  chan []byte
	raw      bool
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
		context: ctx,
		cancel:  cancel,
		emit:    emit,
	}
	if StackMode() == C.TunGvisor {
		p.endpoint = channel.New(inboundQueueSize, mtu, "")
		go p.drainOutboundPackets()
	} else {
		p.raw = true
		p.inbound = make(chan []byte, inboundQueueSize)
	}
	return p
}

func (p *PacketFlowTun) InjectPacket(packet []byte, family int) error {
	if p.raw {
		// Never block: the bridge may hold its state lock while injecting,
		// and Close runs under the same lock. Drop on a full queue like the
		// gVisor channel endpoint does.
		select {
		case p.inbound <- append([]byte(nil), packet...):
		default:
		}
		return nil
	}

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

func (p *PacketFlowTun) Read(packet []byte) (int, error) {
	if p.raw {
		select {
		case inbound := <-p.inbound:
			// Truncating an over-MTU packet matches kernel utun semantics.
			return copy(packet, inbound), nil
		case <-p.context.Done():
			return 0, io.ErrClosedPipe
		}
	}
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
		if p.endpoint != nil {
			p.endpoint.Close()
		}
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
	if p.endpoint == nil {
		return nil, stack.NICOptions{}, fmt.Errorf("packet-flow TUN has no gVisor endpoint in raw mode")
	}
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
