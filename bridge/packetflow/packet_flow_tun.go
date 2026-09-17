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
	// outboundQueueSize bounds packets buffered between the raw stack's
	// write loop and the emit drain. Sized like the gVisor channel endpoint.
	outboundQueueSize = 1024
	// emitBatchSize caps how many outbound packets one emit call carries.
	emitBatchSize = 32
)

// PacketFlowTun adapts raw packets from a Network Extension packet flow to
// mihomo's TUN stacks without opening another utun interface. In gVisor mode
// packets are injected into a channel endpoint; in raw mode (mips stack)
// they queue for Read instead. Outbound packets are emitted in batches to
// amortize the FFI crossing into Network Extension.
type PacketFlowTun struct {
	endpoint *channel.Endpoint
	inbound  chan []byte
	outbound chan []byte
	raw      bool
	context  context.Context
	cancel   context.CancelFunc
	emit     func(packets [][]byte, families []int) error
	close    sync.Once
}

var _ tun.GVisorTun = (*PacketFlowTun)(nil)

func NewPacketFlowTun(mtu uint32, emit func(packets [][]byte, families []int) error) *PacketFlowTun {
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
		go p.drainEndpoint()
	} else {
		p.raw = true
		p.inbound = make(chan []byte, inboundQueueSize)
		p.outbound = make(chan []byte, outboundQueueSize)
		go p.drainOutboundQueue()
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
	if !p.raw {
		// The gVisor stack writes through the channel endpoint or
		// WritePacket; a direct Write falls back to a single-packet emit.
		if err := p.emit([][]byte{append([]byte(nil), packet...)}, []int{packetFamily(packet)}); err != nil {
			return 0, err
		}
		return len(packet), nil
	}
	// Never block past Close. Drop on a full queue like the gVisor channel
	// endpoint does; TCP retransmits cover the loss.
	select {
	case p.outbound <- append([]byte(nil), packet...):
		return len(packet), nil
	case <-p.context.Done():
		return 0, io.ErrClosedPipe
	default:
		return len(packet), nil
	}
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
	if err := p.emit([][]byte{data}, []int{family}); err != nil {
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

// drainEndpoint batches gVisor outbound packets: block for the first one,
// then opportunistically collect whatever else is already queued.
func (p *PacketFlowTun) drainEndpoint() {
	var packets [][]byte
	var families []int
	for {
		packet := p.endpoint.ReadContext(p.context)
		if packet == nil {
			return
		}
		packets = packets[:0]
		families = families[:0]
		if data, family := packetData(packet); len(data) > 0 {
			packets = append(packets, data)
			families = append(families, family)
		}
		packet.DecRef()
		for len(packets) < emitBatchSize {
			next := p.endpoint.Read()
			if next == nil {
				break
			}
			if data, family := packetData(next); len(data) > 0 {
				packets = append(packets, data)
				families = append(families, family)
			}
			next.DecRef()
		}
		if len(packets) > 0 {
			_ = p.emit(packets, families)
		}
	}
}

// drainOutboundQueue batches raw-stack outbound packets the same way
// drainEndpoint does for the gVisor channel endpoint.
func (p *PacketFlowTun) drainOutboundQueue() {
	var packets [][]byte
	var families []int
	for {
		var first []byte
		select {
		case first = <-p.outbound:
		case <-p.context.Done():
			return
		}
		packets = append(packets[:0], first)
		drain := true
		for drain && len(packets) < emitBatchSize {
			select {
			case packet := <-p.outbound:
				packets = append(packets, packet)
			default:
				drain = false
			}
		}
		families = families[:0]
		for _, packet := range packets {
			families = append(families, packetFamily(packet))
		}
		_ = p.emit(packets, families)
	}
}

func packetFlowProtocol(packet []byte, family int) (tcpip.NetworkProtocolNumber, error) {
	switch family {
	case packetFlowIPv4:
		return header.IPv4ProtocolNumber, nil
	case packetFlowIPv6:
		return header.IPv6ProtocolNumber, nil
	default:
		return packetFamilyProtocol(packet), nil
	}
}

func packetFamilyProtocol(packet []byte) tcpip.NetworkProtocolNumber {
	if packetFamily(packet) == packetFlowIPv6 {
		return header.IPv6ProtocolNumber
	}
	return header.IPv4ProtocolNumber
}

func packetFamily(packet []byte) int {
	if len(packet) > 0 && packet[0]>>4 == 6 {
		return packetFlowIPv6
	}
	return packetFlowIPv4
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
