//go:build with_gvisor && (darwin || ios)

package main

/*
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

void swihomo_emit_packet(const uint8_t *packet, size_t length, int family);
void swihomo_emit_log(const char *level, const char *message);
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	goRuntime "runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	constant "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/log"
	tun "github.com/metacubex/sing-tun"
	"go.yaml.in/yaml/v3"
)

const (
	coreOK = iota
	coreInvalidConfiguration
	coreNotRunning
	corePacketFailure
	coreResourceFailure
	coreStreamFailure
)

var runtime = struct {
	sync.Mutex
	tun        *sing_tun.PacketFlowTun
	restore    func()
	running    bool
	lastErr    string
	stopLog    func()
	resources  map[string]externalResource
	groupOrder []string
}{}

type externalResource struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	ProviderType string `json:"providerType"`
	Path         string `json:"path"`
	URL          string `json:"url,omitempty"`
	Behavior     string `json:"behavior,omitempty"`
	IsPresent    bool   `json:"isPresent"`
	absPath      string
}

//export SwihomoCoreStart
func SwihomoCoreStart(
	profile *C.uint8_t,
	profileLength C.size_t,
	homeDirectory *C.char,
) C.int {
	runtime.Lock()
	defer runtime.Unlock()

	stopLocked()

	profileContents := copyBytes(profile, profileLength)
	if len(profileContents) == 0 {
		return failLocked(coreInvalidConfiguration, fmt.Errorf("profile configuration is empty"))
	}
	groupOrder, _, err := proxyGroupOrderFromYAML(profileContents)
	if err != nil {
		return failLocked(coreInvalidConfiguration, fmt.Errorf("decode profile proxy groups: %w", err))
	}

	home := C.GoString(homeDirectory)
	if home == "" {
		return failLocked(coreInvalidConfiguration, fmt.Errorf("mihomo home directory is empty"))
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return failLocked(coreInvalidConfiguration, fmt.Errorf("create mihomo home directory: %w", err))
	}
	constant.SetHomeDir(home)
	resources, err := discoverExternalResources(profileContents)
	if err != nil {
		return failLocked(coreInvalidConfiguration, err)
	}
	startLogCaptureLocked()
	log.Infoln("Swihomo packet-flow bridge starting")

	runtime.restore = sing_tun.SetTunFactory(func(options tun.Options) (tun.Tun, error) {
		packetTun := sing_tun.NewPacketFlowTun(options.MTU, emitPacket)
		runtime.tun = packetTun
		return packetTun, nil
	})

	if err := hub.Parse(profileContents); err != nil {
		stopLocked()
		return failLocked(coreInvalidConfiguration, fmt.Errorf("start mihomo: %w", err))
	}
	if runtime.tun == nil {
		stopLocked()
		return failLocked(coreInvalidConfiguration, fmt.Errorf("mihomo did not create the packet-flow TUN listener"))
	}

	runtime.running = true
	runtime.lastErr = ""
	runtime.resources = resources
	runtime.groupOrder = groupOrder
	log.Infoln("Swihomo packet-flow bridge started")
	return coreOK
}

//export SwihomoCoreInputPacket
func SwihomoCoreInputPacket(packet *C.uint8_t, length C.size_t, family C.int) C.int {
	runtime.Lock()
	defer runtime.Unlock()

	if !runtime.running || runtime.tun == nil {
		return failLocked(coreNotRunning, fmt.Errorf("mihomo core is not running"))
	}
	if err := runtime.tun.InjectPacket(copyBytes(packet, length), int(family)); err != nil {
		return failLocked(corePacketFailure, err)
	}
	return coreOK
}

// SwihomoCoreAPIRequest dispatches a controller API request directly against the
// in-process router — no listener, no loopback HTTP. Positive return values are HTTP
// status codes; values below 100 are bridge error codes (see SwihomoCoreLastError).
//
//export SwihomoCoreAPIRequest
func SwihomoCoreAPIRequest(
	method *C.char,
	target *C.char,
	body *C.uint8_t,
	bodyLength C.size_t,
	response **C.uint8_t,
	responseLength *C.size_t,
) C.int {
	if response == nil || responseLength == nil {
		return C.int(coreInvalidConfiguration)
	}
	*response = nil
	*responseLength = 0

	runtime.Lock()
	if !runtime.running {
		code := failLocked(coreNotRunning, fmt.Errorf("mihomo core is not running"))
		runtime.Unlock()
		return code
	}
	runtime.Unlock()

	if method == nil || target == nil {
		runtime.Lock()
		code := failLocked(coreInvalidConfiguration, fmt.Errorf("api request method or target is missing"))
		runtime.Unlock()
		return code
	}
	status, responseBody := route.HandleLocalRequest(C.GoString(method), C.GoString(target), copyBytes(body, bodyLength))
	if len(responseBody) > 0 {
		*response = (*C.uint8_t)(C.CBytes(responseBody))
		*responseLength = C.size_t(len(responseBody))
	}
	return C.int(status)
}

// SwihomoCoreAPIStreamOpen starts a streaming controller API request (endpoints that
// flush chunks indefinitely, like /traffic). Positive return values are stream IDs;
// smaller values are bridge error codes (see SwihomoCoreLastError).
//
//export SwihomoCoreAPIStreamOpen
func SwihomoCoreAPIStreamOpen(
	method *C.char,
	target *C.char,
	body *C.uint8_t,
	bodyLength C.size_t,
) C.int {
	runtime.Lock()
	if !runtime.running {
		code := failLocked(coreNotRunning, fmt.Errorf("mihomo core is not running"))
		runtime.Unlock()
		return code
	}
	runtime.Unlock()

	if method == nil || target == nil {
		runtime.Lock()
		code := failLocked(coreInvalidConfiguration, fmt.Errorf("api stream method or target is missing"))
		runtime.Unlock()
		return code
	}
	id := route.HandleLocalStreamOpen(C.GoString(method), C.GoString(target), copyBytes(body, bodyLength))
	if id == 0 {
		runtime.Lock()
		code := failLocked(coreStreamFailure, fmt.Errorf("mihomo core is not running"))
		runtime.Unlock()
		return code
	}
	return C.int(id)
}

// SwihomoCoreAPIStreamRead drains the buffered chunks of a stream, blocking up to
// timeoutMs when the buffer is empty. coreOK means more data may follow;
// coreStreamFailure means the stream ended and no further reads are valid.
//
//export SwihomoCoreAPIStreamRead
func SwihomoCoreAPIStreamRead(
	id C.int,
	timeoutMs C.int,
	data **C.uint8_t,
	dataLength *C.size_t,
) C.int {
	if data == nil || dataLength == nil {
		return C.int(coreInvalidConfiguration)
	}
	*data = nil
	*dataLength = 0

	chunk, eof := route.HandleLocalStreamRead(uint64(id), time.Duration(timeoutMs)*time.Millisecond)
	if len(chunk) > 0 {
		*data = (*C.uint8_t)(C.CBytes(chunk))
		*dataLength = C.size_t(len(chunk))
	}
	if eof {
		return C.int(coreStreamFailure)
	}
	return C.int(coreOK)
}

//export SwihomoCoreAPIStreamClose
func SwihomoCoreAPIStreamClose(id C.int) {
	route.HandleLocalStreamClose(uint64(id))
}

//export SwihomoCoreStop
func SwihomoCoreStop() {
	runtime.Lock()
	defer runtime.Unlock()
	stopLocked()
}

//export SwihomoCoreFreeMemory
func SwihomoCoreFreeMemory(before *C.uint64_t, after *C.uint64_t) {
	var beforeStats goRuntime.MemStats
	goRuntime.ReadMemStats(&beforeStats)
	debug.FreeOSMemory()
	var afterStats goRuntime.MemStats
	goRuntime.ReadMemStats(&afterStats)
	if before != nil {
		*before = C.uint64_t(beforeStats.HeapAlloc)
	}
	if after != nil {
		*after = C.uint64_t(afterStats.HeapAlloc)
	}
}

//export SwihomoCoreLastError
func SwihomoCoreLastError() *C.char {
	runtime.Lock()
	defer runtime.Unlock()
	return C.CString(runtime.lastErr)
}

//export SwihomoCoreExternalResources
func SwihomoCoreExternalResources() *C.char {
	runtime.Lock()
	defer runtime.Unlock()

	if !runtime.running {
		runtime.lastErr = "mihomo core is not running"
		return nil
	}
	resources := make([]externalResource, 0, len(runtime.resources))
	for _, resource := range runtime.resources {
		resources = append(resources, resource)
	}
	sort.Slice(resources, func(left, right int) bool {
		if resources[left].Kind == resources[right].Kind {
			return resources[left].Name < resources[right].Name
		}
		return resources[left].Kind < resources[right].Kind
	})
	for index := range resources {
		info, err := os.Stat(resources[index].absPath)
		resources[index].IsPresent = err == nil && !info.IsDir()
		resources[index].absPath = ""
	}
	contents, err := json.Marshal(resources)
	if err != nil {
		runtime.lastErr = fmt.Sprintf("encode external resources: %v", err)
		return nil
	}
	return C.CString(string(contents))
}

//export SwihomoCoreProxyGroupOrder
func SwihomoCoreProxyGroupOrder() *C.char {
	runtime.Lock()
	defer runtime.Unlock()

	if !runtime.running {
		runtime.lastErr = "mihomo core is not running"
		return nil
	}
	contents, err := json.Marshal(runtime.groupOrder)
	if err != nil {
		runtime.lastErr = fmt.Sprintf("encode proxy group order: %v", err)
		return nil
	}
	return C.CString(string(contents))
}

//export SwihomoCoreReadExternalResource
func SwihomoCoreReadExternalResource(
	identifier *C.char,
	contents **C.uint8_t,
	length *C.size_t,
) C.int {
	if contents == nil || length == nil {
		return C.int(coreResourceFailure)
	}
	*contents = nil
	*length = 0

	runtime.Lock()
	defer runtime.Unlock()

	if identifier == nil {
		return failLocked(coreResourceFailure, fmt.Errorf("external resource identifier is missing"))
	}
	resource, err := resourceLocked(C.GoString(identifier))
	if err != nil {
		return failLocked(coreResourceFailure, err)
	}
	data, err := os.ReadFile(resource.absPath)
	if err != nil {
		return failLocked(coreResourceFailure, fmt.Errorf("read %s: %w", resource.Name, err))
	}
	if len(data) == 0 {
		return coreOK
	}
	*contents = (*C.uint8_t)(C.CBytes(data))
	*length = C.size_t(len(data))
	return coreOK
}

//export SwihomoCoreWriteExternalResource
func SwihomoCoreWriteExternalResource(
	identifier *C.char,
	contents *C.uint8_t,
	length C.size_t,
) C.int {
	runtime.Lock()
	defer runtime.Unlock()

	if identifier == nil {
		return failLocked(coreResourceFailure, fmt.Errorf("external resource identifier is missing"))
	}
	resource, err := resourceLocked(C.GoString(identifier))
	if err != nil {
		return failLocked(coreResourceFailure, err)
	}
	if err := os.MkdirAll(filepath.Dir(resource.absPath), 0o700); err != nil {
		return failLocked(coreResourceFailure, fmt.Errorf("create resource directory for %s: %w", resource.Name, err))
	}
	if err := os.WriteFile(resource.absPath, copyBytes(contents, length), 0o600); err != nil {
		return failLocked(coreResourceFailure, fmt.Errorf("write %s: %w", resource.Name, err))
	}
	return coreOK
}

//export SwihomoCoreFreeString
func SwihomoCoreFreeString(value *C.char) {
	C.free(unsafe.Pointer(value))
}

//export SwihomoCoreFreeData
func SwihomoCoreFreeData(value *C.uint8_t) {
	C.free(unsafe.Pointer(value))
}

func main() {}

func stopLocked() {
	if runtime.tun != nil || runtime.running {
		executor.Shutdown()
	}
	if runtime.tun != nil {
		_ = runtime.tun.Close()
		runtime.tun = nil
	}
	if runtime.restore != nil {
		runtime.restore()
		runtime.restore = nil
	}
	if runtime.stopLog != nil {
		runtime.stopLog()
		runtime.stopLog = nil
	}
	runtime.running = false
	runtime.resources = nil
	runtime.groupOrder = nil
}

func failLocked(code int, err error) C.int {
	runtime.lastErr = err.Error()
	emitLog("error", runtime.lastErr)
	return C.int(code)
}

func startLogCaptureLocked() {
	subscription := log.Subscribe()
	runtime.stopLog = func() {
		log.UnSubscribe(subscription)
	}
	go func() {
		for event := range subscription {
			if event.LogLevel < log.Level() {
				continue
			}
			emitLog(event.Type(), event.Payload)
		}
	}()
}

func copyBytes(pointer *C.uint8_t, length C.size_t) []byte {
	if pointer == nil || length == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(pointer), C.int(length))
}

func emitPacket(packet []byte, family int) error {
	if len(packet) == 0 {
		return nil
	}
	C.swihomo_emit_packet((*C.uint8_t)(unsafe.Pointer(&packet[0])), C.size_t(len(packet)), C.int(family))
	return nil
}

func emitLog(level, message string) {
	if message == "" {
		return
	}
	cLevel := C.CString(level)
	cMessage := C.CString(message)
	defer C.free(unsafe.Pointer(cLevel))
	defer C.free(unsafe.Pointer(cMessage))
	C.swihomo_emit_log(cLevel, cMessage)
}

func proxyGroupOrderFromYAML(contents []byte) ([]string, bool, error) {
	if len(contents) == 0 {
		return nil, false, nil
	}

	var document yaml.Node
	if err := yaml.Unmarshal(contents, &document); err != nil {
		return nil, false, err
	}
	if len(document.Content) == 0 || document.Content[0].Kind != yaml.MappingNode {
		return nil, false, nil
	}

	root := document.Content[0]
	for index := 0; index+1 < len(root.Content); index += 2 {
		if root.Content[index].Value != "proxy-groups" {
			continue
		}
		groups := root.Content[index+1]
		if groups.Kind != yaml.SequenceNode {
			return nil, true, fmt.Errorf("proxy-groups must be a sequence")
		}

		order := make([]string, 0, len(groups.Content))
		seen := make(map[string]struct{}, len(groups.Content))
		for _, group := range groups.Content {
			if group.Kind != yaml.MappingNode {
				return nil, true, fmt.Errorf("proxy group must be a mapping")
			}
			name := mappingNodeValue(group, "name")
			if name == "" {
				continue
			}
			if _, duplicate := seen[name]; duplicate {
				continue
			}
			seen[name] = struct{}{}
			order = append(order, name)
		}
		return order, true, nil
	}
	return nil, false, nil
}

func mappingNodeValue(mapping *yaml.Node, key string) string {
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index+1].Value
		}
	}
	return ""
}

func discoverExternalResources(configuration []byte) (map[string]externalResource, error) {
	root := map[string]any{}
	if err := yaml.Unmarshal(configuration, &root); err != nil {
		return nil, fmt.Errorf("decode merged configuration: %w", err)
	}

	resources := make(map[string]externalResource)
	if err := collectExternalResources(root, "proxy-providers", "proxyProvider", "proxies", resources); err != nil {
		return nil, err
	}
	if err := collectExternalResources(root, "rule-providers", "ruleProvider", "rules", resources); err != nil {
		return nil, err
	}
	if err := collectGeoDataResources(root, resources); err != nil {
		return nil, err
	}
	return resources, nil
}

func collectGeoDataResources(root map[string]any, resources map[string]externalResource) error {
	requiresGeoIP, requiresGeoSite := geoDataRequirements(root)
	if requiresGeoIP {
		path := constant.Path.MMDB()
		name := filepath.Base(path)
		if geodataMode, _ := root["geodata-mode"].(bool); geodataMode {
			path = constant.Path.GeoIP()
			name = "GeoIP.dat"
		}
		if err := addGeoDataResource(resources, name, path); err != nil {
			return err
		}
	}
	if requiresGeoSite {
		if err := addGeoDataResource(resources, "GeoSite.dat", constant.Path.GeoSite()); err != nil {
			return err
		}
	}
	return nil
}

func geoDataRequirements(root map[string]any) (bool, bool) {
	var requiresGeoIP, requiresGeoSite bool
	collectRules := func(value any) {
		for _, rule := range stringRules(value) {
			upperRule := strings.ToUpper(rule)
			requiresGeoIP = requiresGeoIP || strings.Contains(upperRule, "GEOIP,")
			requiresGeoSite = requiresGeoSite || strings.Contains(upperRule, "GEOSITE,")
		}
	}
	collectRules(root["rules"])
	if subRules, ok := root["sub-rules"].(map[string]any); ok {
		for _, rules := range subRules {
			collectRules(rules)
		}
	}
	return requiresGeoIP, requiresGeoSite
}

func stringRules(value any) []string {
	rawRules, ok := value.([]any)
	if !ok {
		return nil
	}
	rules := make([]string, 0, len(rawRules))
	for _, rawRule := range rawRules {
		if rule, ok := rawRule.(string); ok {
			rules = append(rules, rule)
		}
	}
	return rules
}

func addGeoDataResource(resources map[string]externalResource, name, path string) error {
	relativePath, err := filepath.Rel(constant.Path.HomeDir(), path)
	if err != nil || !filepath.IsLocal(relativePath) {
		return fmt.Errorf("geodata path is outside the mihomo home directory: %s", path)
	}
	resource := externalResource{
		ID:           "geoData:" + name,
		Kind:         "geoData",
		Name:         name,
		ProviderType: "geox",
		Path:         filepath.ToSlash(relativePath),
		absPath:      path,
	}
	resources[resource.ID] = resource
	return nil
}

func collectExternalResources(
	root map[string]any,
	configurationKey string,
	kind string,
	cachePrefix string,
	resources map[string]externalResource,
) error {
	providers, ok := root[configurationKey]
	if !ok {
		return nil
	}
	mappings, ok := providers.(map[string]any)
	if !ok {
		return fmt.Errorf("%s must be a mapping", configurationKey)
	}

	for name, rawProvider := range mappings {
		provider, ok := rawProvider.(map[string]any)
		if !ok {
			return fmt.Errorf("%s.%s must be a mapping", configurationKey, name)
		}
		providerType := stringValue(provider, "type")
		if providerType != "file" && providerType != "http" {
			continue
		}

		path := stringValue(provider, "path")
		url := stringValue(provider, "url")
		if providerType == "http" && path == "" {
			path = constant.Path.GetPathByHash(cachePrefix, url)
		} else {
			path = constant.Path.Resolve(path)
		}
		if !constant.Path.IsSafePath(path) {
			return constant.Path.ErrNotSafePath(path)
		}

		relativePath, err := filepath.Rel(constant.Path.HomeDir(), path)
		if err != nil || !filepath.IsLocal(relativePath) {
			return fmt.Errorf("resource path is outside the mihomo home directory: %s", path)
		}
		resource := externalResource{
			ID:           kind + ":" + name,
			Kind:         kind,
			Name:         name,
			ProviderType: providerType,
			Path:         filepath.ToSlash(relativePath),
			URL:          url,
			Behavior:     stringValue(provider, "behavior"),
			absPath:      path,
		}
		resources[resource.ID] = resource
	}
	return nil
}

func resourceLocked(identifier string) (externalResource, error) {
	if !runtime.running {
		return externalResource{}, fmt.Errorf("mihomo core is not running")
	}
	resource, ok := runtime.resources[identifier]
	if !ok {
		return externalResource{}, fmt.Errorf("external resource is unavailable")
	}
	return resource, nil
}

func stringValue(mapping map[string]any, key string) string {
	value, _ := mapping[key].(string)
	return value
}
