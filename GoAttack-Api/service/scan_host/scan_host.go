package scanhost

import (
	"GoAttack/common/log"
	"GoAttack/service/common"
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// HostScanner 主机探测扫描器
type HostScanner struct {
	Timeout     time.Duration           // 超时时间
	Concurrency int                     // 并发数
	Tracker     *common.ProgressTracker // 进度跟踪器
}

// NewHostScanner 创建主机扫描器实例
func NewHostScanner(timeout time.Duration, concurrency int) *HostScanner {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	if concurrency == 0 {
		concurrency = 50
	}
	return &HostScanner{
		Timeout:     timeout,
		Concurrency: concurrency,
	}
}

// HostResult 主机探测结果
type HostResult struct {
	IP      string        // IP地址
	IsAlive bool          // 是否存活
	Latency time.Duration // 延迟时间
	Error   error         // 错误信息
}

// ScanHosts 批量扫描主机存活性
func (s *HostScanner) ScanHosts(ctx context.Context, hosts []string) []HostResult {
	results := make([]HostResult, len(hosts))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.Concurrency)

	// 设置总目标数
	if s.Tracker != nil {
		s.Tracker.SetTotal(len(hosts))
	}

	for i, host := range hosts {
		wg.Add(1)
		go func(index int, target string) {
			defer wg.Done()

			// 控制并发
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// 检查上下文是否已取消
			select {
			case <-ctx.Done():
				results[index] = HostResult{
					IP:      target,
					IsAlive: false,
					Error:   ctx.Err(),
				}
				return
			default:
			}

			// 执行ICMP ping
			result := s.PingHost(target)
			results[index] = result

			// ✨ 实时报告进度
			if s.Tracker != nil {
				s.Tracker.ReportTargetScanned(target, result.IsAlive)
			}
		}(i, host)
	}

	wg.Wait()
	return results
}

// PingHost 使用ICMP探测单个主机
func (s *HostScanner) PingHost(host string) HostResult {
	result := HostResult{
		IP:      host,
		IsAlive: false,
	}

	// 解析IP地址
	ipAddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		result.Error = fmt.Errorf("解析IP地址失败: %v", err)
		return result
	}

	// 创建ICMP连接
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		// 如果没有权限创建原始套接字，尝试使用TCP探测
		return s.fallbackTCPPing(host)
	}
	defer conn.Close()

	// 设置超时时间
	if err := conn.SetDeadline(time.Now().Add(s.Timeout)); err != nil {
		result.Error = err
		return result
	}

	// 构造ICMP Echo Request消息
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1234,
			Seq:  1,
			Data: []byte("GoAttack-Ping"),
		},
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		result.Error = fmt.Errorf("构造ICMP消息失败: %v", err)
		return result
	}

	// 发送ICMP Echo Request
	startTime := time.Now()
	if _, err := conn.WriteTo(msgBytes, &net.IPAddr{IP: ipAddr.IP}); err != nil {
		result.Error = fmt.Errorf("发送ICMP请求失败: %v", err)
		return result
	}

	// 接收ICMP Echo Reply
	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		result.Error = fmt.Errorf("接收ICMP响应超时: %v", err)
		return result
	}

	latency := time.Since(startTime)

	// 解析ICMP响应
	parsedMsg, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		result.Error = fmt.Errorf("解析ICMP响应失败: %v", err)
		return result
	}

	// 检查是否为Echo Reply
	if parsedMsg.Type == ipv4.ICMPTypeEchoReply {
		result.IsAlive = true
		result.Latency = latency
		log.Info("[主机探测] %s 在线 (延迟: %v)", host, latency)
	}

	return result
}

// fallbackTCPPing 当ICMP权限不足时，使用TCP连接作为备用探测方法
func (s *HostScanner) fallbackTCPPing(host string) HostResult {
	result := HostResult{
		IP:      host,
		IsAlive: false,
	}

	// 常用端口列表，用于TCP探测
	commonPorts := []string{"80", "443", "22", "21", "3389"}

	for _, port := range commonPorts {
		target := net.JoinHostPort(host, port)
		conn, err := net.DialTimeout("tcp", target, s.Timeout)
		if err == nil {
			conn.Close()
			result.IsAlive = true
			log.Info("[主机探测-TCP] %s 在线 (通过端口 %s 检测)", host, port)
			break
		}
	}

	if !result.IsAlive {
		result.Error = fmt.Errorf("主机无响应")
	}

	return result
}

// ScanSubnet 扫描整个子网的存活主机
func (s *HostScanner) ScanSubnet(ctx context.Context, cidr string) ([]HostResult, error) {
	// 解析CIDR
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("无效的CIDR格式: %v", err)
	}

	// 生成所有IP地址
	hosts := generateIPsFromCIDR(ipNet)
	if len(hosts) == 0 {
		return nil, fmt.Errorf("子网中没有可扫描的主机")
	}

	log.Info("[子网扫描] 开始扫描 %s，共 %d 个主机", cidr, len(hosts))

	// 批量扫描
	results := s.ScanHosts(ctx, hosts)

	// 只返回存活的主机
	aliveHosts := make([]HostResult, 0)
	for _, result := range results {
		if result.IsAlive {
			aliveHosts = append(aliveHosts, result)
		}
	}

	log.Info("[子网扫描] 完成 %s，发现 %d 个存活主机", cidr, len(aliveHosts))
	return aliveHosts, nil
}

// generateIPsFromCIDR 从CIDR生成所有IP地址
func generateIPsFromCIDR(ipNet *net.IPNet) []string {
	var ips []string

	// 获取起始IP
	ip := ipNet.IP.Mask(ipNet.Mask)

	// 遍历所有IP
	for ipNet.Contains(ip) {
		// 跳过网络地址和广播地址
		if !isNetworkOrBroadcast(ip, ipNet) {
			ips = append(ips, ip.String())
		}

		// 递增IP
		ip = nextIP(ip)
	}

	return ips
}

// nextIP 获取下一个IP地址
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for j := len(next) - 1; j >= 0; j-- {
		next[j]++
		if next[j] > 0 {
			break
		}
	}
	return next
}

// isNetworkOrBroadcast 检查是否为网络地址或广播地址
func isNetworkOrBroadcast(ip net.IP, ipNet *net.IPNet) bool {
	// 网络地址
	if ip.Equal(ipNet.IP) {
		return true
	}

	// 广播地址
	broadcast := make(net.IP, len(ip))
	for i := range ip {
		broadcast[i] = ipNet.IP[i] | ^ipNet.Mask[i]
	}
	if ip.Equal(broadcast) {
		return true
	}

	return false
}

// GetAliveHosts 从结果中获取所有存活主机的IP列表
func GetAliveHosts(results []HostResult) []string {
	aliveHosts := make([]string, 0)
	for _, result := range results {
		if result.IsAlive {
			aliveHosts = append(aliveHosts, result.IP)
		}
	}
	return aliveHosts
}
