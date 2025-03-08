# PC_WALL
PC 방화벽 프로그램 개발

25.03~

## DEMO CODE
```python
from scapy.all import sniff
import os

# 차단할 IP 목록
BLOCKED_IPS = ["192.168.1.100", "10.0.0.5"]

# 차단할 포트 목록
BLOCKED_PORTS = [22, 80]  # SSH, HTTP 차단 예시

def packet_callback(packet):
    """패킷을 감시하고 특정 조건에 따라 차단하는 함수"""
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst

        # 차단된 IP 주소 감지
        if src_ip in BLOCKED_IPS or dst_ip in BLOCKED_IPS:
            print(f"[BLOCKED] 패킷 차단: {src_ip} → {dst_ip}")
            return

    if packet.haslayer("TCP"):
        dst_port = packet["TCP"].dport
        if dst_port in BLOCKED_PORTS:
            print(f"[BLOCKED] 포트 차단: {dst_port}")
            return

    print(f"[ALLOWED] 패킷 허용: {packet.summary()}")

# 네트워크 인터페이스 지정 (윈도우의 경우 'Ethernet', 리눅스는 'eth0' 또는 'wlan0' 등)
INTERFACE = "Ethernet"  

print("방화벽 실행 중... 패킷 감시 시작")
sniff(prn=packet_callback, iface=INTERFACE, store=0)
```

변수 Rule Set 를 뭘로 할지 고민
```
출발지 ip
출발지 포트

목적지 ip
목적지 포트

지속시간

건수

탐지 시간

탐지명

분석룰셋
```


차단할 ip 목록을 엑셀 파일로 전달
포트를 엑셀파일로 전달

조건에 따라 차단
