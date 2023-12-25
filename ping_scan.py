#import scapy.all as scapy
#目標 多layer嘗試的scanner can step by step try to 確認對方是否活著

from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet import TCP, UDP
from scapy.layers.l2 import Ether,ARP,arping
from scapy.sendrecv import sr1
import ipaddress
import threading
import time
#arpscan
#netsh interface ip delete arpcache
success_list=set()
DETAIL_FLAG=False
def arp_scan(s_ip):
    
    print(s_ip)
    arp_request = ARP(pdst=s_ip)
    broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request 
    results,unans = sr(arp_request_broadcast,timeout=1, verbose=False)
    #results,unans = scapy.srp(arp_request_broadcast,timeout=0.01, verbose=False)  # timeout very small dangerous!!!
    #print(arp_request_broadcast.show())
    print('----------------------------------------------------------------')
    print(results)
    print(unans)
    
    if results:
        success_list.add(s_ip)
        print(results[0].show())
        print(f"Host {s_ip} use arp scan success")
    else:
        print(unans[0].show())
        print(f"Host {s_ip} use arp scan fail") 

#PRO  不會拘限SUBNET  and i dont know why if i use 無線網卡 i must use ping to update arp cache
def ping_scan(ip):
    
    packet = IP(dst=ip,ttl=255,tos=46)/ICMP()  #use  Expedited forwarding  讓我們的封包會被優先轉發
    results,unans = sr(packet, timeout=0.1, verbose=0)
    print('----------------------------------------------------------------')
    print('\n')
    print(results)
    print(unans)
    print('----------------------------------------------------------------')
    #In icmp packet we want type
    for ele in results:
        pass
        print(ele)
        print(ele[0].show())
        print(ele[1].show()) 
        # print('\n\nHere is request packet contents:')
        # #We want (version , ttl ,sources id ,dest ip ,proto)
        # print('ip_version is :'+str(ele[0].version)+'\t'+'ttl is :'+str(ele[0].ttl))
        # print('ID is :'+str(ele[0][IP].id)+'\t'+'Echo Request number is :'+str(ele[0][ICMP].type)+' !8是ICMP中ECHO Request的代號 ')
        # print('sources_ip is :'+str(ele[0].src)+'\t'+'dest_ip is :'+str(ele[0].dst))
        # print('protocol_number is:'+str(ele[0][IP].proto) +'\t因為icmp在ip 的protocol中的協定編號是0x01 We must compare with TCP\n\n')
        # #reply we want [IP] (ihl,id,proto,checksum,ttl ,sources ip ,dest ip)
        # #print(ele[1].show())
        # print('\n\nHere is reply packet contents:')
        # print('ip_version is :'+str(ele[1].version)+'\t'+'ttl is :'+str(ele[1].ttl))
        # print('ID is :'+str(ele[1][IP].id)+'\t'+'Echo Request number is :'+str(ele[1][ICMP].type)+' !0是ICMP中ECHO Reply的代號 ')
        # print('sources_ip is :'+str(ele[1].src)+'\t'+'dest_ip is :'+str(ele[1].dst))
        # print('protocol_number is:'+str(ele[1][IP].proto) +'\t因為icmp在ip 的protocol中的協定編號是0x01 We must compare with TCP\n\n')
        # print('Reply特別的地方chksum(IP的|ICMP的): '+str(ele[1][IP].chksum)+'|'+str(ele[1][ICMP].chksum))
        # print(ele[1].show()) 
        if DETAIL_FLAG:
            print(ele[0].show())
            print(ele[1].show()) 
        #[ICMP] (type,chksum)
    for ele in unans:
        if unans:
            print('\n\n沒有掃到host 封包內容如下:')
        print(ele)
        print(ele[0].show())#request    
        print(ele[1].show())#reply
    if results:
        success_list.add(ip)
        print(f"Host {ip} is up")
    else:
        print(f"Host {ip} is down")
#CON 會拘限於防火牆的設定



def tcp_syn_scan(ip, port):
    packet = IP(dst=ip)/TCP(dport=port, flags="S",seq=random.randint(255, 5000)%5000,ack=5)#syn建立請求 3-way handshake
    response,Noresponse = sr(packet, timeout=1)
    print(response)
    print(Noresponse)

    for ele in response:
        print(ele)
        #request
        print('-------------------------DIFF WITH ICMP------------------------------------')
        print('protocol_number is:'+str(ele[0][IP].proto) +'\t因為TCP在ip 的protocol中的協定編號是0x06 We must compare with ICMP\n\n')
        print('-------------------------TCP-CONTENT------------------------------------')
        print('s_port is:'+str(ele[0][TCP].sport)+'\t20其實就是FTP FILE transport protocol')
        print('d_port is:'+str(ele[0][TCP].dport)+'\t5050是我設置的des port')
        print('seq is:'+str(ele[0][TCP].seq)+'\t3-way handshake 第一way的seq 最好要隨機不然有安全性問題')
        print('ack is:'+str(ele[0][TCP].ack)+'\t3-way handshake 設定初始ack')
        print('flags is:'+str(ele[0][TCP].flags)+'\t3-way handshake send Syn')
        print('window size is:'+str(ele[0][TCP].window))
        
        #reply   in my test RA RESET ACK 有3-WAY到但PORT沒開
        print('-------------------------DIFF WITH ICMP------------------------------------')
        print('protocol_number is:'+str(ele[1][IP].proto) +'\t因為TCP在ip 的protocol中的協定編號是0x06 We must compare with ICMP\n')
        print('-------------------------TCP-CONTENT------------------------------------')
        print('s_port is:'+str(ele[1][TCP].sport)+'\t5050是sender設置的des port')
        print('d_port is:'+str(ele[1][TCP].dport)+'\t20其實就是FTP FILE transport protocol')
        print('seq is:'+str(ele[1][TCP].seq)+'\t3-way handshake 起始SEQ一樣隨機才不會有安全性問題')
        print('ack is:'+str(ele[1][TCP].ack)+'\t3-way handshake sender的seq假設是X 那我就要ACK X+1回去')
        print('flags is:'+str(ele[1][TCP].flags)+'\t3-way handshake 第二WAY回傳的flags!!!')
        if DETAIL_FLAG:
            print(ele[0].show())
            print(ele[1].show()) 
        if ele[1][TCP].flags =='SA':
            print('Reply了SA也就是 SYN ACK')
        if ele[1][TCP].flags =='RA':
            print('Reply了RA也就是 RESET ACK 代表HOST其實存活但是PORT沒開')
        print('window size is:'+str(ele[1][TCP].window))
        
    for ele in Noresponse:
        print(ele)
        print(ele[0].show())#request
        print(ele[1].show())#reply
    if response:
        success_list.add(ip)
        print(f"Host {ip} is scan by TCP 3-way handshake")
    else:
        print(f"Host {ip} fail scan by TCP 3-way handshake")
        
def udp_scan(target_ip, target_port):
    # 創建UDP封包
    packet = IP(dst=target_ip) / UDP(dport=target_port)

    # 使用sr1函數發送UDP封包，timeout設置為1秒
    response = sr1(packet, timeout=1, verbose=0)

    if response is not None:
        # 如果收到回應，則認為目標端口是開啟的
        print(f"Port {target_port} on {target_ip} is open")
        #print(response.show())
        for ele in response:
            #print(ele)
            #print(ele[0].show())#request
            #print(ele[1].show())#request
            if(int(ele[1][ICMP].type)==3):
                print('回傳了icmp的dest-unreachable 所以可以確認主機存活但是port沒開')
            else:
                print('確認主機存活且port開啟')
        print(f"Port {target_port} on {target_ip} is open")
    else:
        # 如果沒有收到回應，則認為目標端口是關閉的
        print(f"Port {target_port} on {target_ip} is undecided port與主機未能確認狀況 清況有可能是防火牆擋住了/封包drop/")


    


threads = []
max_threads = 50
# user_input = input("我們將會透過四種方法掃出網段所有host 請問是否詳細封包0/1： ")
# if user_input  == 1:
#     DETAIL_FLAG=True
# print('我們將會從底層開始測試往上掃')
# print('ARP=>ICMP=>UDP=>TCP')
# user_input_ip = input("輸入ip與遮罩xxx.xxx.xxx.xxx/kk : ")
# ip_list=[str(ip) for ip in ipaddress.IPv4Network(str('192.168.0.0/24'))]

#print(ip_list)
# 掃描子網路範圍內的所有IP  在我這不一定會成功
# for ip in ip_list:
#     arp_scan(ip)
# for ip in ip_list:
#     while threading.active_count() > max_threads:
#         time.sleep(1)
#     t = threading.Thread(target=arp_scan, args=(ip,))
#     threads.append(t)
#     t.start()
#     time.sleep(0.1) #給他一咪咪時間收封包
    
# for temp in threads:
#     temp.join()
#以上ARP scan


#掃描子網路範圍內的所有IP
# for ip in ip_list:
#     ping_scan(ip)
# start = time.time()
# for ip in ip_list:
#     while threading.active_count() > max_threads:
#         time.sleep(1)
#     t = threading.Thread(target=ping_scan, args=(ip,))
#     threads.append(t)
#     t.start()
#     time.sleep(0.1) #給他一咪咪時間收封包
    
# for temp in threads:
#     temp.join()
# end = time.time()
# print("執行時間：%f 秒" % (end - start))
#以上icmp scan
#192.168.0.0/24
# 掃描子網路範圍內的所有IP
# port = 80
# #tcp_syn_scan('192.168.0.144',port)
# port2=5050
# port3=3000
# for ip in ip_list:
#     while threading.active_count() > max_threads:
#         time.sleep(1)
#     t = threading.Thread(target=tcp_syn_scan, args=(ip,port,))
#     t2 = threading.Thread(target=tcp_syn_scan, args=(ip,port2,))
#     t3 = threading.Thread(target=tcp_syn_scan, args=(ip,port3,))
#     threads.append(t)
#     threads.append(t2)
#     threads.append(t3)
#     t.start()
#     time.sleep(0.1)
#     t2.start()
#     time.sleep(0.1)
#     t3.start()
#     time.sleep(0.1)
    
# for temp in threads:
#     temp.join()
    
# time.sleep(1)
# print(success_list)
# #以上tcp 3-way





udp_scan('192.168.0.159',80)
# #以上udp


# for ip in ip_list:
#     while threading.active_count() > max_threads:
#         time.sleep(1)
#     t = threading.Thread(target=udp_scan, args=(ip,port,))
#     t2 = threading.Thread(target=udp_scan, args=(ip,port2,))
#     t3 = threading.Thread(target=udp_scan, args=(ip,port3,))
#     threads.append(t)
#     threads.append(t2)
#     threads.append(t3)
#     t.start()
#     time.sleep(0.1)
#     t2.start()
#     time.sleep(0.1)
#     t3.start()
#     time.sleep(0.1)
# for t in threads:
#     t.join()
    
with open('success_list.txt','w') as f:
    for ele in success_list:
        f.write(ele+'\n')
#last thing to do 
#if arp失敗
#try icmp if icmp失敗
#try udp else tcp