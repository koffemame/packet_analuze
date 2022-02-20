
#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import tkinter as tk
import subprocess
import time
from scapy.all import *
from datetime import datetime


#GUIの描画
root = tk.Tk()
root.geometry('200x200')
root.title(u"パケット解析")


#ラジオボタンのリスト化
rdo_txt = ['tcpdump','pcap']
rdo_var = tk.IntVar()

prt_txt = ['TCP','UDP','ICMP','ARP','全解析']
prt_var = tk.IntVar()

#ラジオボタンの動的配置

for i in range(len(rdo_txt)):

    rdo =tk.Radiobutton(root, value=i, variable=rdo_var, text=rdo_txt[i])
    rdo.place(x=20, y=40 +(i*20))

for j in range(len(prt_txt)):

    prt =tk.Radiobutton(root, value=j, variable=prt_var, text=prt_txt[j])
    prt.place(x=120, y=40 +(j*20))





#ボタンクリックイベント

def analyze(pkt):

    datetime_str = datetime.fromtimestamp(pkt.time).isoformat()
    return "[%s] %s " % (datetime_str, pkt.summary())

def click_func():

    num = rdo_var.get()
    ber = prt_var.get()
    if num == 0:




#tcpdump実行箇所
        print("パケットを取得します。")
        subprocess.run("sudo tcpdump -i eth0 -w test.pcap -W1 -G10",shell=True)
        print("パケットを取得しました。")
    else:

#pcap実行箇所

        print("パケットを解析します")
        print("--------------------")

        if ber == 0:
            print("プロトコル名:TCP")
            sniff(offline="test.pcap",filter="tcp",store=0, prn=analyze)
            print("--------------------")

        elif ber == 1:
            print("プロトコル名:UDP")
            sniff(offline="test.pcap",filter="udp",store=0, prn=analyze)
            print("--------------------")

        elif ber == 2:
            print("プロトコル名:ICMP")
            sniff(offline="test.pcap",filter="icmp",store=0, prn=analyze)
            print("--------------------")

        elif ber == 3:
            print("プロトコル名:ARP")
            sniff(offline="test.pcap",filer="arp",store=0, prn=analyze)
            print("--------------------")

        else:
            print("すべてのパケットを解析します")
            sniff(offline="test.pcap",store=0,prn=analyze)
            print("--------------------")

btn = tk.Button(root, text=u"開始",command=click_func)
btn.place(x=20,y=100)

root.mainloop()
