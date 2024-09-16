#!/bin/bash

echo -e "\n********** Script SCAN PORTS powered by (Mr4ndr3w) **********\n"

handleExit(){
    echo -e "\n****************** Script SCAN Interirupted ********************\n"  
    exit 1
}
trap handleExit SIGINT

manScript(){
    echo -e "\n[!] SCRIPT MAN TOOL"
    echo -e "*************************************************************"
    echo -e "[*]Basic Usage scriptScan.sh (IP) "
    echo -e "[Ex]Example : scriptScan.sh 1.1.1.1 "
    echo -e "[*]Advanced Usage scriptScan.sh 1.1.1.1 ( v | vuln)"
    echo -e "[Ex]Example : scriptScan.sh 1.1.1.1 v | scriptScan.sh 1.1.1.1 vuln "
    echo -e "*************************************************************"
    echo -e "\n\n"
}

if [ -z $1 ]; then
    manScript
    exit 1;
fi
IP_HOST=$1
VULNSCAN=0

if [ -n "$2" ]; then
    if [[ "$2" == "v" || "$2" == "vuln" ]]; then
        VULNSCAN=1
    else
        manScript
        exit 1;
    fi
fi


TTL_HOST=$(ping -c 1 $IP_HOST | grep -Eo  "ttl=[0-9]+" | cut -d "=" -f2)

defSystemOs(){
    if [[ $TTL_HOST -gt 0 && $TTL_HOST -le 64 ]]; then
        echo -e "[+] Host OS: LINUX"
    elif [[ $TTL_HOST -gt 64 && $TTL_HOST -le 128 ]]; then
        echo "[+] Host OS: Windows"
    elif [[ $TTL_HOST -gt 128 && $TTL_HOST -le 255 ]]; then
        echo -e "[+] Host OS: Cisco IOS o Solaris Or (routers, switches, etc.)"
    else
        echo -e "[!] Host OS: (Undetected OS)"
    fi
}

if [[ -n $TTL_HOST && $TTL_HOST -gt 0 ]]; then
    echo -e "[+] Host $IP_HOST responde con TTL=$TTL_HOST"
    defSystemOs
else
    echo -e "[+] Host $IP_HOST No responde a ICMP "
fi

mkdir $IP_HOST &>/dev/null; cd $IP_HOST &>/dev/null

echo -e "\n[*] Start SCAN Ports (step 1)..."

PORTS_HOST=$(sudo nmap -sS -n -Pn -p- --open --min-rate=5000 $IP_HOST --oA scan_ports | grep -E "^[0-9]{1,3}" | grep -v "unknown" | cut -d "/" -f1 | xargs | tr " " ",")

if [ -n $PORTS_HOST ]; then

    echo -e "[+] Host Port Detected: $PORTS_HOST "
    echo -e "\n[+] Host Port(s) Version(s): (step 2)\n"

    nmap -sV -Pn -p$PORTS_HOST $IP_HOST | grep -E "^[0-9]{1,3}"

fi

if [ $VULNSCAN -gt 0 ]; then
    echo -e "\n[+] Host Port(s) Vuln(s) Version(s): (step 3)\n"

    git clone https://github.com/scipag/vulscan scipag_vulscan &>/dev/null

    nmap -sV -Pn -p$PORTS_HOST --script=scipag_vulscan/vulscan.nse $IP_HOST | sed "1,5d" | head -n -4

    rm -rf scipag_vulscan
fi

echo -e "\n[+] SCAN Tool Output generated (nmap,grep,xml):\n "
ls -l
                     
echo -e "\n****************** Script SCAN Completed ********************\n"
