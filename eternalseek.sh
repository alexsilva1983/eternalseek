#!/bin/bash
# EternalSeek v1.0
# Author: thelinuxchoice
# Github: github.com/thelinuxchoice/eternalseek
# Instagram: @thelinuxchoice
trap 'printf "\n";partial;exit 1' 2

usetor() {

read -p $'\e[1;92m[\e[0m\e[1;77m?\e[0m\e[1;92m] Anonymize via Tor? \e[0m\e[1;77m[Y/n]\e[0m ' asw_tor
if [[ $asw_tor == "Y" || $asw_tor == "y" || $asw_tor == "yes" || $asw_tor == "Yes" ]]; then
use_tor="true"
command -v tor > /dev/null 2>&1 || { echo >&2 "I require Tor. Run: apt-get install tor. Aborting."; exit 1; }
command -v proxychains > /dev/null 2>&1 || { echo >&2 "I require Proxychains. Run: apt-get install proxychains. Aborting."; exit 1; }

checktor
else
use_tor="false"
fi

if [[ $user_tor == "true" ]]; then
cmd_nc="proxychains nc"
elif [[ $use_tor == "false" ]]; then
cmd_nc="nc"
fi
}

partial() {


if [[ -n "$threads" ]]; then
printf "\n"
printf "\e[1;91m [*] Waiting threads..\n\e[0m"
wait $pid > /dev/null 2>&1 ;
sleep 6
if [[ -e logip ]]; then

countip=$(wc -l logip | cut -d " " -f1)
printf "\e[1;92m[*] IPs Found:\e[0m\e[1;77m %s\e[0m\n" $countip 
cat logip >> "logip.$session"
wait $!
rm -rf logip
printf "\e[1;92m [*] Saved:\e[0m\e[1;77m logip.%s\e[0m\n" $session
fi
default_session_ans="Y"
printf "\n\e[1;77m [?] Save session \e[0m\e[1;92m %s \e[0m" $session
read -p $'\e[1;77m? [Y/n]: \e[0m' session_ans
session_ans="${session_ans:-${default_session_ans}}"
if [[ "$session_ans" == "Y" || "$session_ans" == "y" || "$session_ans" == "yes" || "$session_ans" == "Yes" ]]; then
if [[ ! -d sessions ]]; then
mkdir sessions
fi
printf "session=\"%s\"\ncount=\"%s\"\nport=\"%s\"\ntargets=\"targets-%s\"\n" $session $count $port $session > sessions/session.$session
if [[ -e targets-$session ]]; then
mv targets-$session sessions/targets-$session
fi
printf "\e[1;77m[*] Session saved.\e[0m\n"
printf "\e[1;93m[*] Use ./eternalseek.sh --resume\n"
else
exit 1
fi
else
exit 1
fi
}
checktor() {

check_tor=$(curl --socks5-hostname localhost:9050 -s https://www.google.com > /dev/null; echo $?)
if [[ "check_tor" -gt 0 ]]; then
printf "\e[1;91mCheck your Tor connection!\n"
exit 1 
fi
}

banner() {

printf "\e[34m  _____ _                        _   \e[0m\e[1;77m____            _     \e[0m\n"
printf "\e[34m | ____| |_ ___ _ __ _ __   __ _| | \e[0m\e[1;77m/ ___|  ___  ___| | __ \e[0m\n"
printf "\e[34m |  _| | __/ _ \ '__| '_ \ / _\` | | \e[0m\e[1;77m\___ \ / _ \/ _ \ |/ / \e[0m\n"
printf "\e[34m | |___| ||  __/ |  | | | | (_| | |\e[0m\e[1;77m  ___) |  __/  __/   <  \e[0m\n"
printf "\e[34m |_____|\__\___|_|  |_| |_|\__,_|_|\e[0m\e[1;77m |____/ \___|\___|_|\_\ v1.0\e[0m\n"
                                                          

printf "\n"
printf " \e[1;100m        Author: thelinuxchoice (Github/Instagram)        \e[0m\n\n"


}


dependencies() {

command -v msfconsole > /dev/null 2>&1 || { echo >&2 "I require Metasploit. Install it. Aborting."; exit 1; }


}


scan() {
command -v nc > /dev/null 2>&1 || { echo >&2 "I require NetCat. Run: apt-get install netcat. Aborting."; exit 1; }
usetor
read -p $'\e[1;37m[::] Put range ip part 1/4 \e[0m\e[91m(e.g.:192 255)  \e[0m\e[1;92m -> \e[0m' r1
read -p $'\e[1;37m[::] Put range ip part 2/4 \e[0m\e[91m(e.g: 168 255)  \e[0m\e[1;92m -> \e[0m' r2
read -p $'\e[1;37m[::] Put range ip part 3/4 \e[0m\e[91m(e.g.: 1 255)   \e[0m\e[1;92m -> \e[0m' r3
read -p $'\e[1;37m[::] Put range ip part 4/4 \e[0m\e[91m(e.g.: 10 255)  \e[0m\e[1;92m -> \e[0m' r4
default_port=445
read -p $'\e[1;37m[::] Port to scan\e[0m \e[1;91m(Default 445):\e[0m ' port
port="${port:-${default_port}}"
number=$RANDOM
default_session="session-$number"
read -p $'\e[1;37m[::] Session name \e[1;91m(Default:\e[0m '$default_session'): ' session
session="${session:-${default_session}}"
default_threads=100
read -p $'\e[1;37m[::] Threads to scan \e[1;91m(Default 100):\e[0m \e[0m' threads
threads="${threads:-${default_threads}}"
for x in $(seq $r1);do for y in $(seq $r2);do for z in $(seq $r3);do for w in $(seq $r4);do
printf "%s.%s.%s.%s\n" $x $y $z $w >> targets-$session
done done done done

if [[ -e logip ]]; then
rm -rf logip;
fi
count_target=$(wc -l targets-$session | cut -d " " -f1)
printf "\e[1;92m[*] Targets:\e[0m\e[1;77m %s\e[0m\n" $count_target
printf "\e[1;92m[*] Starting scanner...\e[0m\n"
sleep 3
count=0
startline=1
endline="$threads"
while [ $count -lt $count_target ]; do
for target in $(sed -n ''$startline','$endline'p' targets-$session); do
let count++
printf "\e[1;93mScanning target:\e[0m\e[77m %s \e[0m\e[1;93m(\e[0m\e[77m%s\e[0m\e[1;93m/\e[0m\e[77m%s\e[0m\e[1;93m)\e[0m\n" $target $count $count_target
{(trap '' SIGINT && check=$($cmd_nc $target $port -v -z -w5 > /dev/null 2>&1; echo $?); if [[ $check == "0" ]]; then echo $target >> logip; fi; ) } & done; pid=$! ; wait $!;
let startline+=$threads
let endline+=$threads

done

if [[ -e logip ]]; then

countip=$(wc -l logip | cut -d " " -f1)
printf "\e[1;92m[*] IPs Found:\e[0m\e[1;77m %s\e[0m\n" $countip 
ssfile=logip.$session
cp logip ip_list
sfile=$(mv logip $ssfile | echo $ssfile)
printf "\e[1;92m [*] Saved:\e[0m\e[1;77m %s\e[0m\n" $sfile
threads=""
printf "\e[1;92m[\e[0m\e[1;77m*\e[0m\e[1;92m] Starting Metasploit Scanner...\e[0m\n"
msfc
else
printf "\e[1;91m[!] No Open ports found in this IP range!\e[0m\n"
exit 1
fi
}


function scan_resume() {

count_target=$(wc -l sessions/$targets | cut -d " " -f1)
printf "\e[1;92m[*] Targets:\e[0m\e[1;77m %s\e[0m\n" $count_target
printf "\e[1;92m[*] Starting scanner...\e[0m\n"
sleep 3
startline=$((count+1))
endline=$((count+threads))
while [ $((count2)) -lt $count_target ]; do
for target in $(sed -n ''$startline','$endline'p' sessions/$targets); do
count21=0
count2=$((count+count21+1))
#count_ip=$(grep -n -x "$target" "sessions/$targets" | cut -d ":" -f1)
printf "\e[1;93mScanning target:\e[0m\e[77m %s \e[0m\e[1;93m(\e[0m\e[77m%s\e[0m\e[1;93m/\e[0m\e[77m%s\e[0m\e[1;93m)\e[0m\n" $target $count2 $count_target
let count++
let count21++
{(trap '' SIGINT && check=$($cmd_nc $target $port -v -z -w5 > /dev/null 2>&1; echo $?); if [[ $check == "0" ]]; then echo $target >> logip; fi; ) } & done; pid=$! ; wait $!;
let startline+=$threads
let endline+=$threads

done

if [[ -e logip ]]; then

countip=$(wc -l logip | cut -d " " -f1)
printf "\e[1;92m[*] IPs Found:\e[0m\e[1;77m %s\e[0m\n" $countip 
cat logip >> logip.$session
mv logip ip_list
printf "\e[1;92m [*] Saved:\e[0m\e[1;77m logip.%s\e[0m\n" $session
threads=""
msfc
else
printf "\e[1;91m[!] No Open ports found in this IP range!\e[0m\n"
exit 1
fi



}


function resume() {

banner 
dependencies
if [[ -e mass ]]; then
rm -rf mass
fi

if [[ -e ip_list ]]; then
rm -rf ip_list
fi
default_resume_mass="Y"
if [[ -e paused.conf ]]; then
read -p $'\e[1;92m[\e[0m\e[1;77m!\e[0m\e[1;92m] A masscan session was found, do you want to use it?\e[0m \e[1;77m[Y/n]\e[0m ' resume_mass

resume_mass="${resume_mass:-${default_resume_mass}}"
if [[ $resume_mass == "Y" || $resume_mass == "Yes" || $resume_mass == "y" || $resume_mass == "yes" ]]; then
masscan --resume paused.conf
fi
fi
if [[ -e mass ]]; then
grep -o 'addr=.*' mass | cut -d " " -f1 | cut -d '"' -f2 > ip_list
fi

if [[ -e ip_list ]]; then
printf "\e[1;92m[\e[0m\e[1;77m*\e[0m\e[1;92m] Starting Metasploit Scanner...\e[0m\n"
msfc
fi



countern=1
if [[ ! -d sessions ]]; then
printf "\e[1;91m[*] No sessions\n\e[0m"
exit 1
fi

printf "\e[1;92mFiles sessions:\n\e[0m"
for list in $(ls sessions/session*); do
IFS=$'\n'
source $list
printf "\e[1;92m%s\e[0m\e[1;77m: \e[0m %s \e[1;92mPort:\e[0m %s \e[1;92mLast position:\e[0m %s\n" $countern $session $port $count
let countern++
done
read -p $'\e[1;92mChoose a session number: \e[0m' fileresume
source $(ls sessions/session* | sed ''$fileresume'q;d')
default_threads=100
usetor
read -p $'\e[1;37m[::] Numbers of Threads to scan \e[1;91m(Default 100):\e[0m \e[0m' threads
threads="${threads:-${default_threads}}"

printf "\e[1;92m[*] Resuming session :\e[0m \e[1;77m%s\e[0m\n" $session
printf "\e[1;91m[*] Press Ctrl + C to stop or save session\n\e[0m"
scan_resume


}

shodan() {

checkshodan=$(python -c "import shodan" > /dev/null 2>&1 ; echo $?)
if [[ $checkshodan == "1" ]]; then
printf "\e[1;93m[!] Requires shodan module, run:\e[0m\e[1;77m pip install shodan\e[0m\n"
exit 1
fi

if [[ -e ip_list ]]; then
rm -rf ip_list
fi

if [[ -e shodan.result ]]; then
rm -rf shodan.result
fi
default_search="port 445"
read -p $'\e[1;92m[\e[0m\e[1;77m?\e[0m\e[1;92m] Shodan search (Default: port 445): \e[0m ' search
search="${search:-${default_search}}"
python shodanapi.py "$search" > shodan.result
checkshodan=$(cat shodan.result > /dev/null 2>&1 )
if [[ -e shodan.result ]]; then
##
interface=$(ifconfig -a | sed 's/[ \t].*//;/^$/d' | tr -d ':' > iface)
counter=1
for i in $(cat iface); do
printf "\e[1;92m%s\e[0m: \e[1;77m%s\n" $counter $i
let counter++
done

read -p $'\e[1;92m[\e[0m\e[1;77m*\e[0m\e[1;92m] Interface to use:\e[0m ' use_interface
choosed_interface=$(sed ''$use_interface'q;d' iface)
##

for s in $(cat shodan.result); do
    if [[ $s =~ ^([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]; then
        #IPv4
        echo $s >> ip_list
    elif [[ $s =~ ^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$ ]]; then
        # IPv6
        echo $s%$choosed_interface >> ip_list
    else
        # Neither
        continue
    fi
done

else
printf "\e[1;93m[\e[0m\e[1;77m!\e[0m\e[1;93m] No Results!\e[0m\n"
fi
if [[ -e ip_list ]]; then
printf "\e[1;92m[\e[0m\e[1;77m*\e[0m\e[1;92m] Starting Metasploit Scanner...\e[0m\n"
msfc
fi
}


masscan_scan() {
command -v masscan > /dev/null 2>&1 || { echo >&2 "I require masscan. Run: apt-get install masscan. Aborting."; exit 1; }
if [[ -e mass ]]; then
rm -rf mass
fi

if [[ -e ip_list ]]; then
rm -rf ip_list
fi

default_rate="100"
default_port="445"
read -p $'\e[1;92m[\e[0m\e[1;77m*\e[0m\e[1;92m] IP/IP Range \e[0m\e[1;77m(E.g: 192.168.1.10 / 192.168.1.0/24)\e[0m\e[1;92m:\e[0m ' ip
read -p $'\e[1;92m[\e[0m\e[1;77m*\e[0m\e[1;92m] Rate \e[0m\e[1;77m(Default: 100)\e[0m\e[1;92m:\e[0m ' rate
rate="${rate:-${default_rate}}"
read -p $'\e[1;92m[\e[0m\e[1;77m*\e[0m\e[1;92m] Port \e[0m\e[1;77m(Default: 445)\e[0m\e[1;92m:\e[0m ' port
port="${port:-${default_port}}"
printf "\e[1;92m[\e[0m\e[1;77m*\e[0m\e[1;92m] Starting Masscan...\e[0m\n"
masscan $ip --rate=$rate -p$port --output-filename="mass"

if [[ -e mass ]]; then
grep -o 'addr=.*' mass | cut -d " " -f1 | cut -d '"' -f2 > ip_list
fi

if [[ -e ip_list ]]; then
printf "\e[1;92m[\e[0m\e[1;77m*\e[0m\e[1;92m] Starting Metasploit Scanner...\e[0m\n"
msfc
fi
}

check_vuls() {

check_vul=$(grep -a ' Host is likely VULNERABLE' spool | cut -d " " -f2 | cut -d ":" -f1)
if [[ $check_vul == "" ]]; then
printf "\e[1;93m[!] Not Found Vulnerable Hosts\e[0m\n"
exit 1
else
printf "\e[1;92m[\e[0m\e[1;77m*\e[0m\e[1;92m] Vulnerable Hosts:\e[0m\n"
printf "\e[1;77m%s\e[0m\n" $check_vul
printf "\e[1;77m%s\e[0m\n" $check_vul > vuln.txt
printf "\e[1;92mSaved:\e[0m\e[1;77m vuln.txt\n"
exit 1
fi
}

msfc() {

if [[ -e ip_list ]]; then
rm -rf spool
ips=$(cat ip_list)
echo "spool spool" > resource.rc
echo "use auxiliary/scanner/smb/smb_ms17_010" >> resource.rc
printf "set rhosts " >> resource.rc
printf "%s, " $ips >> resource.rc
printf "\n" >> resource.rc
echo "set rport 445" >> resource.rc
echo "set threads 10" >> resource.rc
echo "exploit" >> resource.rc
echo "quit -y" >> resource.rc

echo "" > filemsf
msfconsole -r resource.rc > filemsf &

while [ true ]; do
result=$(grep -o '100%' filemsf)
result2=$(sed -n '$p' filemsf)
#tail -f filemsf | grep 'Scanned'
if [[ ! $result2 == "" ]]; then
IFS=$'\n'
printf "%s\n" $result2
fi

if [[ $result == *'100%'* ]]; then
  lazy="%"
  printf '\n\e[1;92m[\e[0m\e[1;77m*\e[0m\e[1;92m] Scan 100%s Complete\e[0m\n' $lazy
  check_vuls
fi
sleep 5

done
check_vuls
else
printf "\e[1;93m[!] 0 IP Found! :(\e[0m"
fi
}

menu() {

printf "\e[1;92m[\e[0m\e[1;77m01\e[0m\e[1;92m] Masscan \e[0m\e[1;77m(Faster, without Tor)\e[0m\n"
printf "\e[1;92m[\e[0m\e[1;77m02\e[0m\e[1;92m] Netcat \e[0m\e[1;77m(Slow, with Tor)\e[0m\n"
printf "\e[1;92m[\e[0m\e[1;77m03\e[0m\e[1;92m] Shodan\e[0m\n"    
printf "\n"
printf "\e[1;93m[\e[0m\e[1;77m99\e[0m\e[1;93m] Exit\e[0m\n"    
read -p $'\e[1;92m[\e[0m\e[1;77m?\e[0m\e[1;92m] Choose a Scan option: \e[0m' scan_option

if [[ "$scan_option" == 1 || "$scan_option" == 01 ]]; then
masscan_scan
elif [[ "$scan_option" == 2 || "$scan_option" == 02 ]]; then
scan
elif [[ "$scan_option" == 3 || "$scan_option" == 03 ]]; then
shodan
elif [[ "$scan_option" == 99 ]]; then
exit 1
else
printf "\e[1;93m [!] Invalid Option!\e[0m\n"
sleep 1
banner
menu
fi

}

case "$1" in --resume) resume ;; *)
banner
menu
esac

