#!/bin/bash



# tc script by klacke@hyber.org to shape outgoing traffic, I don't
# want download from my yaws webserver nor p2p to fuck up
# interactive ssh 


DEV=eth2


# this is carefully tuned value, I've got an adsl connection
# that claims 0.8 mbit/sec upload, The goal of this script 
# is to not have packets queued at the ADSL router, but rather
# have them queued in the qdiscs on the router.


#RATEUP=610
RATEUP=910

# 
# End Configuration Options
#



TC=/sbin/tc

tc_reset ()
{
	# Reset everything to a known state (cleared)
	$TC qdisc del dev $DEV root 2> /dev/null > /dev/null
}

tc_status ()
{
    echo "[qdisc - $DEV]"
    $TC -s qdisc show dev $DEV
    echo "------------------------"
    echo
    echo "[class - $DEV]"
    $TC -s class show dev $DEV
}

tc_start()
{
    echo -n "Starting traffic shaping"
    tc_reset
	#
	# dev eth0 - creating qdiscs & classes
	#
    $TC qdisc add dev $DEV root handle 1: htb default 60
    $TC class add dev $DEV parent 1: classid 1:1 htb rate ${RATEUP}kbit
    $TC class add dev $DEV parent 1:1 classid 1:10 htb rate $[$RATEUP/6]kbit ceil ${RATEUP}kbit prio 0
    $TC class add dev $DEV parent 1:1 classid 1:20 htb rate $[$RATEUP/6]kbit ceil ${RATEUP}kbit prio 1
    $TC class add dev $DEV parent 1:1 classid 1:30 htb rate $[$RATEUP/6]kbit ceil ${RATEUP}kbit prio 2
    $TC class add dev $DEV parent 1:1 classid 1:40 htb rate $[$RATEUP/6]kbit ceil ${RATEUP}kbit prio 3
    $TC class add dev $DEV parent 1:1 classid 1:50 htb rate $[$RATEUP/6]kbit ceil ${RATEUP}kbit prio 4
    $TC class add dev $DEV parent 1:1 classid 1:60 htb rate $[$RATEUP/6]kbit ceil ${RATEUP}kbit prio 5
    $TC qdisc add dev $DEV parent 1:10 handle 10: sfq perturb 10
    $TC qdisc add dev $DEV parent 1:20 handle 20: sfq perturb 10
    $TC qdisc add dev $DEV parent 1:30 handle 30: sfq perturb 10
    $TC qdisc add dev $DEV parent 1:40 handle 40: sfq perturb 10
    $TC qdisc add dev $DEV parent 1:50 handle 50: sfq perturb 10
    $TC qdisc add dev $DEV parent 1:60 handle 60: sfq perturb 10
    tc_status
}



add_fwmarks()
{
    iptables -t mangle -N SHAPER 2> /dev/null
    iptables -t mangle -I POSTROUTING -o $DEV -j SHAPER 2> /dev/null > /dev/null

    # give "overhead" packets highest priority
    iptables -t mangle -A SHAPER -o $DEV -p tcp --syn -m length --length 40:68 -j CLASSIFY --set-class 1:10
    iptables -t mangle -A SHAPER -o $DEV -p tcp --tcp-flags ALL SYN,ACK -m length --length 40:68 -j CLASSIFY --set-class 1:10
    iptables -t mangle -A SHAPER -o $DEV -p tcp --tcp-flags ALL ACK -m length --length 40:100 -j CLASSIFY --set-class 1:10
    iptables -t mangle -A SHAPER -o $DEV -p tcp --tcp-flags ALL RST -j CLASSIFY --set-class 1:10
    iptables -t mangle -A SHAPER -o $DEV -p tcp --tcp-flags ALL ACK,RST -j CLASSIFY --set-class 1:10
    iptables -t mangle -A SHAPER -o $DEV -p tcp --tcp-flags ALL ACK,FIN -j CLASSIFY --set-class 1:10
# interactive SSH traffic + my mail
    iptables -t mangle -A SHAPER -o $DEV -p tcp --sport ssh -m length --length 40:300 -j CLASSIFY --set-class 1:20
    iptables -t mangle -A SHAPER -o $DEV -p tcp --dport ssh -m length --length 40:300 -j CLASSIFY --set-class 1:20
    iptables -t mangle -A SHAPER -o $DEV -p tcp -m multiport --sport 465,2525,pop3,imap2,https,imaps,smtp -j CLASSIFY --set-class 1:20
    iptables -t mangle -A SHAPER -o $DEV -p tcp -m multiport --dport 465,2525,pop3,imap2,https,imaps,smtp -j CLASSIFY --set-class 1:20
# dns lookups
    iptables -t mangle -A SHAPER -o $DEV -p udp --dport domain -j CLASSIFY --set-class 1:20
# small outgoing size web traffic, svtplay
    iptables -t mangle -A SHAPER -o $DEV -p tcp --sport http -j CLASSIFY --set-class 1:30
    iptables -t mangle -A SHAPER -o $DEV -p tcp -m multiport --dport 554 -j CLASSIFY --set-class 1:30
    iptables -t mangle -A SHAPER -o $DEV -p udp -m multiport --dport 554 -j CLASSIFY --set-class 1:30
# outgoing nntp traffic
    iptables -t mangle -A SHAPER -o $DEV -p tcp --dport 119 -j CLASSIFY --set-class 1:30
# incoming http traffic
    iptables -t mangle -A SHAPER -o $DEV -p tcp --dport http -j CLASSIFY --set-class 1:30
# ICMP
    iptables -t mangle -A SHAPER -o $DEV -p icmp -m length --length 28:1500 -m limit --limit 2/s --limit-burst 5 -j CLASSIFY --set-class 1:40

# bulk SSH traffic upload http
    iptables -t mangle -A SHAPER -o $DEV -p tcp --sport ssh -j CLASSIFY --set-class 1:40
    iptables -t mangle -A SHAPER -o $DEV -p tcp --dport ssh -j CLASSIFY --set-class 1:40
    iptables -t mangle -A SHAPER -o $DEV -p tcp --sport http -m length --length 301:  -j CLASSIFY --set-class 1:40

# bulk traffic, all p2p
    iptables -t mangle -A SHAPER -o $DEV -p udp -j CLASSIFY --set-class 1:50

    iptables -t mangle -A SHAPER -o $DEV -p tcp --dport 6667 -j CLASSIFY --set-class 1:50
    iptables -t mangle -A SHAPER -o $DEV -p tcp --dport 27526 -j CLASSIFY --set-class 1:50



}



del_fwmarks()
{
    iptables -t mangle -D POSTROUTING -o $DEV -j SHAPER 2> /dev/null > /dev/null
    iptables -t mangle -F SHAPER 2> /dev/null > /dev/null
    iptables -t mangle -X SHAPER 2> /dev/null > /dev/null
}




if [ "$1" = "status" ]; then
    tc_status
    exit
elif [ "$1" = "start" ]; then
    del_fwmarks
    add_fwmarks
    tc_start
    exit;
elif [ "$1" = "stop" ]; then
    del_fwmarks
    tc_reset
    exit
else
    echo "Unknown cmd"
    exit
fi




exit



 
