
## mschapv2-to-des.py
The main file for this program is in mschapv2-to-des.py that will get your hashes for hashcat. 

This program will extract the challege, and DES response and write them to a file that you can load into hashcat using mode 14000.

It uses the ct3.py program to crack the third part of the key (K3). 

## ct3.py thanks to EvilMog
[EvilMog](https://github.com/evilmog) made the [ct3.py](https://github.com/evilmog/ntlmv1-multi) from a C+ program in [hashcat_utils] (https://github.com/hashcat/hashcat-utils/blob/master/src/ct3_to_ntlm.c).

None of this stuff is super ground breaking, but we have made it pretty easy to crack a PEAP challenge response. 
EvilMog also has a bunch of fun stuff for NTLMv1 and other fun research.

## Passing the hash
If you crack the three keys that are part of the challenge, you can put them back togother, and use them as an NT hash to do PTH type attacks. A good exmaple is replaying that hash back at the RADIUS server to authenticate to the WiFi. 

Check out this [blog](https://sensepost.com/blog/2020/pass-the-hash-wifi/) for more info on the PTH stuff.

The basic of it is that if you reverse the MsCHAPv2 to an NTLM Hash, you 
can make a wpa_supplicant.conf config that can be used to replayed the NTLM hash 
at the radius server.

## Example wpa_supplicant.conf
```
network={
        ssid="EvilMog"
        scan_ssid=1
        key_mgmt=WPA-EAP
        eap=PEAP
        identity="test"
        password="hash:0cb6948805f797bf2a82807973b89537"
        ca_cert="/etc/cert/ca.pem"
        phase1="peaplabel=0"
        phase2="auth=MSCHAPV2"
}
```

## Evil-Twin Radius Server
You can also setup your own Radius server with this option too.

Just add the user to the "users" hostapd-wpe.conf config file. 

# Phase 2 (tunnelled within EAP-PEAP or EAP-TTLS) users
```
"test" MSCHAPV2 hash:0cb6948805f797bf2a82807973b89537 [2]
```
