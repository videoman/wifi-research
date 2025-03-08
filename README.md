
## mschapv2-to-des.py
The main file for this program is in mschapv2-to-des.py - 

This program will extract the challege, and DES response and write them to a file that you can load into hashcat using mode 14000.

It uses the ct3.py program to crack the third part of the key (K3). 

## Passing the hash
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

## You can also setup your own Radius server with this option too.

Just add the user to the "users" hostapd-wpe.conf config file. 

# Phase 2 (tunnelled within EAP-PEAP or EAP-TTLS) users
"test" MSCHAPV2 hash:0cb6948805f797bf2a82807973b89537 [2]
