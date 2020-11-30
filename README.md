# bobNet
airodump is a diagnostic tool for evaluating WiFi network security.
It provides various functions for wifi security diagnosis.
- Scanning (Monitoring) : Packet capture and export of data to text files for further processing by third party tools.
- Attacking : Fake AP, ARP Pollution, Beacon Flooding, deauthentication and others via packet injection.
- Checking & Testing : Diagnosis is performed based on the attacked information.
If it supports monitor mode and c environment, it can be used anywhere.

# Building
Proceed in the monitor mode environment.
1. installing
```
git clone https://github.com/team-234567/bobNET
```
2. Code execution
```
g++ -o bobNET main.cpp dot11.cpp -lpcap -pthread
```
3. Run executable
```
./bobNet <interface>
```

## Run screen
![1](https://user-images.githubusercontent.com/57438644/100564126-71143400-3303-11eb-988c-fe00f58b7a58.png)

## Function Selection screen
![2](https://user-images.githubusercontent.com/57438644/100564136-73768e00-3303-11eb-8f79-31e4dccf9127.png)


# Options
## Scanning
1. Monitoring
2. Help(Usage introduction) : Describes the attack menu to be diagnosed.
3. Rescan : rescan and reselect ap

## Attacking & Checking
1. Fake AP : The probability that the selected ap is a fake ap is judged as a risk rating.
    - Whether to judge - password, ESSID name, ESSID duplicate
2. ARP Pollution : Among the stations connected to the selected ap, Find a station where arp spoofing can proceed.
    - ARP Spoofing - arp spoofing is a man-in-the-middle attack technique that uses messages to intercept data packets from other parties.
3. Beacon Flooding : A beacon packet is transmitted by generating a random MAC address including the same SSID and channel number as the selected AP.
    It is possible to determine whether the selected AP can be attacked by Beacon Flooding.
4. Deauth Attack & Checking : Diagnose by checking if deauth attack is possible against the selected AP.
5. Disasso Attack & Checking : Diagnose by checking if deauth attack is possible against the selected AP.
6. Resasso Attack & Checking : Diagnose by checking if deauth attack is possible against the selected AP.

# Team
project team in BoB(a.k.a [Best of the Best](https://www.kitribob.kr/)) in Republic of Korea.
TEAM-234567

Wireless LAN Diagnostic Framework with Utilization Script(무선랜 진단 프레임워크)


## Team Members
**Project Member**: 김남석([s-bot12](https://github.com/s-bot12)), 고지웅([jiwoongko](https://github.com/jiwoongko)), 공재호([asebn1](https://github.com/asebn1)), 김유현([aramkim09](https://github.com/aramkim09)), 권영우([fullbbadda1208](https://github.com/fullbbadda1208)), 정효종([cheblo49](https://github.com/cheblo49))

**Project Leader**: 최병준([qudwns2052](https://github.com/qudwns2052))

**Project Mentor**: 김홍진([hjkim0892](https://github.com/hjkim0892))
 
