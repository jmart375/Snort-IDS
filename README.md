![download](https://github.com/jmart375/Snort-IDS/assets/91294710/57c73232-d80a-4261-a59c-3837081ca549)

# Intrusion Detection System Lab Report

<h2>Description</h2>
Snort is a versatile and effective tool for monitoring and protecting networked environments against a variety of security threats. Its combination of signature-based detection, packet inspection, and rule-based customization makes it a valuable asset in the cybersecurity toolkit.
<br />

## Intrusion Detection System Lab Setup
This lab aims to determine the alerts generated for a Snort intrusion detection system (IDS) running on a network where malicious network traffic is present. The lab network is a network address translation (NAT) network with three virtual machines (VM) hosts: Metasploitable 2, Kali Linux, and Snort. Metasploitable 2 is an intentionally vulnerable Linux host that can be easily exploited. Kali Linux is an industry-standard penetration-testing Linux distribution. The Snort IDS runs on Ubuntu 22.04.1 LTS server, and the virtual network interface card (NIC), enp0s3, is running in promiscuous mode. The network is sandboxed to prevent extraneous network traffic during the lab exercise. The network IP address is 172.16.1.0/29, with a default gateway of 172.16.1.1 and a broadcast address of 172.16.1.7. The VM IP addresses are as follows:

- Metasploitable 2: 172.16.1.4
•	Kali Linux: 172.16.1.5
•	Snort IDS: 172.16.1.6

## Snort IDS Setup
Before commencing the lab exercise, the Snort IDS host required minimal setup. The host’s NIC was placed into the promiscuous mode with the following command: sudo ip link set enp0s3 promisc on. The command was confirmed by checking the NIC status with ip a. 
```
command: sudo link set enp0s3 promisc on
```
![image](https://github.com/jmart375/Snort-IDS/assets/91294710/3e1a630c-6a7d-4f6d-938a-4ce282ff6bce)

![image](https://github.com/jmart375/Snort-IDS/assets/91294710/b24d1754-ae5e-4ba8-954c-e9f433dccda3)

The Snort IDS was initialized in alert mode, will print any alerts to the terminal, and loaded rules located in the configuration file: 
```
sudo snort -A console -c /etc/snort/snort.conf.
```
![image](https://github.com/jmart375/Snort-IDS/assets/91294710/ae31904a-9df1-4bb4-b6bd-660ee85cc2da)

## Enumeration
### TCP Port Scanning
From the Kali Linux VM, a series of network mapper (Nmap) scans were conducted against the Metasploitable 2 VM. The first was a TCP port scan (nmap -sT 172.16.1.4), which determines which TCP ports are open on the target host. The Snort IDS created two alerts for this scan, indicating traffic via TCP by the simple network management protocol (SNMP). Both alerts are classified as attempted information leakage and are listed with a priority of 2. Based on the source and destination IP address, it can be seen that both SNMP requests originate from the Kali Linux VM and are destined for the Metasploitable 2 VM. 
![image](https://github.com/jmart375/Snort-IDS/assets/91294710/9188d852-6a26-400a-b0be-bae520a1f0d4)

### UDP Port Scanning
The second scan was a Nmap UDP port scan (nmap -T5 --top-ports=5 -sU -sV 172.16.1.4). Similar to the TCP scan, this scan is intended to discover services running on exposed UDP ports. The scan was conducted a second time with the -T3 option, and both scans were repeated an additional time. Each of the UDP scans generated 3 Snort IDS alerts. These alerts indicated that, again, the requests were from SNMP. They were also classified as priority two and attempted information leakage. As with the previous warnings on the TCP scan, the alerts indicate the source is the Kali Linux VM, and the destination is the Metasploitable 2 VM. 
![image](https://github.com/jmart375/Snort-IDS/assets/91294710/13eb98de-f8ab-4b74-9e41-b46ee14e4235)
![image](https://github.com/jmart375/Snort-IDS/assets/91294710/fea304bc-f388-41e0-b787-f39a8732ed50)
![image](https://github.com/jmart375/Snort-IDS/assets/91294710/6fe837ba-6af8-46eb-b3ed-bd311909ae71)
![image](https://github.com/jmart375/Snort-IDS/assets/91294710/b7a5e9c9-a21c-4d08-9eff-b0c0491ecdb6)

## Operating System Detection
Operating system (OS) detection is essential when finding the operating system you are planning to attack and, in this situation, the Metasploitable2 VM. After running the command (sudo nmap –O 172.16.1.4), the command automatically runs a port scan to fingerprint to target the OS. The Snort IDS identified this type of scan as an XMAS scan, as shown in the picture below.  This can be classified as priority 2, attempted information leak. 
![image](https://github.com/jmart375/Snort-IDS/assets/91294710/51335084-540f-4202-8594-d445a043ad03)


## Service Version Scanning
Service version scanning is version detection that uses various probes in the Nmap-services-probes file to solicit service and application responses. Nmap queries the target host with the probe information and analyzes the response, comparing it against known reactions for various services, applications, and versions. Nmap will attempt to identify the parameters such as: service protocol, application name, version number, hostname, device type, operating system family, miscellaneous detail, and port state. We run a version scan to detect security holes or vulnerabilities in outdated or specific software versions. In the picture below, we are performing a version scan using the -sV command, which will give us a list of services with their versions that the Metasploitable VM has.
![image](https://github.com/jmart375/Snort-IDS/assets/91294710/76424916-d2a5-4d9a-8e5e-e45df6758434)


## The “Kitchen Sink” Scan
Using the sudo nmap –A 172.16.1.4 command, you can run what is referred to as the Kitchen Sink scan. This provides information on specific target systems such as OS detection, version detection, script scanning, and traceroute. It is an aggressive command that provides far better information than a regular scan. As shown in the picture below, Snort identified multiple open services running on the Metasploitable VM, which can exploit known vulnerabilities. The findings illustrated below are a mixture of level 2 and level 3 priorities.
![image](https://github.com/jmart375/Snort-IDS/assets/91294710/0c7d2796-edfb-4026-93c5-e1b0865596a9)

## Exploitation
### VSFTPD
In this section, we use a module to exploit a malicious backdoor that was added to the VSFTPD download archive. We run the following exploit using the Metasploit Framework: vsftpd_234_backdoor. The exploit opens a remote command shell session to gain local access to the Metasploitable VM where we can steal account information and destroy the OS remotely. We tested by copying the data we needed from the target computer, and then running the following command to kill the OS: rm -rf /*. The Snort alerts were also classified as priority 2 attempted information leakage. As with the previous alerts on the TCP scan, the alerts indicate the source is the Kali Linux VM, and the destination is the Metasploitable 2 VM. 
![image](https://github.com/jmart375/Snort-IDS/assets/91294710/1715482d-b2bc-41e3-b937-58a783f31451)

## Data Exfiltration
No alerts were provided from Snort, as we believe the behavior is expected as Snort cannot decode the shell traffic going over netcat (NC) over port 4444. After doing some Googling, I think some level of encryption is going on, as you would expect when using HTTPS or SSH. I’ve included the image below to verify that multiple systems could not detect any traffic once the vsftpd exploit is completed. 
![image](https://github.com/jmart375/Snort-IDS/assets/91294710/40353254-92b4-47d8-a847-e94299ba79d5)

## Summary
Based on the results from the previous lab, Snort was an effective IDS. The Nmap scans and the Metasploit Framework exploit created enough alerts that if the IDS were being monitored by a trained analyst, the attack likely would have been detected. There was little differentiation between the TCP and UDP scans in terms of Snort alerts. The other Nmap scans created a significant amount of “noise” and alerts. In particular, the service version and “Kitchen Sink” scans created significantly more alerts than the other scans. It is reasonable to assume that the alerts generated by Snort during the lab would be out of the ordinary for day-to-day enterprise operations. If penetration testers were using the “noisier” Nmap scans, they most certainly would have been detected. What is notable, however, is that the Metasploit Framework vsftpd exploit only generated 2 alerts. If the IDS were deployed in a busy environment and was not tuned properly, it is quite possible that these 2 alerts could be missed amongst all other traffic. 

