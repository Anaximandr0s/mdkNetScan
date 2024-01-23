<h1 align="center"> mdkNetScan </h1>
<p align="center">
  <a href="https://www.python.org/ftp/python/3.12.1/python-3.12.1-amd64.exe"><img src="https://img.shields.io/badge/python-3.12-blue"></a>
  <a href='https://www.linkedin.com/in/mohamed-doukkani/' target="_blank"><img alt='Linkedin' src='https://img.shields.io/badge/mdk19-100000?style=plastic&logo=Linkedin&logoColor=FFFFFF&labelColor=B7B7B7&color=593FEA'/></a>
  <a href="https://github.com/doukkani17moha/mdkNetScan/issues"><img src="https://img.shields.io/github/issues/doukkani17moha/mdkNetScan"></a>
  <a href='https://github.com/doukkani17moha/mdkNetScan' target="_blank"><img alt='Github' src='https://img.shields.io/badge/January_2024-100000?style=plastic&logo=Github&logoColor=FFFFFF&labelColor=B7B7B7&color=FF2222'/></a>
  <a href="https://github.com/doukkani17moha/mdkNetScan/stargazers"><img src="https://img.shields.io/github/stars/doukkani17moha/mdkNetScan"></a>
</p>

![alt text](https://github.com/doukkani17moha/mdkNetScan/blob/main/mdkNetScan.png)

## How it works
- ### Scan all, common, or range ports
Sends a TCP SYN packet to the destination on the defined port using threads for each port, enhancing the scanning speed. If the port is open, it utilizes a function (`get_service_name`) to determine the service running on the port. The get_service_name function leverages the (`socket`)socket library to retrieve the service name associated with the given port. If the service name is found, it is printed; otherwise, it is labeled as "Unknown Service." This threaded approach allows for a more efficient and rapid scan of multiple ports.

- ### Discover hosts in network
Uses the router's IP as a base to map all possible IPs. You can specify the protocol used (ICMP, ARP) to send a packet to each IP and waits for a response. If it receives any response, it saves the IP of the online host. When it finishes checking all hosts, it prints all online hosts.

- ### OS Scan
Sends an ICMP packet to the destination and waits for a response. Then, it extracts the TTL from the destination response and checks the possible OS in a list. If it finds any, it prints it.

- ### Timeout and Interface Options
You have the flexibility to customize the scan by specifying a timeout for each request. This allows you to control the duration for waiting for a response from the target. Additionally, you can choose the network interface (`interface`) through which the requests will be sent. This is useful in cases where you have multiple network interfaces, enabling you to select a specific one for the scanning operation.


## OS Support
- **Windows** :heavy_check_mark:              
- **Linux** :heavy_check_mark: 
- **Android** :heavy_check_mark:            
- **Mac** :question:

## How to install
Clone this repository
``` git clone https://github.com/doukkani17moha/mdkNetScan.git ```                                                                                    
- Install python 3.
  - Linux
    - ``` apt-get install python3 ```
    - ``` cd mdkNetScan ```
    - ``` chmod +x * ```
    - ``` python3 -m pip install -r requirements.txt ```
    - Done!
  - Windows
    - [Python 3, download and install](https://www.python.org/ftp/python/3.12.1/python-3.12.1-amd64.exe)
    - ``` cd mdkNetScan ```
    - ``` python3 -m pip install -r requirements.txt ```
    - Done!

## Arguments
## Arguments
- -sC | Scan common ports
  - -H | Target host (e.g., 127.0.0.1, 192.168.1.105)
  - -i | Interface to use
  - -t | Timeout to each request
- -sA | Scan all ports
  - -H | Target host (e.g., 127.0.0.1, 192.168.1.105)
  - -i | Interface to use
  - -t | Timeout to each request
- -sP | Scan a range of ports (e.g., 80, [1-100])
  - -H | Target host (e.g., 127.0.0.1, 192.168.1.105)
  - -i | Interface to use
  - -t | Timeout to each request
- -sO | Scan OS of a target
  - -H   Target host (e.g., 127.0.0.1, 192.168.1.105)
  - -i | Interface to use (optional)
  - -t | Timeout to each request (optional)
- -d  | Discover hosts in the network
  - -p | Protocol to use in the scan [ICMP, ARP]
  - -i | Interface to use


## Examples

- Discover hosts
```bash
mdkNetScan.py -d -p [ICMP,ARP]
```

- Scan common ports using SYN Scan
```bash
mdkNetScan.py -sC -H 192.168.1.105 -t 5 -i eth0
```

- Scan a range of ports
```bash
mdkNetScan.py -sP 1-443 -H 192.168.1.105
```

- Scan OS
```bash
mdkNetScan.py -sO -H 192.168.1.105
```

## Contributing

Feel free to fork this project, add new functionalities, or resolve any issues you encounter. Your contributions are highly welcomed and can make this tool even better. If you have ideas for improvements, new features, or bug fixes, please open an issue or submit a pull request.

Let's collaborate to make `mdkNetScan` more powerful and efficient together!

## License
Created By [Mohamed Doukkani](https://www.linkedin.com/in/mohamed-doukkani/) with ❤️, Happy hacking!