```markdown
## PSCAN

PSCAN is a simple Go program that can be used to check the availability of TCP ports on a target IP address range.

## Features

- Scanning a single host or an IP address range in CIDR format
- Support for specifying multiple target ports
- Customizable timeout for port scans
- Option to enable debug mode for detailed output of the scanning process
- Option to enable ultrafast mode for faster scans
- Option to display only open ports


## Usage

1. Make sure you have Go installed on your system.

2. Clone the repository:
```

```shell
git clone https://github.com/ipcis/pscan.git
```

3. Navigate to the project directory:

```shell
cd pscan
```

4. Build the program:

```shell
go install github.com/fatih/color@latest
go mod init pscan
go get github.com/fatih/color
go run pscan_v1.go -ip 192.168.1.0/24 -ports 80,443 -onlyopen -ultrafast
go build
```

5. Run the port scanner:

```shell
./pscan -ip <IP address or CIDR network> -ports <ports> [-timeout <timeout>] [-debug] [-onlyopen] [-ultrafast]
```

- `<IP address or CIDR network>`: The target IP address or CIDR network to scan.
- `<ports>`: A comma-separated list of target ports to scan.
- `<timeout>` (optional): The timeout value in milliseconds for each port scan. Default is 5000 ms.
- `-debug` (optional): Enables debug mode and provides detailed information about the scanning process.
- `-onlyopen` (optional): Displays only open ports.
- `-ultrafast` (optional): Enables ultrafast mode for faster scans.

Example:

```shell
./pscan -ip 192.168.0.0/24 -ports 80,443 -timeout 5 -onlyopen
```

6. The program will now scan the specified IP address range and display the results.

Note: Ensure that you have permission to perform port scans on the specified IP addresses.

## Contribution

- If you have found a bug or would like to propose an improvement, please open an issue or submit a pull request.
- For any questions or issues, contact me at.
```

Feel free to customize this template accordingly and add more details or instructions as needed.
