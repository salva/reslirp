# reSLIRP

**reSLIRP** is a comprehensive implementation of SLIRP built using `libslirp`, offering a robust solution for creating and managing virtual network configurations.

## What is SLIRP?

SLIRP originated in the mid-1990s as a solution for Unix systems that lacked direct network access. It was initially designed to provide network services in environments without physical or direct network connections by masquerading TCP/IP traffic, making it appear as if it originated from the host system. This enabled isolated systems to connect seamlessly to external networks.

Over time, SLIRP evolved and found applications in modern computing scenarios. While its original use case was focused on Unix, it has since become a versatile utility commonly employed in various situations:

- **Virtualization and Emulation**: `libslirp` is commonly used with virtual machine and emulation software (e.g., QEMU, Bochs) to allow guest systems to connect to external networks via the host’s connection without requiring additional network configuration or root privileges on the host system. This is particularly helpful in scenarios where guest systems are isolated or constrained from accessing host networks directly.

- **WSL Integration with VPNs**: One particularly valuable use case for `reSLIRP` is its application with Windows Subsystem for Linux (WSL). WSL typically lacks support for routing traffic through VPN connections initiated on the Windows host. By using `reSLIRP`, traffic from the WSL environment can be masqueraded to seamlessly route through the host's VPN connection. This approach bridges the gap between the Linux subsystem and the Windows network stack, enabling WSL to access resources that are only available through the VPN.

- **Development and Testing**: SLIRP can be beneficial for developers who need to test networked applications in isolated virtual environments. It allows virtualized applications to interact with the internet or a larger network in a controlled manner.

Overall, SLIRP and its derivatives and reimplementations remain versatile tools for facilitating network connectivity in virtualized, emulated, and other environments, continuing to serve various use cases in modern computing.

## Usage

```bash
reslirp [OPTIONS]
```

In most cases, running `reSLIRP` without any options will suffice for general use.

## Options

- `-n, --vnetwork`: Specifies the base address of the virtual network you want to configure. This typically sets the range of IPs available in the network.
- `-m, --vnetmask`: Sets the subnet mask of the virtual network. This determines the size of the subnet and aids in defining network boundaries within your IP range.
- `-h, --vhost`: Assigns a specific IP address to the virtual host within the network. This is the primary IP used for network operations.
- `-s, --vnameserver`: Assigns the IP address of the DNS server that the virtual network should use for resolving domain names.
- `-t, --if-mtu`: Configures the Maximum Transmission Unit (MTU) for the network interface, which defines the largest packet size that can be transmitted.
- `-r, --if-mru`: Sets the Maximum Receive Unit (MRU) for the network interface, impacting the size of incoming packet processing.
- `--disable-dns`: Turns off DNS services within the network, which might be necessary for security or performance reasons.
- `--disable-dhcp`: Deactivates DHCP, requiring manual IP configuration within the network.
- `--restricted`: Activates restricted mode to enhance security by limiting network operations.
- `--disable-host-loopback`: Prevents network traffic from looping back to the host, which can be useful for isolating network segments.
- `--enable-emu`: Turns on network emulation settings for simulating specific network conditions.
- `--vhostname`: Sets the hostname for the virtual environment, useful for identifying the host in the network.
- `--tftp-server-name`: Defines the name of the TFTP server, which can be used for file transfers.
- `--tftp-path`: Determines the file path for the TFTP directory, specifying where to store or access files.
- `--bootfile`: Sets the location of the bootfile, which the system uses during network boot operations.
- `--vnameserver6`: Configures an IPv6 DNS server address for resolving domain names in IPv6 networks.
- `--vdnssearch`: Defines a list of DNS search domains, aiding in domain name resolution by appending these domains when searching for hosts.
- `--vdomainname`: Sets the domain name for the virtual environment, used to distinguish or categorize networks.
- `--mfr-id`: Specifies an identifier for the manufacturer, often used for inventory or tracking purposes.
- `--oob-eth-addr`: Defines an out-of-band Ethernet address, used for managing the network independent of the operating traffic system.
- `-d, --debug`: Increases verbosity of debug logging. The accepted levels range from 0 (no debug information) to 4 (most detailed debug output).
- `-D, --dump`: Enables different dump modes for monitoring and logging network traffic. Options include:
  - `ether`: To log Ethernet layer traffic,
  - `ip`: For Internet Protocol traffic,
  - `ipv4`: Specific to IPv4 traffic,
  - `ipv6`: Specific to IPv6 traffic,
  - `dhcp`: For Dynamic Host Configuration Protocol traffic,
  - `dns`: To log Domain Name System traffic.
- `-q, --quiet`: Silences reslirp. Even warnings and errors.
- `-?, --help`: Displays detailed information about the command usage and all available options, useful for users seeking guidance on usage.## Example
```bash
reslirp --vnetwork 10.0.2.0 --vnetmask 255.255.255.0 \
        --vhost 10.0.2.2 --vnameserver 10.0.2.3 \
        --dump ether,ip --debug --enable_emu
```

This example sets up a virtual network with specified addresses, enables network packet dumping for specific protocols, activates debug information, and turns on emulation mode.

## Features

- **Virtual Network Configuration**: Set network, mask, and host addresses using `--vnetwork`, `--vnetmask`, and `--vhost`.
- **Advanced Debugging**: Utilize `--debug` for detailed logging.
- **Custom DNS and DHCP**: Easily enable/disable and configure DNS/DHCP services.
- **Restrictive and Emulation Modes**: Specialized configurations for enhanced security and emulation.

## Cable Protocol

reSLIRP requires network packets to include a two-byte length prefix,
which is the same method used by `vde_plug` on the "cable" side. This
design prevents packet fragmentation and corruption during tunneling,
such as over SSH.

If you prefer/need other protocol just ask for it!

### Example: Tunneling a TAP Interface Using dpipe, vde_plug, and SSH

To tunnel a TAP interface over SSH to a remote machine, run as root:

```bash
dpipe vde_plug tap://dev/tap0 = ssh user@remote reslirp &
ip link set dev tap0 up
udhcpc -i tap0
```

- `vde_plug tap://dev/tap0` connects the local TAP interface (`tap0`)
  and forwards its data stream to standard input/output.
- `ssh user@remote reslirp` opens an SSH connection to the remote
  machine and runs `reslirp`, which provides SLIRP networking on the
  remote side.
- `dpipe` links the input/output streams of `vde_plug` and `ssh`,
  creating the tunnel.
- `ip link set dev tap0 up` activates the local TAP interface.
- `udhcpc -i tap0` uses DHCP to assign an IP address to the `tap0` interface.

This setup securely tunnels traffic from the local TAP interface to
the remote machine via SSH, where it is masqueraded by
`reslirp`. Additional configurations, like setting up routes or DNS
resolvers, may be required for specific use cases.

