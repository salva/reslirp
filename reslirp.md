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

- `-n, --vnetwork`: Set the virtual network address.
- `-m, --vnetmask`: Set the virtual network mask.
- `-h, --vhost`: Set the virtual host address.
- `-D, --dump`: Set dump flags. Modes include `ether`, `ip`, `ipv4`, `ipv6`, `dhcp`, and `dns`.
- `-s, --vnameserver`: Set the nameserver address.
- `-t, --if_mtu`: Define the interface MTU.
- `-r, --if_mru`: Define the interface MRU.
- `-d, --debug`: Increase the debug level. Valid levels range from 0 to 4.
- `--disable_dns`: Disable the DNS feature.
- `--disable_dhcp`: Disable the DHCP feature.
- `--restricted`: Enable restricted mode for enhanced security.
- `--disable_host_loopback`: Disable host loopback for network traffic.
- `--enable_emu`: Enable emulation settings.
- `--vhostname`: Define the virtual hostname.
- `--tftp_server_name`: Define the TFTP server name.
- `--tftp_path`: Set the TFTP directory path.
- `--bootfile`: Define the bootfile location.
- `--vnameserver6`: Set the IPv6-compatible nameserver address.
- `--vdnssearch`: Set DNS search domains.
- `--vdomainname`: Define the domain name.
- `--mfr_id`: Set the manufacturer ID.
- `--oob_eth_addr`: Define the out-of-band Ethernet address.
- `-?, --help`: Print this help message for usage information.

## Example

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

