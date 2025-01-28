# reSLIRP

reSLIRP is a comprehensive SLIRP implementation built using
`libslirp`, offering a robust solution for creating and managing
virtual network configurations.

## SLIRP

SLIRP is a software utility that enables a virtualized or emulated
environment to access network services through the host's internet
connection. Initially developed in the mid-1990s, SLIRP was primarily
used to provide network services on Unix systems that did not have
direct access to a network. It acted as a user-mode network stack,
facilitating the forwarding of TCP/IP traffic from the virtual
environment to the host network.

Today, the idea behind SLIRP remains relevant and useful in various
situations:

- **Virtualization and Emulation**: libslirp is commonly used with
  virtual machine and emulation software (e.g., QEMU, Bochs) to allow
  guest systems to connect to external networks via the host’s
  connection without requiring additional network configuration or
  root privileges on the host system.

  One very interesting use case for `reslirp` in this context is
  allowing WSL to connect through VPNs connections initiated in the
  Windows side, something which is not usually supported/allowed. In
  general this approach can be used to forward traffic from any host
  to the one running the VPN.

- **Development and Testing**: SLIRP can be beneficial for developers
  who need to test networked applications on isolated virtual
  environments. It allows virtualized applications to interact with
  the internet or a larger network in a controlled manner.

Overall, SLIRP and its derivates and reimplementations,
remain versatile tools for facilitating network connectivity in
virtualized, emulated and other environments, continuing to serve
various use cases in modern computing.## Usage

## Usage

```shell
reslirp [OPTIONS]
```

In most cases, running reSLIRP without any options will suffice for general use.

## Options

- `-n, --vnetwork`: Set the virtual network address.
- `-m, --vnetmask`: Set the virtual network mask.
- `-h, --vhost`: Set the virtual host address.
- `-D, --dump`: Set dump flags. Modes include ether, ip, ipv4, ipv6, dhcp, and dns.
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

```shell
reSLIRP --vnetwork 10.0.2.0 --vnetmask 255.255.255.0 \
        --vhost 10.0.2.2 --vnameserver 10.0.2.3 \
        --dump ether,ip --debug --enable_emu
```

This example sets up a virtual network with specified addresses,
enables network packet dumping for specific protocols, activates debug
information, and turns on emulation mode.

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

You can tunnel a TAP interface over SSH to a remote machine using the following list of commands as root:

```bash
dpipe vde_plug tap://dev/tap0 = ssh user@remote reslirp &
ip link set dev <tap-interface-name> up
udhcpc -i tap0
```

In this command:

- `vde_plug tap://dev/tap0` connects the local TAP interface and forwards data to its stdio stream.
- `ssh user@remote reslirp` initiates an SSH connection to the remote machine and runs reslirp, a tool that provides SLIRP networking for the remote end.
- `dpipe` connects the stdio streams of the vde_plugin with those of ssh which actually forwards everything to/from the remote slirp process.
- `ip link set dev tap0 up` brings the specified TAP interface up.
- `udhcpc -i tap0` requests an IP address for the `tap0` interface using the DHCP client.

This setup ensures that data passing through the TAP interface on your
local machine is securely tunneled over SSH to the designated host
where TPC and UDP connections are reinitiated as local connections.

Real life scenarios may require to also set up IP routes and
configuring the resolver (hosts, DNS).
