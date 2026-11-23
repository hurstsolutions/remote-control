//! IPv4 subnets in CIDR form, with the limits the scanner enforces.

use std::fmt;
use std::net::Ipv4Addr;

/// The largest subnet that may be scanned: a /16 (65,536 addresses).
pub const MIN_PREFIX: u8 = 16;
/// Subnets larger than this (more than 1,024 addresses) get a warning in the UI.
pub const WARN_PREFIX: u8 = 22;
/// The most addresses one scan may cover, all selected subnets together.
pub const MAX_SCAN_ADDRESSES: u64 = 1 << 16;

/// An IPv4 network: the address with its host bits cleared, and the prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    network: Ipv4Addr,
    prefix: u8,
}

/// Why a subnet was refused. The `Display` text is shown to the user as is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrError {
    Empty,
    Ipv6,
    Malformed,
    BadPrefix,
    TooLarge { prefix: u8 },
}

impl fmt::Display for CidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CidrError::Empty => f.write_str("Enter a subnet such as 10.0.0.0/24."),
            CidrError::Ipv6 => f.write_str("IPv6 subnets are not supported yet. Enter an IPv4 subnet such as 10.0.0.0/24."),
            CidrError::Malformed => {
                f.write_str("Enter the subnet as an IPv4 address and prefix length, such as 10.0.0.0/24.")
            }
            CidrError::BadPrefix => f.write_str("The prefix length after / must be a number from 0 to 32."),
            CidrError::TooLarge { prefix } => write!(
                f,
                "A /{prefix} is too large to scan: the limit is /{MIN_PREFIX} (65,536 addresses). Split it into smaller subnets."
            ),
        }
    }
}

impl std::error::Error for CidrError {}

impl Cidr {
    /// Parse "a.b.c.d/p" (or a bare address, read as /32). Host bits are cleared, so
    /// "10.0.0.7/24" becomes 10.0.0.0/24. Anything larger than a /16 is refused.
    pub fn parse(text: &str) -> Result<Self, CidrError> {
        let text = text.trim();
        if text.is_empty() {
            return Err(CidrError::Empty);
        }
        if text.contains(':') {
            return Err(CidrError::Ipv6);
        }
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => {
                let prefix = prefix.trim();
                if prefix.is_empty() || prefix.len() > 2 || !prefix.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(CidrError::BadPrefix);
                }
                let prefix: u8 = prefix.parse().map_err(|_| CidrError::BadPrefix)?;
                if prefix > 32 {
                    return Err(CidrError::BadPrefix);
                }
                (address.trim(), prefix)
            }
            None => (text, 32),
        };
        // Ipv4Addr::from_str accepts only the dotted-quad form, which is what we want.
        let address: Ipv4Addr = address.parse().map_err(|_| CidrError::Malformed)?;
        if prefix < MIN_PREFIX {
            return Err(CidrError::TooLarge { prefix });
        }
        Ok(Self::new(address, prefix))
    }

    fn new(address: Ipv4Addr, prefix: u8) -> Self {
        let mask = mask(prefix);
        Self {
            network: Ipv4Addr::from(u32::from(address) & mask),
            prefix,
        }
    }

    pub fn network(&self) -> Ipv4Addr {
        self.network
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Every address in the subnet, including network and broadcast.
    pub fn size(&self) -> u64 {
        1u64 << (32 - u32::from(self.prefix))
    }

    /// Big enough that the UI asks the user to think twice (more than 1,024 addresses).
    pub fn is_large(&self) -> bool {
        self.prefix < WARN_PREFIX
    }

    /// Private, shared or local address space: RFC 1918, carrier-grade NAT (RFC 6598),
    /// link-local and loopback. Anything else needs the user's explicit confirmation.
    pub fn is_private(&self) -> bool {
        const PRIVATE: [(u32, u8); 6] = [
            (0x0A00_0000, 8),  // 10.0.0.0/8
            (0xAC10_0000, 12), // 172.16.0.0/12
            (0xC0A8_0000, 16), // 192.168.0.0/16
            (0x6440_0000, 10), // 100.64.0.0/10 (CGNAT)
            (0xA9FE_0000, 16), // 169.254.0.0/16 (link-local)
            (0x7F00_0000, 8),  // 127.0.0.0/8 (loopback)
        ];
        let start = u32::from(self.network);
        PRIVATE
            .iter()
            .any(|&(net, len)| len <= self.prefix && start & mask(len) == net)
    }

    /// The addresses to probe. Up to /30 the network and broadcast addresses are skipped; a /31
    /// has two usable addresses (RFC 3021) and a /32 is the one address.
    pub fn hosts(&self) -> impl Iterator<Item = Ipv4Addr> {
        let start = u32::from(self.network);
        let last = start + (self.size() - 1) as u32;
        let (first, last) = if self.prefix <= 30 { (start + 1, last - 1) } else { (start, last) };
        (first..=last).map(Ipv4Addr::from)
    }

    /// How many addresses `hosts` yields.
    pub fn host_count(&self) -> u64 {
        if self.prefix <= 30 {
            self.size() - 2
        } else {
            self.size()
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes() {
        let cidr = Cidr::parse(" 10.20.0.0/24 ").unwrap();
        assert_eq!(cidr.to_string(), "10.20.0.0/24");
        assert_eq!(Cidr::parse("10.20.0.77/24").unwrap().to_string(), "10.20.0.0/24");
        assert_eq!(Cidr::parse("192.0.2.5").unwrap().to_string(), "192.0.2.5/32");
        assert_eq!(Cidr::parse("10.0.0.0/16").unwrap().size(), 65_536);
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(Cidr::parse(""), Err(CidrError::Empty));
        assert_eq!(Cidr::parse("fd00::/64"), Err(CidrError::Ipv6));
        assert_eq!(Cidr::parse("::1"), Err(CidrError::Ipv6));
        for bad in ["10.0.0/24", "10.0.0.256/24", "office", "10.0.0.0/24/1", "010.0.0.0x/24", "1.2.3.4.5"] {
            assert!(Cidr::parse(bad).is_err(), "{bad}");
        }
        for bad in ["10.0.0.0/", "10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/ab", "10.0.0.0/+8", "10.0.0.0/024"] {
            assert_eq!(Cidr::parse(bad), Err(CidrError::BadPrefix), "{bad}");
        }
    }

    #[test]
    fn refuses_anything_larger_than_a_16() {
        assert_eq!(Cidr::parse("10.0.0.0/15"), Err(CidrError::TooLarge { prefix: 15 }));
        assert_eq!(Cidr::parse("0.0.0.0/0"), Err(CidrError::TooLarge { prefix: 0 }));
        assert!(Cidr::parse("10.0.0.0/15").unwrap_err().to_string().contains("/16"));
        assert!(Cidr::parse("10.0.0.0/21").unwrap().is_large());
        assert!(!Cidr::parse("10.0.0.0/22").unwrap().is_large());
    }

    #[test]
    fn skips_network_and_broadcast() {
        let hosts: Vec<_> = Cidr::parse("10.0.0.0/30").unwrap().hosts().collect();
        assert_eq!(hosts, [Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]);
        let cidr = Cidr::parse("10.0.0.0/24").unwrap();
        assert_eq!(cidr.hosts().count(), 254);
        assert_eq!(cidr.host_count(), 254);
        assert_eq!(cidr.hosts().next(), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(cidr.hosts().last(), Some(Ipv4Addr::new(10, 0, 0, 254)));
        assert_eq!(Cidr::parse("10.0.0.0/31").unwrap().hosts().count(), 2);
        assert_eq!(Cidr::parse("10.0.0.9/32").unwrap().hosts().collect::<Vec<_>>(), [Ipv4Addr::new(10, 0, 0, 9)]);
        // The top of the address space does not overflow.
        assert_eq!(Cidr::parse("255.255.255.255/32").unwrap().hosts().count(), 1);
        assert_eq!(Cidr::parse("255.255.0.0/16").unwrap().host_count(), 65_534);
    }

    #[test]
    fn knows_private_ranges() {
        for private in ["10.0.0.0/16", "172.16.0.0/16", "172.31.255.0/24", "192.168.1.0/24", "100.64.0.0/16", "169.254.0.0/16", "127.0.0.0/30"] {
            assert!(Cidr::parse(private).unwrap().is_private(), "{private}");
        }
        for public in ["192.0.2.0/24", "172.32.0.0/16", "8.8.8.0/24", "100.128.0.0/16", "11.0.0.0/16"] {
            assert!(!Cidr::parse(public).unwrap().is_private(), "{public}");
        }
    }
}
