//! Just enough of the DNS wire format for unicast mDNS and NetBIOS queries.
//! Every input is untrusted: all reads are bounds-checked and compression loops are cut off.

/// One resource record from a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    /// Offset of the RDATA in the message (needed to expand compressed names inside it).
    pub data_offset: usize,
    pub data: Vec<u8>,
}

pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_NBSTAT: u16 = 33;

/// Append a name as length-prefixed labels.
pub fn push_name(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        let bytes = &label.as_bytes()[..label.len().min(63)];
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
}

/// A query with the given (name, type) questions, class IN.
pub fn query(id: u16, flags: u16, questions: &[(&str, u16)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&(questions.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for (name, rtype) in questions {
        push_name(&mut out, name);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
    }
    out
}

/// Read the (possibly compressed) name at `offset`. Returns it and the offset just after it.
pub fn read_name(message: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut position = offset;
    let mut end = None;
    for _ in 0..64 {
        let length = *message.get(position)?;
        match length {
            0 => {
                let after = end.unwrap_or(position + 1);
                return Some((labels.join("."), after));
            }
            l if l & 0xC0 == 0xC0 => {
                let pointer = (usize::from(l & 0x3F) << 8) | usize::from(*message.get(position + 1)?);
                end.get_or_insert(position + 2);
                position = pointer;
            }
            l if l < 64 => {
                let label = message.get(position + 1..position + 1 + usize::from(l))?;
                labels.push(String::from_utf8_lossy(label).into_owned());
                position += 1 + usize::from(l);
            }
            _ => return None,
        }
    }
    None
}

/// Answer, authority and additional records of a response with transaction `id`.
pub fn records(message: &[u8], id: u16) -> Option<Vec<Record>> {
    if message.len() < 12 || u16::from_be_bytes([message[0], message[1]]) != id || message[2] & 0x80 == 0 {
        return None;
    }
    let count = |i: usize| usize::from(u16::from_be_bytes([message[i], message[i + 1]]));
    let mut offset = 12;
    for _ in 0..count(4) {
        offset = read_name(message, offset)?.1 + 4;
    }
    let total = count(6) + count(8) + count(10);
    let mut out = Vec::new();
    for _ in 0..total.min(64) {
        let (name, after) = read_name(message, offset)?;
        let fixed = message.get(after..after + 10)?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let length = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let data_offset = after + 10;
        let data = message.get(data_offset..data_offset + length)?.to_vec();
        out.push(Record { name, rtype, data_offset, data });
        offset = data_offset + length;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_and_compression_is_followed() {
        let mut message = query(7, 0, &[("a.example", 1)]);
        message[2] |= 0x80;
        // One answer whose name points back at the question's name.
        message[7] = 1;
        message.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 2, 9, 9]);
        let records = records(&message, 7).unwrap();
        assert_eq!(records[0].name, "a.example");
        assert_eq!(records[0].data, [9, 9]);
        assert!(super::records(&message, 8).is_none(), "another transaction");
    }

    #[test]
    fn hostile_input_does_not_loop_or_panic() {
        // A pointer to itself.
        assert_eq!(read_name(&[0xC0, 0], 0), None);
        assert_eq!(read_name(&[5, b'a'], 0), None);
        let mut message = vec![0, 1, 0x80, 0, 0, 0, 0, 0xFF, 0, 0, 0, 0];
        message.extend_from_slice(&[0, 0, 1]);
        assert_eq!(records(&message, 1), None);
    }
}
