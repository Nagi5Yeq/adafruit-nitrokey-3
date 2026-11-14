use heapless::VecView;
use iso7816::Status;

pub fn extend(buf: &mut VecView<u8>, data: &[u8]) -> Result<(), Status> {
    buf.extend_from_slice(data)
        .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)
}

pub fn push_len(buf: &mut VecView<u8>, len: usize) -> Result<(), Status> {
    match len {
        0..=0x7F => extend(buf, &[len as u8]),
        0x80..=0xFF => extend(buf, &[0x81, len as u8]),
        0x100..=0xFFFF => extend(buf, &[0x82, (len >> 8) as u8, len as u8]),
        _ => Err(Status::UnspecifiedNonpersistentExecutionError),
    }
}

pub fn push_tlv(buf: &mut VecView<u8>, tag: &[u8], value: &[u8]) -> Result<(), Status> {
    extend(buf, tag)?;
    push_len(buf, value.len())?;
    extend(buf, value)
}

pub fn take_tag(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let first = *data.first()?;
    let mut len = 1;
    if first & 0x1F == 0x1F {
        loop {
            let byte = *data.get(len)?;
            len += 1;
            if byte & 0x80 == 0 {
                break;
            }
            if len > 3 {
                return None;
            }
        }
    }
    Some(data.split_at(len))
}

pub fn take_len(data: &[u8]) -> Option<(usize, &[u8])> {
    let (&first, rest) = data.split_first()?;
    match first {
        0..=0x7F => Some((first.into(), rest)),
        0x81 => {
            let (&len, rest) = rest.split_first()?;
            Some((len.into(), rest))
        }
        0x82 => {
            let (len, rest) = rest.split_first_chunk::<2>()?;
            Some((u16::from_be_bytes(*len).into(), rest))
        }
        _ => None,
    }
}

pub fn take_tlv(data: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let (tag, rest) = take_tag(data)?;
    let (len, rest) = take_len(rest)?;
    if rest.len() < len {
        return None;
    }
    let (value, rest) = rest.split_at(len);
    Some((tag, value, rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use heapless::Vec;

    #[test]
    fn length_encoding() {
        let mut buf: Vec<u8, 8> = Vec::new();
        push_len(buf.as_mut_view(), 0x7F).unwrap();
        push_len(buf.as_mut_view(), 0x80).unwrap();
        push_len(buf.as_mut_view(), 0x1234).unwrap();
        assert_eq!(buf, [0x7F, 0x81, 0x80, 0x82, 0x12, 0x34]);
    }

    #[test]
    fn parse_multi_byte_tag() {
        let (tag, value, rest) = take_tlv(&[0x5F, 0x2F, 0x01, 0x60, 0xAA]).unwrap();
        assert_eq!(tag, [0x5F, 0x2F]);
        assert_eq!(value, [0x60]);
        assert_eq!(rest, [0xAA]);
    }

    #[test]
    fn parse_truncated() {
        assert!(take_tlv(&[0x5C, 0x02, 0x7F]).is_none());
        assert!(take_tlv(&[0x5C, 0x83, 0x00, 0x00, 0x01]).is_none());
    }
}
