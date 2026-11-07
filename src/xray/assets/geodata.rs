//! Bounded validation of the Xray geodat.proto wire format before activation.
use anyhow::{Context, Result, ensure};
use std::{
    fs::File,
    io::{self, BufReader, Read},
    path::Path,
};

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Ip,
    Site,
}

pub(super) fn validate(path: &Path, kind: Kind) -> Result<()> {
    super::plain_file(path)?;
    let file = File::open(path)?;
    ensure!(
        (1..=super::MAX_GEODATA).contains(&file.metadata()?.len()),
        "Invalid geodata size"
    );
    validate_list(&mut BufReader::new(file), kind)
}

fn validate_list(reader: &mut impl Read, kind: Kind) -> Result<()> {
    let mut has_data = false;
    while let Some(key) = varint(reader)? {
        ensure!(key == 10, "Invalid geodata list entry");
        has_data |= delimited(reader, |entry| validate_entry(entry, kind))?;
    }
    ensure!(has_data, "The geodata file has no rules");
    Ok(())
}

fn validate_entry(reader: &mut impl Read, kind: Kind) -> Result<bool> {
    let mut code = false;
    let mut rules = false;
    while let Some(key) = varint(reader)? {
        match key {
            10 => {
                let len = length(reader)?;
                ensure!(
                    (1..=128).contains(&len) && !code,
                    "Invalid geodata category"
                );
                let mut name = [0; 128];
                let name = &mut name[..len as usize];
                reader.read_exact(name)?;
                ensure!(
                    name.iter().all(u8::is_ascii_graphic),
                    "Invalid geodata category"
                );
                code = true;
            }
            18 => {
                delimited(reader, |rule| match kind {
                    Kind::Ip => validate_ip(rule),
                    Kind::Site => validate_site(rule),
                })?;
                rules = true;
            }
            _ => skip(reader, key)?,
        }
    }
    ensure!(code, "Missing geodata category");
    Ok(rules)
}

fn validate_ip(reader: &mut impl Read) -> Result<()> {
    let mut address_len = 0;
    let mut prefix = 0;
    while let Some(key) = varint(reader)? {
        match key {
            10 => {
                address_len = length(reader)?;
                ensure!(matches!(address_len, 4 | 16), "Invalid GeoIP address");
                reader.read_exact(&mut [0; 16][..address_len as usize])?;
            }
            16 => prefix = varint(reader)?.context("Missing GeoIP prefix")?,
            _ => skip(reader, key)?,
        }
    }
    ensure!(
        address_len != 0 && prefix <= address_len * 8,
        "Invalid GeoIP network"
    );
    Ok(())
}

fn validate_site(reader: &mut impl Read) -> Result<()> {
    let mut value = false;
    while let Some(key) = varint(reader)? {
        match key {
            8 => ensure!(
                varint(reader)?.is_some_and(|kind| kind <= 3),
                "Invalid GeoSite domain type"
            ),
            18 => {
                let len = length(reader)?;
                ensure!(
                    (1..=64 * 1024).contains(&len),
                    "Invalid GeoSite domain size"
                );
                discard(reader, len)?;
                value = true;
            }
            _ => skip(reader, key)?,
        }
    }
    ensure!(value, "Missing GeoSite domain");
    Ok(())
}

fn delimited<R: Read, T>(
    reader: &mut R,
    parse: impl FnOnce(&mut io::Take<&mut R>) -> Result<T>,
) -> Result<T> {
    let size = length(reader)?;
    let mut limited = reader.take(size);
    let result = parse(&mut limited)?;
    ensure!(limited.limit() == 0, "Truncated geodata message");
    Ok(result)
}

fn length(reader: &mut impl Read) -> Result<u64> {
    let size = varint(reader)?.context("Missing geodata message length")?;
    ensure!(size <= super::MAX_GEODATA, "Invalid geodata message length");
    Ok(size)
}

fn skip(reader: &mut impl Read, key: u64) -> Result<()> {
    ensure!(key >= 8, "Invalid geodata field");
    match key & 7 {
        0 => {
            varint(reader)?.context("Truncated geodata integer")?;
            Ok(())
        }
        1 => discard(reader, 8),
        2 => {
            let size = length(reader)?;
            discard(reader, size)
        }
        5 => discard(reader, 4),
        _ => anyhow::bail!("Unsupported geodata field"),
    }
}

fn discard(reader: &mut impl Read, mut size: u64) -> Result<()> {
    let mut buffer = [0; 256];
    while size != 0 {
        let chunk = size.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..chunk])?;
        size -= chunk as u64;
    }
    Ok(())
}

fn varint(reader: &mut impl Read) -> Result<Option<u64>> {
    let mut byte = [0];
    if reader.read(&mut byte)? == 0 {
        return Ok(None);
    }
    let mut value = 0;
    for shift in (0..=63).step_by(7) {
        if shift != 0 {
            reader.read_exact(&mut byte)?;
        }
        ensure!(shift < 63 || byte[0] <= 1, "Invalid geodata integer");
        value |= u64::from(byte[0] & 0x7f) << shift;
        if byte[0] < 0x80 {
            return Ok(Some(value));
        }
    }
    anyhow::bail!("Invalid geodata integer")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geodata_validation_checks_message_kind_and_truncation() {
        let ip = [
            10, 14, 10, 2, b'R', b'U', 18, 8, 10, 4, 192, 0, 2, 0, 16, 24,
        ];
        let site = [10, 9, 10, 2, b'R', b'U', 18, 3, 18, 1, b'x'];
        validate_list(&mut ip.as_slice(), Kind::Ip).unwrap();
        validate_list(&mut site.as_slice(), Kind::Site).unwrap();
        assert!(validate_list(&mut ip.as_slice(), Kind::Site).is_err());
        assert!(validate_list(&mut site.as_slice(), Kind::Ip).is_err());
        assert!(validate_list(&mut &ip[..ip.len() - 1], Kind::Ip).is_err());
        assert!(validate_list(&mut b"<html>".as_slice(), Kind::Ip).is_err());
    }
}
