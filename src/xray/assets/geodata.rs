//! Bounded parsing of the Xray geodat.proto wire format.
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, BufReader, Read},
    path::Path,
};

const MAX_TAGS: usize = 8192;

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Ip,
    Site,
}

pub(super) fn validate(path: &Path, kind: Kind) -> Result<()> {
    read_file(path, |reader| validate_list(reader, kind))
}

pub(super) fn tags(path: &Path, kind: Kind) -> Result<Vec<String>> {
    read_file(path, |reader| read_tags(reader, kind))
}

fn read_file<T>(
    path: &Path,
    parse: impl FnOnce(&mut BufReader<io::Take<File>>) -> Result<T>,
) -> Result<T> {
    super::plain_file(path)?;
    let file = File::open(path)?;
    ensure!(
        (1..=super::MAX_GEODATA).contains(&file.metadata()?.len()),
        "Invalid geodata size"
    );
    let mut reader = BufReader::new(file.take(super::MAX_GEODATA + 1));
    let data = parse(&mut reader)?;
    ensure!(reader.get_ref().limit() != 0, "Invalid geodata size");
    Ok(data)
}

fn validate_list(reader: &mut impl Read, kind: Kind) -> Result<()> {
    scan_list(reader, Some(kind), |_| Ok(()))
}

fn read_tags(reader: &mut impl Read, kind: Kind) -> Result<Vec<String>> {
    let kind = match kind {
        Kind::Ip => "geoip",
        Kind::Site => "geosite",
    };
    let mut tags = BTreeSet::new();
    scan_list(reader, None, |name| {
        if super::super::profile::valid_geo_code(name, kind) {
            tags.insert(name.to_ascii_lowercase());
            ensure!(tags.len() <= MAX_TAGS, "Too many geodata categories");
        }
        Ok(())
    })?;
    Ok(tags.into_iter().collect())
}

fn scan_list(
    reader: &mut impl Read,
    validate: Option<Kind>,
    mut category: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    let mut has_data = false;
    while let Some(key) = varint(reader)? {
        ensure!(key == 10, "Invalid geodata list entry");
        has_data |= delimited(reader, |entry| scan_entry(entry, validate, &mut category))?;
    }
    ensure!(has_data, "The geodata file has no rules");
    Ok(())
}

fn scan_entry(
    reader: &mut impl Read,
    validate: Option<Kind>,
    category: impl FnOnce(&str) -> Result<()>,
) -> Result<bool> {
    let mut name = [0; 128];
    let mut name_len = 0;
    let mut rules = false;
    while let Some(key) = varint(reader)? {
        match key {
            10 => {
                ensure!(name_len == 0, "Invalid geodata category");
                let len = length(reader)?;
                ensure!(
                    (1..=name.len() as u64).contains(&len),
                    "Invalid geodata category"
                );
                name_len = len as usize;
                let name = &mut name[..name_len];
                reader.read_exact(name)?;
                ensure!(
                    name.iter().all(u8::is_ascii_graphic),
                    "Invalid geodata category"
                );
            }
            18 => {
                delimited(reader, |rule| match validate {
                    Some(Kind::Ip) => validate_ip(rule),
                    Some(Kind::Site) => validate_site(rule),
                    None => io::copy(rule, &mut io::sink())
                        .map(|_| ())
                        .map_err(Into::into),
                })?;
                rules = true;
            }
            _ => skip(reader, key)?,
        }
    }
    ensure!(name_len != 0, "Missing geodata category");
    if rules {
        category(std::str::from_utf8(&name[..name_len])?)?;
    }
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

    #[test]
    fn geodata_tags_are_lowercase_sorted_unique_and_usable() {
        let mut file = Vec::new();
        for name in [
            "RU",
            "category-RU",
            "ru",
            "IN-CN@CMCC",
            "GEOLOCATION-!CN",
            "US_EAST",
        ] {
            let len = name.len() as u8;
            file.extend([10, len + 7, 10, len]);
            file.extend(name.bytes());
            file.extend([18, 3, 18, 1, b'x']);
        }
        assert_eq!(
            read_tags(&mut file.as_slice(), Kind::Site).unwrap(),
            ["category-ru", "geolocation-!cn", "ru", "us_east"]
        );
        assert_eq!(
            read_tags(&mut file.as_slice(), Kind::Ip).unwrap(),
            ["category-ru", "in-cn@cmcc", "ru", "us_east"]
        );
        assert!(read_tags(&mut &file[..file.len() - 1], Kind::Site).is_err());
    }
}
