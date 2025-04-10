#![allow(dead_code)]

fn vlvec_overhead(data_len: usize) -> usize {
    const MLS_VLBYTES_MAX_LEN: usize = (1 << 30) - 1;
    debug_assert!(
        data_len <= MLS_VLBYTES_MAX_LEN,
        "The serialized size is above the MLS-defined limits of Variable-Length vectors [actual = {data_len}, max = {MLS_VLBYTES_MAX_LEN}]"
    );

    if data_len <= 0x3f {
        1
    } else if data_len <= 0x3fff {
        2
    } else if data_len <= 0x3fff_ffff {
        4
    } else {
        8
    }
}

#[inline]
pub fn tls_serialized_len_as_vlvec(data_len: usize) -> usize {
    vlvec_overhead(data_len) + data_len
}

pub fn write_vlvec_prefix<W: std::io::Write>(
    data_len: usize,
    writer: &mut W,
) -> Result<usize, tls_codec::Error> {
    let overhead = vlvec_overhead(data_len);
    let prefix: u8 = match overhead {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        8 => 0xC0,
        _ => unreachable!(),
    };
    let mut data_len_mix = data_len;

    for i in 0..overhead {
        let base = if i == 0 { prefix } else { 0x00 };
        let byte = base | (data_len_mix & 0xFF) as u8;
        writer.write_all(&[byte])?;
        data_len_mix >>= 8;
    }

    Ok(overhead)
}

pub mod bytes {
    use tls_codec::{Deserialize as _, Serialize as _, Size as _, VLByteSlice, VLBytes};

    pub fn tls_serialized_len(v: &[u8]) -> usize {
        VLByteSlice(v).tls_serialized_len()
    }

    pub fn tls_serialize<W: std::io::Write>(
        v: &[u8],
        writer: &mut W,
    ) -> Result<usize, tls_codec::Error> {
        VLByteSlice(v).tls_serialize(writer)
    }

    pub fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Vec<u8>, tls_codec::Error> {
        Ok(VLBytes::tls_deserialize(bytes)?.into())
    }
}

pub mod optbytes {
    use tls_codec::{Deserialize as _, Serialize as _, Size as _, VLByteSlice, VLBytes};

    pub fn tls_serialized_len<B: AsRef<[u8]>>(v: &Option<B>) -> usize {
        v.as_ref()
            .map(|v| VLByteSlice(v.as_ref()))
            .tls_serialized_len()
    }

    pub fn tls_serialize<W: std::io::Write, B: AsRef<[u8]>>(
        v: &Option<B>,
        writer: &mut W,
    ) -> Result<usize, tls_codec::Error> {
        v.as_ref()
            .map(|v| VLByteSlice(v.as_ref()))
            .tls_serialize(writer)
    }

    pub fn tls_deserialize<R: std::io::Read>(
        bytes: &mut R,
    ) -> Result<Option<Vec<u8>>, tls_codec::Error> {
        Ok(Option::<VLBytes>::tls_deserialize(bytes)?.map(Into::into))
    }
}

pub mod string {
    pub fn tls_serialized_len(v: &str) -> usize {
        super::bytes::tls_serialized_len(v.as_bytes())
    }

    pub fn tls_serialize<W: std::io::Write>(
        v: &str,
        writer: &mut W,
    ) -> Result<usize, tls_codec::Error> {
        super::bytes::tls_serialize(v.as_bytes(), writer)
    }

    #[allow(dead_code)]
    pub fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<String, tls_codec::Error> {
        super::bytes::tls_deserialize(bytes).and_then(|bytes| {
            String::from_utf8(bytes).map_err(|e| {
                tls_codec::Error::DecodingError(format!("Could not decode utf8 string: {e:?}"))
            })
        })
    }
}
