use crate::cvt_p;
use crate::error::ErrorStack;
use crate::md::MdRef;
use foreign_types::ForeignTypeRef;
use openssl_macros::corresponds;
use libc::{c_void, c_uint};
use std::convert::TryFrom;

/// Computes the HMAC as a one-shot operation.
///
/// Calculates the HMAC of data, using the given |key|
/// and hash function |md|, and returns the result re-using the space from
/// buffer |out|. On entry, |out| must contain at least |EVP_MD_size| bytes
/// of space. The actual length of the result is used to resize the returned
/// slice. An output size of |EVP_MAX_MD_SIZE| will always be large enough.
/// It returns a resized |out| or ErrorStack on error.
#[corresponds(HMAC)]
#[inline]
pub fn hmac<'a>(
    md: &MdRef,
    key: &[u8],
    data: &[u8],
    out: &'a mut [u8]
) -> Result<&'a [u8], ErrorStack> {
    let mut out_len = c_uint::try_from(out.len()).unwrap();
    unsafe {
        cvt_p(ffi::HMAC(
            md.as_ptr(),
            key.as_ptr() as *const c_void,
            key.len(),
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
            &mut out_len
            ))?;
    }
    Ok(&out[..out_len as usize])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::md::Md;
    use crate::memcmp;

    const SHA_256_DIGEST_SIZE:usize = 32;

    #[test]
    fn hmac_sha256_test() {
        let expected_hmac = [0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0xb, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x0, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7];
        let mut out: [u8; SHA_256_DIGEST_SIZE] = [0; SHA_256_DIGEST_SIZE];
        let key:[u8; 20] = [0x0b; 20];
        let data = b"Hi There";
        let hmac_result = hmac(Md::sha256(), &key, data, &mut out).expect("Couldn't calculate sha256 hmac");
        expect!(memcmp::eq(&hmac_result, &expected_hmac));
    }

    #[test]
    fn hmac_sha256_test_big_buffer() {
        let expected_hmac = [0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0xb, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x0, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7];
        let mut out: [u8; 100] = [0; 100];
        let key:[u8;20] = [0x0b; 20];
        let data = b"Hi There";
        let hmac_result = hmac(Md::sha256(), &key, data, &mut out).expect("Couldn't calculate sha256 hmac");
        expect_eq!(hmac_result.len(), SHA_256_DIGEST_SIZE);
        expect!(memcmp::eq(&hmac_result, &expected_hmac));
    }
}
