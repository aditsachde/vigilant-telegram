// https://github.com/marshallpierce/rust-base64/issues/213
use base64_impl::engine::general_purpose::STANDARD;
use base64_impl::engine::Engine;
pub use base64_impl::DecodeError;

#[inline]
pub fn decode<T>(input: T) -> Result<Vec<u8>, DecodeError>
where
    T: AsRef<[u8]>,
{
    STANDARD.decode(input)
}

#[inline]
pub fn encode<T>(input: T) -> String
where
    T: AsRef<[u8]>,
{
    STANDARD.encode(input)
}
