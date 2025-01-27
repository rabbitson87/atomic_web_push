pub fn rand_bytes(buf: &mut [u8]) -> Result<(), ece::Error> {
    use rand::{rngs::OsRng, RngCore};
    OsRng.fill_bytes(buf);
    Ok(())
}
