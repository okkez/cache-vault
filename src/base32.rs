use base32::Alphabet::Z;

pub fn encode(data: &[u8]) -> String {
    base32::encode(Z, data)
}

pub fn decode(data: &str) -> Option<Vec<u8>> {
    base32::decode(Z, data)
}
