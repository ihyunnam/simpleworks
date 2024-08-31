use crate::gadgets::ConstraintF;
use anyhow::{anyhow, Result};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

pub fn serialize_field_element(field_element: ConstraintF) -> Result<Vec<u8>> {
    let mut bytes_field_element = Vec::new();
    field_element
        .serialize_with_mode(&mut bytes_field_element, Compress::Yes)
        .map_err(|e| anyhow!("Error serializing proof: {e:?}"))?;
    Ok(bytes_field_element)
}

pub fn deserialize_field_element(bytes_field_element: Vec<u8>) -> Result<ConstraintF> {
    ConstraintF::deserialize_with_mode(&mut bytes_field_element.as_slice(), Compress::Yes, Validate::Yes)       // Note: just added compress and validate
        .map_err(|e| anyhow!("Error deserializing field element: {e:?}"))
}

// NOTE commented out to kill marlin

// #[allow(clippy::print_stdout)]
// #[cfg(test)]
// mod tests {
//     use super::serialize_field_element;
//     use crate::{gadgets::ConstraintF, marlin};
//     use ark_ff::UniformRand;

//     #[test]
//     fn test_serialize_field_element() {
//         let nonce = ConstraintF::rand(&mut marlin::generate_rand());

//         let v = serialize_field_element(nonce).unwrap();

//         println!("{v:?}");
//     }
// }
