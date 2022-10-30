use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::PrimeField;
use serde::de::{self, Deserializer, SeqAccess, MapAccess, Visitor};
use serde::ser::{SerializeStruct, SerializeTuple};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::structs::{PVSSCiphertext, PVSSSecrets};

pub struct FrSerializable(Fr);
pub struct FqSerializable(Fq);
pub struct Fq2Serializable(Fq2);
pub struct G1AffineSerializable(G1Affine);
pub struct G2AffineSerializable(G2Affine);

impl From<Fr> for FrSerializable {
    fn from(item: Fr) -> Self {
        FrSerializable(item)
    }
}

impl From<Fq> for FqSerializable {
    fn from(item: Fq) -> Self {
        FqSerializable(item)
    }
}

impl From<Fq2> for Fq2Serializable {
    fn from(item: Fq2) -> Self {
        Fq2Serializable(item)
    }
}

impl From<G1Affine> for G1AffineSerializable {
    fn from(item: G1Affine) -> Self {
        G1AffineSerializable(item)
    }
}

impl From<G2Affine> for G2AffineSerializable {
    fn from(item: G2Affine) -> Self {
        G2AffineSerializable(item)
    }
}

impl Into<Fr> for FrSerializable {
    fn into(self) -> Fr {
        self.0
    }
}

impl Into<Fq> for FqSerializable {
    fn into(self) -> Fq {
        self.0
    }
}

impl Into<Fq2> for Fq2Serializable {
    fn into(self) -> Fq2 {
        self.0
    }
}

impl Into<G1Affine> for G1AffineSerializable {
    fn into(self) -> G1Affine {
        self.0
    }
}

impl Into<G2Affine> for G2AffineSerializable {
    fn into(self) -> G2Affine {
        self.0
    }
}

impl Serialize for FrSerializable {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = "0x".to_string() + &self.0.into_repr().to_string().to_lowercase();
        serializer.serialize_newtype_struct("FrSerializable", &s)
    }
}

impl Serialize for FqSerializable {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = "0x".to_string() + &self.0.into_repr().to_string().to_lowercase();
        serializer.serialize_newtype_struct("FqSerializable", &s)
    }
}

impl Serialize for Fq2Serializable {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_tuple(2)?;
        let c0 = "0x".to_string() + &self.0.c0.into_repr().to_string().to_lowercase();
        let c1 = "0x".to_string() + &self.0.c1.into_repr().to_string().to_lowercase();
        state.serialize_element(&c1)?; // NOTE: Important! EIP-197 pairing expects reverse order!
        state.serialize_element(&c0)?;
        state.end()
    }
}

impl Serialize for G1AffineSerializable {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("G1AffineSerializable", 2)?;
        let x: FqSerializable = self.0.x.into();
        let y: FqSerializable = self.0.y.into();
        state.serialize_field("x", &x)?;
        state.serialize_field("y", &y)?;
        state.end()
    }
}

impl Serialize for G2AffineSerializable {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("G2AffineSerializable", 2)?;
        let x: Fq2Serializable = self.0.x.into();
        let y: Fq2Serializable = self.0.y.into();
        state.serialize_field("x", &x)?;
        state.serialize_field("y", &y)?;
        state.end()
    }
}

impl Serialize for PVSSCiphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("PVSSCiphertext", 3)?;
        state.serialize_field(
            "f_i",
            &self
                .f_i
                .iter()
                .map(|&f| f.into())
                .collect::<Vec<G1AffineSerializable>>(),
        )?;
        state.serialize_field(
            "a_i",
            &self
                .a_i
                .iter()
                .map(|&a| a.into())
                .collect::<Vec<G1AffineSerializable>>(),
        )?;
        state.serialize_field(
            "y_i",
            &self
                .y_i
                .iter()
                .map(|&y| y.into())
                .collect::<Vec<G2AffineSerializable>>(),
        )?;
        state.end()
    }
}

impl Serialize for PVSSSecrets {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("PVSSSecrets", 2)?;
        let f_0_serializable: FrSerializable = self.f_0.into();
        let h_f_0_serializable: G2AffineSerializable = self.h_f_0.into();
        state.serialize_field("f_0", &f_0_serializable)?;
        state.serialize_field("h_f_0", &h_f_0_serializable)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for FrSerializable {
    fn deserialize<D>(deserializer: D) -> Result<FrSerializable, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FrVisitor;

        impl<'de> Visitor<'de> for FrVisitor {
            type Value = FrSerializable;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("Big number corresponding to Fr")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() <= 2 || &value[..2] != "0x" {
                    return Err(E::custom("Invalid hex string"));
                }
                let value = &value[2..];
                if let Some(bytes) = hex::decode(value).ok() {
                    let fr = Fr::from_be_bytes_mod_order(bytes.as_slice());
                    if fr.into_repr().to_string().to_lowercase() != value {
                        return Err(E::custom(format!(
                            "Hex value too large {} {} {:?}",
                            value,
                            bytes.len(),
                            bytes
                        )));
                    }
                    Ok(FrSerializable(fr))
                } else {
                    return Err(E::custom("Invalid hex string"));
                }
            }
        }

        deserializer.deserialize_str(FrVisitor)
    }
}

impl<'de> Deserialize<'de> for FqSerializable {
    fn deserialize<D>(deserializer: D) -> Result<FqSerializable, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FqVisitor;

        impl<'de> Visitor<'de> for FqVisitor {
            type Value = FqSerializable;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("Big number corresponding to Fr")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() <= 2 || &value[..2] != "0x" {
                    return Err(E::custom("Invalid hex string"));
                }
                let value = &value[2..];
                if let Some(bytes) = hex::decode(value).ok() {
                    let fq = Fq::from_be_bytes_mod_order(bytes.as_slice());
                    if fq.into_repr().to_string().to_lowercase() != value {
                        return Err(E::custom(format!(
                            "Hex value too large {} {} {:?}",
                            value,
                            bytes.len(),
                            bytes
                        )));
                    }
                    Ok(FqSerializable(fq))
                } else {
                    return Err(E::custom("Invalid hex string"));
                }
            }
        }

        deserializer.deserialize_str(FqVisitor)
    }
}

impl<'de> Deserialize<'de> for Fq2Serializable {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Fq2Visitor;

        impl<'de> Visitor<'de> for Fq2Visitor {
            type Value = Fq2Serializable;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Fq2Serializable")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Fq2Serializable, V::Error>
            where
                V: SeqAccess<'de>,
            {
                // NOTE: Important! EIP-197 pairing expects reverse order!
                let c1: FqSerializable = seq.next_element::<FqSerializable>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?.into();
                let c0: FqSerializable = seq.next_element::<FqSerializable>()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?.into();
                Ok(Fq2Serializable(Fq2::new(c0.into(), c1.into())))
            }
        }

        const FIELDS: &'static [&'static str] = &["c0", "c1"];
        deserializer.deserialize_struct("Fq2Serializable", FIELDS, Fq2Visitor)
    }
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "lowercase")]
enum ECPointField {
    X,
    Y,
}

impl<'de> Deserialize<'de> for G1AffineSerializable {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct G1AffineVisitor;

        impl<'de> Visitor<'de> for G1AffineVisitor {
            type Value = G1AffineSerializable;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct G1AffineSerializable")
            }

            fn visit_map<V>(self, mut map: V) -> Result<G1AffineSerializable, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut x: Option<FqSerializable> = None;
                let mut y: Option<FqSerializable> = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        ECPointField::X => {
                            if x.is_some() {
                                return Err(de::Error::duplicate_field("x"));
                            }
                            x = Some(map.next_value()?);
                        }
                        ECPointField::Y => {
                            if y.is_some() {
                                return Err(de::Error::duplicate_field("y"));
                            }
                            y = Some(map.next_value()?);
                        }
                    }
                }
                let x: Fq = x.ok_or_else(|| de::Error::missing_field("x"))?.into();
                let y: Fq = y.ok_or_else(|| de::Error::missing_field("y"))?.into();
                Ok(G1AffineSerializable(G1Affine::new(
                    x.into(),
                    y.into(),
                    false,
                )))
            }
        }

        const FIELDS: &'static [&'static str] = &["x", "y"];
        deserializer.deserialize_struct("G1AffineSerializable", FIELDS, G1AffineVisitor)
    }
}

impl<'de> Deserialize<'de> for G2AffineSerializable {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct G2AffineVisitor;

        impl<'de> Visitor<'de> for G2AffineVisitor {
            type Value = G2AffineSerializable;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct G2AffineSerializable")
            }

            fn visit_map<V>(self, mut map: V) -> Result<G2AffineSerializable, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut x: Option<Fq2Serializable> = None;
                let mut y: Option<Fq2Serializable> = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        ECPointField::X => {
                            if x.is_some() {
                                return Err(de::Error::duplicate_field("x"));
                            }
                            x = Some(map.next_value()?);
                        }
                        ECPointField::Y => {
                            if y.is_some() {
                                return Err(de::Error::duplicate_field("y"));
                            }
                            y = Some(map.next_value()?);
                        }
                    }
                }
                let x: Fq2 = x.ok_or_else(|| de::Error::missing_field("x"))?.into();
                let y: Fq2 = y.ok_or_else(|| de::Error::missing_field("y"))?.into();
                Ok(G2AffineSerializable(G2Affine::new(
                    x.into(),
                    y.into(),
                    false,
                )))
            }
        }

        const FIELDS: &'static [&'static str] = &["x", "y"];
        deserializer.deserialize_struct("G2AffineSerializable", FIELDS, G2AffineVisitor)
    }
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "lowercase")]
#[allow(non_camel_case_types)]
enum PVSSCiphertextField {
    F_i,
    A_i,
    Y_i,
}

impl<'de> Deserialize<'de> for PVSSCiphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PVSSCiphertextVisitor;

        impl<'de> Visitor<'de> for PVSSCiphertextVisitor {
            type Value = PVSSCiphertext;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct PVSSCiphertext")
            }

            fn visit_map<V>(self, mut map: V) -> Result<PVSSCiphertext, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut f_i: Option<Vec<G1AffineSerializable>> = None;
                let mut a_i: Option<Vec<G1AffineSerializable>> = None;
                let mut y_i: Option<Vec<G2AffineSerializable>> = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        PVSSCiphertextField::F_i => {
                            if f_i.is_some() {
                                return Err(de::Error::duplicate_field("f_i"));
                            }
                            f_i = Some(map.next_value()?);
                        }
                        PVSSCiphertextField::A_i => {
                            if a_i.is_some() {
                                return Err(de::Error::duplicate_field("A_i"));
                            }
                            a_i = Some(map.next_value()?);
                        }
                        PVSSCiphertextField::Y_i => {
                            if y_i.is_some() {
                                return Err(de::Error::duplicate_field("Y_i"));
                            }
                            y_i = Some(map.next_value()?);
                        }
                    }
                }
                let f_i = f_i
                    .ok_or_else(|| de::Error::missing_field("f_i"))?
                    .into_iter()
                    .map(|f| f.into())
                    .collect::<Vec<G1Affine>>();
                let a_i = a_i
                    .ok_or_else(|| de::Error::missing_field("a_i"))?
                    .into_iter()
                    .map(|a| a.into())
                    .collect::<Vec<G1Affine>>();
                let y_i = y_i
                    .ok_or_else(|| de::Error::missing_field("y_i"))?
                    .into_iter()
                    .map(|y| y.into())
                    .collect::<Vec<G2Affine>>();
                Ok(PVSSCiphertext { f_i, a_i, y_i })
            }
        }

        const FIELDS: &'static [&'static str] = &["f_i", "a_i", "y_i"];
        deserializer.deserialize_struct("PVSSCiphertext", FIELDS, PVSSCiphertextVisitor)
    }
}
