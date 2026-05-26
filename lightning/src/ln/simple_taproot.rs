// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-APACHE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Experimental simple-taproot channel wire primitives.
//!
//! These types intentionally cover only the fixed-width TLV payloads defined by
//! the draft simple-taproot BOLT. They provide native LDK serialization,
//! fixed-length validation, and public nonce parsing for the message-level
//! integration. They do not perform MuSig2 signing or partial-signature
//! verification.

use bitcoin::hash_types::Txid;
use bitcoin::secp256k1::PublicKey;

use crate::io::{self, Read};
use crate::ln::msgs::DecodeError;
use crate::prelude::*;
use crate::util::ser::{LengthLimitedRead, LengthReadable, Readable, Writeable, Writer};

/// TLV type for `partial_signature_with_nonce`.
pub const PARTIAL_SIGNATURE_WITH_NONCE_TLV_TYPE: u64 = 2;
/// TLV type for `next_local_nonce`.
pub const NEXT_LOCAL_NONCE_TLV_TYPE: u64 = 4;
/// TLV type for a standalone simple-taproot partial signature.
pub const PARTIAL_SIGNATURE_TLV_TYPE: u64 = 6;
/// TLV type for the cooperative-close shutdown nonce.
pub const SHUTDOWN_NONCE_TLV_TYPE: u64 = 8;
/// TLV type for a set of per-funding-transaction next local nonces.
pub const NEXT_LOCAL_NONCES_TLV_TYPE: u64 = 22;

/// Simple-taproot `closing_complete`/`closing_sig` TLV for the closer-only output signature.
pub const CLOSING_CLOSER_OUTPUT_ONLY_TLV_TYPE: u64 = 5;
/// Simple-taproot `closing_complete`/`closing_sig` TLV for the closee-only output signature.
pub const CLOSING_CLOSEE_OUTPUT_ONLY_TLV_TYPE: u64 = 6;
/// Simple-taproot `closing_complete`/`closing_sig` TLV for the combined-output signature.
pub const CLOSING_CLOSER_AND_CLOSEE_OUTPUTS_TLV_TYPE: u64 = 7;

/// Byte length of a BIP-327 MuSig2 public nonce.
pub const MUSIG2_PUBLIC_NONCE_LEN: usize = 66;
/// Byte length of a BIP-327 MuSig2 partial signature scalar.
pub const MUSIG2_PARTIAL_SIGNATURE_LEN: usize = 32;
/// Byte length of `partial_signature || public_nonce`.
pub const MUSIG2_PARTIAL_SIGNATURE_WITH_NONCE_LEN: usize =
	MUSIG2_PARTIAL_SIGNATURE_LEN + MUSIG2_PUBLIC_NONCE_LEN;

/// A BIP-327 MuSig2 public nonce encoded as two compressed secp256k1 points.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Musig2PublicNonce([u8; MUSIG2_PUBLIC_NONCE_LEN]);

impl Musig2PublicNonce {
	/// Builds a nonce after validating both compressed public-key points.
	pub fn from_bytes(bytes: [u8; MUSIG2_PUBLIC_NONCE_LEN]) -> Result<Self, DecodeError> {
		validate_compressed_point(&bytes[..33])?;
		validate_compressed_point(&bytes[33..])?;
		Ok(Self(bytes))
	}

	/// Builds a nonce from a byte slice.
	pub fn from_slice(bytes: &[u8]) -> Result<Self, DecodeError> {
		if bytes.len() != MUSIG2_PUBLIC_NONCE_LEN {
			return Err(DecodeError::InvalidValue);
		}
		let mut nonce = [0; MUSIG2_PUBLIC_NONCE_LEN];
		nonce.copy_from_slice(bytes);
		Self::from_bytes(nonce)
	}

	/// Returns the fixed-width wire bytes.
	pub fn as_bytes(&self) -> &[u8; MUSIG2_PUBLIC_NONCE_LEN] {
		&self.0
	}
}

impl Writeable for Musig2PublicNonce {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.write_all(&self.0)
	}
}

impl Readable for Musig2PublicNonce {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let mut bytes = [0; MUSIG2_PUBLIC_NONCE_LEN];
		reader.read_exact(&mut bytes)?;
		Self::from_bytes(bytes)
	}
}

/// A MuSig2 partial signature scalar.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct SimpleTaprootPartialSignature([u8; MUSIG2_PARTIAL_SIGNATURE_LEN]);

impl SimpleTaprootPartialSignature {
	/// Builds a fixed-width partial signature scalar.
	pub fn from_bytes(bytes: [u8; MUSIG2_PARTIAL_SIGNATURE_LEN]) -> Self {
		Self(bytes)
	}

	/// Builds a fixed-width partial signature scalar from a byte slice.
	pub fn from_slice(bytes: &[u8]) -> Result<Self, DecodeError> {
		if bytes.len() != MUSIG2_PARTIAL_SIGNATURE_LEN {
			return Err(DecodeError::InvalidValue);
		}
		let mut partial_signature = [0; MUSIG2_PARTIAL_SIGNATURE_LEN];
		partial_signature.copy_from_slice(bytes);
		Ok(Self(partial_signature))
	}

	/// Returns the fixed-width wire bytes.
	pub fn as_bytes(&self) -> &[u8; MUSIG2_PARTIAL_SIGNATURE_LEN] {
		&self.0
	}
}

impl Writeable for SimpleTaprootPartialSignature {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.write_all(&self.0)
	}
}

impl Readable for SimpleTaprootPartialSignature {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let mut bytes = [0; MUSIG2_PARTIAL_SIGNATURE_LEN];
		reader.read_exact(&mut bytes)?;
		Ok(Self(bytes))
	}
}

/// A MuSig2 partial signature paired with the public nonce used to produce it.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct SimpleTaprootPartialSignatureWithNonce {
	/// The 32-byte MuSig2 partial signature scalar.
	pub partial_signature: SimpleTaprootPartialSignature,
	/// The 66-byte public nonce used for this partial signature.
	pub public_nonce: Musig2PublicNonce,
}

impl SimpleTaprootPartialSignatureWithNonce {
	/// Builds the fixed-width `partial_signature || public_nonce` payload.
	pub fn new(
		partial_signature: SimpleTaprootPartialSignature, public_nonce: Musig2PublicNonce,
	) -> Self {
		Self { partial_signature, public_nonce }
	}

	/// Builds the payload from its fixed-width wire bytes.
	pub fn from_slice(bytes: &[u8]) -> Result<Self, DecodeError> {
		if bytes.len() != MUSIG2_PARTIAL_SIGNATURE_WITH_NONCE_LEN {
			return Err(DecodeError::InvalidValue);
		}
		let partial_signature =
			SimpleTaprootPartialSignature::from_slice(&bytes[..MUSIG2_PARTIAL_SIGNATURE_LEN])?;
		let public_nonce = Musig2PublicNonce::from_slice(&bytes[MUSIG2_PARTIAL_SIGNATURE_LEN..])?;
		Ok(Self { partial_signature, public_nonce })
	}
}

impl Writeable for SimpleTaprootPartialSignatureWithNonce {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.partial_signature.write(writer)?;
		self.public_nonce.write(writer)
	}
}

impl Readable for SimpleTaprootPartialSignatureWithNonce {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let partial_signature = Readable::read(reader)?;
		let public_nonce = Readable::read(reader)?;
		Ok(Self { partial_signature, public_nonce })
	}
}

/// A `next_local_nonces` entry keyed by funding transaction ID.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct SimpleTaprootNonceEntry {
	/// Funding transaction ID for the commitment transaction using this nonce.
	pub funding_txid: Txid,
	/// Public nonce for that funding transaction's next local commitment.
	pub public_nonce: Musig2PublicNonce,
}

impl Writeable for SimpleTaprootNonceEntry {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.funding_txid.write(writer)?;
		self.public_nonce.write(writer)
	}
}

impl Readable for SimpleTaprootNonceEntry {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Ok(Self { funding_txid: Readable::read(reader)?, public_nonce: Readable::read(reader)? })
	}
}

/// The `next_local_nonces` TLV payload.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct SimpleTaprootNextLocalNonces(pub Vec<SimpleTaprootNonceEntry>);

impl Writeable for SimpleTaprootNextLocalNonces {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		for entry in self.0.iter() {
			entry.write(writer)?;
		}
		Ok(())
	}
}

impl LengthReadable for SimpleTaprootNextLocalNonces {
	fn read_from_fixed_length_buffer<R: LengthLimitedRead>(
		reader: &mut R,
	) -> Result<Self, DecodeError> {
		let mut entries = Vec::new();
		while reader.remaining_bytes() > 0 {
			entries.push(Readable::read(reader)?);
		}
		Ok(Self(entries))
	}
}

/// Requires a simple-taproot nonce TLV after the caller has established that
/// the message belongs to a simple-taproot channel.
pub fn require_public_nonce(
	nonce: Option<&Musig2PublicNonce>,
) -> Result<&Musig2PublicNonce, DecodeError> {
	nonce.ok_or(DecodeError::InvalidValue)
}

/// Requires a simple-taproot partial-signature-with-nonce TLV after the caller
/// has established that the message belongs to a simple-taproot channel.
pub fn require_partial_signature_with_nonce(
	partial_signature_with_nonce: Option<&SimpleTaprootPartialSignatureWithNonce>,
) -> Result<&SimpleTaprootPartialSignatureWithNonce, DecodeError> {
	partial_signature_with_nonce.ok_or(DecodeError::InvalidValue)
}

/// Requires a simple-taproot partial-signature TLV after the caller has
/// established that the message belongs to a simple-taproot channel.
pub fn require_partial_signature(
	partial_signature: Option<&SimpleTaprootPartialSignature>,
) -> Result<&SimpleTaprootPartialSignature, DecodeError> {
	partial_signature.ok_or(DecodeError::InvalidValue)
}

/// Requires at least one simple-taproot next-local-nonce entry after the caller
/// has established that the message belongs to a simple-taproot channel.
pub fn require_next_local_nonces(
	next_local_nonces: Option<&SimpleTaprootNextLocalNonces>,
) -> Result<&SimpleTaprootNextLocalNonces, DecodeError> {
	match next_local_nonces {
		Some(nonces) if !nonces.0.is_empty() => Ok(nonces),
		_ => Err(DecodeError::InvalidValue),
	}
}

fn validate_compressed_point(bytes: &[u8]) -> Result<(), DecodeError> {
	PublicKey::from_slice(bytes).map(|_| ()).map_err(|_| DecodeError::InvalidValue)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::util::ser::{Readable, Writeable};
	use bitcoin::hashes::Hash as _;

	fn sample_nonce(seed: u8) -> Musig2PublicNonce {
		let mut bytes = [0; MUSIG2_PUBLIC_NONCE_LEN];
		bytes[..33].copy_from_slice(&[
			2, 121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155,
			252, 219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152,
		]);
		bytes[33..].copy_from_slice(&[
			3, 121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155,
			252, 219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152,
		]);
		bytes[32] ^= seed;
		bytes[65] ^= seed;
		Musig2PublicNonce::from_bytes(bytes).unwrap()
	}

	#[test]
	fn rejects_malformed_public_nonce_points() {
		assert_eq!(
			Musig2PublicNonce::from_bytes([0; MUSIG2_PUBLIC_NONCE_LEN]).unwrap_err(),
			DecodeError::InvalidValue
		);
	}

	#[test]
	fn partial_signature_with_nonce_round_trips() {
		let payload = SimpleTaprootPartialSignatureWithNonce::new(
			SimpleTaprootPartialSignature::from_bytes([42; MUSIG2_PARTIAL_SIGNATURE_LEN]),
			sample_nonce(0),
		);
		let mut encoded = Vec::new();
		payload.write(&mut encoded).unwrap();
		assert_eq!(encoded.len(), MUSIG2_PARTIAL_SIGNATURE_WITH_NONCE_LEN);
		let decoded = SimpleTaprootPartialSignatureWithNonce::read(&mut &encoded[..]).unwrap();
		assert_eq!(decoded, payload);
	}

	#[test]
	fn nonce_entry_round_trips() {
		let entry = SimpleTaprootNonceEntry {
			funding_txid: Txid::from_slice(&[3; 32]).unwrap(),
			public_nonce: sample_nonce(1),
		};
		let mut encoded = Vec::new();
		entry.write(&mut encoded).unwrap();
		let decoded = SimpleTaprootNonceEntry::read(&mut &encoded[..]).unwrap();
		assert_eq!(decoded, entry);
	}

	#[test]
	fn next_local_nonces_round_trip_without_collection_length() {
		let entries = SimpleTaprootNextLocalNonces(vec![
			SimpleTaprootNonceEntry {
				funding_txid: Txid::from_slice(&[3; 32]).unwrap(),
				public_nonce: sample_nonce(1),
			},
			SimpleTaprootNonceEntry {
				funding_txid: Txid::from_slice(&[4; 32]).unwrap(),
				public_nonce: sample_nonce(2),
			},
		]);
		let mut encoded = Vec::new();
		entries.write(&mut encoded).unwrap();
		assert_eq!(encoded.len(), 2 * (32 + MUSIG2_PUBLIC_NONCE_LEN));
		let mut reader = &encoded[..];
		let decoded =
			SimpleTaprootNextLocalNonces::read_from_fixed_length_buffer(&mut reader).unwrap();
		assert_eq!(decoded, entries);
	}
}
