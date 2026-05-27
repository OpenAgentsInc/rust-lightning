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
//! fixed-length validation, and public nonce parsing. When the
//! `simple_taproot_musig2` feature is enabled, this module also exposes the
//! first native MuSig2 signing/session primitives needed by simple-taproot
//! channel integration.

use bitcoin::hash_types::Txid;
#[cfg(feature = "simple_taproot_musig2")]
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
#[cfg(feature = "simple_taproot_musig2")]
use bitcoin::hashes::ripemd160::Hash as Ripemd160;
#[cfg(feature = "simple_taproot_musig2")]
use bitcoin::hashes::sha256::Hash as Sha256;
#[cfg(feature = "simple_taproot_musig2")]
use bitcoin::hashes::{Hash, HashEngine};
#[cfg(feature = "simple_taproot_musig2")]
use bitcoin::opcodes;
#[cfg(feature = "simple_taproot_musig2")]
use bitcoin::script::{Builder, Script, ScriptBuf};
use bitcoin::secp256k1::PublicKey;
#[cfg(feature = "simple_taproot_musig2")]
use bitcoin::secp256k1::{
	schnorr, Keypair, Message, Secp256k1, SecretKey, Signing, Verification, XOnlyPublicKey,
};
#[cfg(feature = "simple_taproot_musig2")]
use bitcoin::sighash::{self, SighashCache, TapSighashType};
#[cfg(feature = "simple_taproot_musig2")]
use bitcoin::taproot::{
	LeafVersion, Signature as TaprootSignature, TapLeafHash, TapNodeHash, TaprootBuilder,
	TaprootSpendInfo,
};
#[cfg(feature = "simple_taproot_musig2")]
use bitcoin::{Amount, Transaction, TxOut, Witness};

use crate::io::{self, Read};
use crate::ln::msgs::DecodeError;
use crate::prelude::*;
#[cfg(feature = "simple_taproot_musig2")]
use crate::types::payment::PaymentHash;
use crate::util::ser::{
	CollectionLength, LengthLimitedRead, LengthReadable, Readable, Writeable, Writer,
};

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
/// Byte length of a BIP-327 MuSig2 secret nonce.
pub const MUSIG2_SECRET_NONCE_LEN: usize = 97;
/// Byte length of `partial_signature || public_nonce`.
pub const MUSIG2_PARTIAL_SIGNATURE_WITH_NONCE_LEN: usize =
	MUSIG2_PARTIAL_SIGNATURE_LEN + MUSIG2_PUBLIC_NONCE_LEN;
/// Domain-separated message used only for deterministic nonce pre-generation.
///
/// Simple-taproot commitment nonces are advertised before the commitment
/// transaction message is known. The actual partial signature still signs the
/// commitment transaction sighash; this value only keeps pre-generated counter
/// nonces stable between announcement and signing.
pub const SIMPLE_TAPROOT_COMMITMENT_NONCE_PREIMAGE: &[u8] =
	b"ldk-simple-taproot-commitment-nonce-v1";
/// Domain-separated message for deterministic nonces used when signing the
/// counterparty's commitment transaction.
pub const SIMPLE_TAPROOT_COUNTERPARTY_COMMITMENT_NONCE_PREIMAGE: &[u8] =
	b"ldk-simple-taproot-counterparty-commitment-nonce-v1";
/// Domain-separated message for deterministic closee nonces advertised in
/// simple-taproot `shutdown` and `closing_sig` messages.
pub const SIMPLE_TAPROOT_COOPERATIVE_CLOSE_NONCE_PREIMAGE: &[u8] =
	b"ldk-simple-taproot-cooperative-close-nonce-v1";
/// BOLT simple-taproot NUMS point used for script-only commitment outputs.
#[cfg(feature = "simple_taproot_musig2")]
pub const SIMPLE_TAPROOT_NUMS_POINT_BYTES: [u8; 33] = [
	0x02, 0xdc, 0xa0, 0x94, 0x75, 0x11, 0x09, 0xd0, 0xbd, 0x05, 0x5d, 0x03, 0x56, 0x58, 0x74, 0xe8,
	0x27, 0x6d, 0xd5, 0x3e, 0x92, 0x6b, 0x44, 0xe3, 0xbd, 0x1b, 0xb6, 0xbf, 0x4b, 0xc1, 0x30, 0xa2,
	0x79,
];

/// Errors surfaced by the simple-taproot MuSig2 session helpers.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum SimpleTaprootMusigError {
	/// A funding, aggregate, or secret key could not be parsed or used.
	InvalidKey,
	/// A public, aggregate, or secret nonce could not be parsed or used.
	InvalidNonce,
	/// A partial or final Schnorr signature failed parsing or verification.
	InvalidSignature,
	/// The signing state already consumed this nonce use.
	DuplicateNonceUse,
	/// A signer set was empty where at least one key was required.
	EmptySignerSet,
}

/// Spend data for one script leaf in a simple-taproot output.
#[cfg(feature = "simple_taproot_musig2")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimpleTaprootLeafSpendInfo {
	/// The tapscript leaf.
	pub script: ScriptBuf,
	/// The control block needed to spend through this leaf.
	pub control_block: Vec<u8>,
}

/// Spend data for a simple-taproot `to_local` output.
#[cfg(feature = "simple_taproot_musig2")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimpleTaprootToLocalSpendInfo {
	/// The P2TR commitment output script.
	pub script_pubkey: ScriptBuf,
	/// The tapscript root committed to by the output key.
	pub tapscript_root: [u8; 32],
	/// The BIP341 tap tweak committed to by the output key.
	pub tap_tweak: [u8; 32],
	/// The routine delayed spend path.
	pub delay: SimpleTaprootLeafSpendInfo,
	/// The breach revocation spend path.
	pub revocation: SimpleTaprootLeafSpendInfo,
}

/// Spend data for a single-leaf simple-taproot output.
#[cfg(feature = "simple_taproot_musig2")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimpleTaprootSingleLeafSpendInfo {
	/// The P2TR commitment output script.
	pub script_pubkey: ScriptBuf,
	/// The tapscript root committed to by the output key.
	pub tapscript_root: [u8; 32],
	/// The BIP341 tap tweak committed to by the output key.
	pub tap_tweak: [u8; 32],
	/// The only script spend path for this output.
	pub spend: SimpleTaprootLeafSpendInfo,
}

/// Spend data for a simple-taproot HTLC output.
#[cfg(feature = "simple_taproot_musig2")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimpleTaprootHtlcSpendInfo {
	/// The P2TR commitment output script.
	pub script_pubkey: ScriptBuf,
	/// The tapscript root committed to by the output key.
	pub tapscript_root: [u8; 32],
	/// The BIP341 tap tweak committed to by the output key.
	pub tap_tweak: [u8; 32],
	/// The timeout spend path.
	pub timeout: SimpleTaprootLeafSpendInfo,
	/// The success spend path.
	pub success: SimpleTaprootLeafSpendInfo,
}

/// Selects the HTLC script variant used for a simple-taproot channel.
#[cfg(feature = "simple_taproot_musig2")]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SimpleTaprootHtlcScriptVariant {
	/// The staging script variant used by the current draft deployment and
	/// Lightning Labs' `taproot-overlay-chans` implementation.
	Staging,
	/// The final script variant using the assigned simple-taproot feature bits.
	Final,
}

/// A fully specified tapscript spend for a simple-taproot second-level HTLC transaction.
#[cfg(feature = "simple_taproot_musig2")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimpleTaprootHtlcSpendPath {
	/// Offered HTLC timeout path: local HTLC signature, then remote HTLC signature.
	OfferedTimeout,
	/// Offered HTLC success path: remote HTLC signature and payment preimage.
	OfferedSuccess,
	/// Accepted HTLC timeout path: local HTLC signature.
	AcceptedTimeout,
	/// Accepted HTLC success path: remote HTLC signature, local HTLC signature, and payment preimage.
	AcceptedSuccess,
}

/// A fully specified tapscript spend for a simple-taproot second-level HTLC transaction.
#[cfg(feature = "simple_taproot_musig2")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimpleTaprootSignedHtlcSpend {
	/// The BIP341/BIP342 sighash covered by the HTLC signatures.
	pub sighash: [u8; 32],
	/// The local HTLC signature, when the selected spend path requires it.
	pub local_signature: Option<TaprootSignature>,
	/// The remote HTLC signature, when the selected spend path requires it.
	pub remote_signature: Option<TaprootSignature>,
	/// The complete witness stack for the HTLC transaction input.
	pub witness: Witness,
}

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

	/// Builds a public nonce from two public nonce points.
	pub fn from_points(first: &PublicKey, second: &PublicKey) -> Self {
		let mut bytes = [0; MUSIG2_PUBLIC_NONCE_LEN];
		bytes[..33].copy_from_slice(&first.serialize());
		bytes[33..].copy_from_slice(&second.serialize());
		Self(bytes)
	}

	/// Returns the two public nonce points.
	pub fn points(&self) -> Result<(PublicKey, PublicKey), SimpleTaprootMusigError> {
		Ok((
			PublicKey::from_slice(&self.0[..33])
				.map_err(|_| SimpleTaprootMusigError::InvalidNonce)?,
			PublicKey::from_slice(&self.0[33..])
				.map_err(|_| SimpleTaprootMusigError::InvalidNonce)?,
		))
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

/// A retransmittable simple-taproot commitment partial signature.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct SimpleTaprootSentCommitmentSignature {
	/// Funding transaction ID for the signed commitment transaction.
	pub funding_txid: Txid,
	/// Commitment nonce index used for the signature.
	pub nonce_index: u64,
	/// The partial signature and public nonce that were sent.
	pub partial_signature_with_nonce: SimpleTaprootPartialSignatureWithNonce,
}

/// The output set signed by a simple-taproot cooperative-close partial
/// signature.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum SimpleTaprootClosingOutputSet {
	/// The closing transaction contains only the closer's output.
	CloserOutputOnly,
	/// The closing transaction contains only the closee's output.
	CloseeOutputOnly,
	/// The closing transaction contains both closer and closee outputs.
	CloserAndCloseeOutputs,
}

impl SimpleTaprootClosingOutputSet {
	/// Returns the nonce scope used for the closer-side JIT nonce for this
	/// output set.
	pub fn closer_nonce_scope(self) -> SimpleTaprootNonceScope {
		match self {
			Self::CloserOutputOnly => SimpleTaprootNonceScope::CooperativeCloseCloserOutputOnly,
			Self::CloseeOutputOnly => SimpleTaprootNonceScope::CooperativeCloseCloseeOutputOnly,
			Self::CloserAndCloseeOutputs => {
				SimpleTaprootNonceScope::CooperativeCloseCloserAndCloseeOutputs
			},
		}
	}

	fn wire_value(self) -> u8 {
		match self {
			Self::CloserOutputOnly => 0,
			Self::CloseeOutputOnly => 1,
			Self::CloserAndCloseeOutputs => 2,
		}
	}

	fn from_wire_value(value: u8) -> Result<Self, DecodeError> {
		match value {
			0 => Ok(Self::CloserOutputOnly),
			1 => Ok(Self::CloseeOutputOnly),
			2 => Ok(Self::CloserAndCloseeOutputs),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

impl Writeable for SimpleTaprootClosingOutputSet {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.wire_value().write(writer)
	}
}

impl Readable for SimpleTaprootClosingOutputSet {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Self::from_wire_value(Readable::read(reader)?)
	}
}

/// Restart-persisted counterparty closee nonce state for simple-taproot
/// cooperative closes.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct SimpleTaprootCloseeNonceState {
	/// The locally assigned close attempt index for this peer nonce.
	pub nonce_index: u64,
	/// The peer's closee public nonce for that attempt.
	pub public_nonce: Musig2PublicNonce,
}

impl Writeable for SimpleTaprootCloseeNonceState {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.nonce_index.write(writer)?;
		self.public_nonce.write(writer)
	}
}

impl Readable for SimpleTaprootCloseeNonceState {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Ok(Self { nonce_index: Readable::read(reader)?, public_nonce: Readable::read(reader)? })
	}
}

/// Restart-persisted simple-taproot `closing_complete` data needed to validate
/// a returned `closing_sig` without reusing a MuSig2 nonce.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct SimpleTaprootSentClosingComplete {
	/// Funding transaction ID for the cooperative-close transaction.
	pub funding_txid: Txid,
	/// Close attempt index used for both closer and closee nonces.
	pub nonce_index: u64,
	/// Output set signed in this close attempt.
	pub output_set: SimpleTaprootClosingOutputSet,
	/// Proposed total fee in satoshis.
	pub fee_satoshis: u64,
	/// Closing transaction locktime.
	pub locktime: u32,
	/// The partial signature and public nonce that were sent.
	pub partial_signature_with_nonce: SimpleTaprootPartialSignatureWithNonce,
}

impl Writeable for SimpleTaprootSentClosingComplete {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.funding_txid.write(writer)?;
		self.nonce_index.write(writer)?;
		self.output_set.write(writer)?;
		self.fee_satoshis.write(writer)?;
		self.locktime.write(writer)?;
		self.partial_signature_with_nonce.write(writer)
	}
}

impl Readable for SimpleTaprootSentClosingComplete {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Ok(Self {
			funding_txid: Readable::read(reader)?,
			nonce_index: Readable::read(reader)?,
			output_set: Readable::read(reader)?,
			fee_satoshis: Readable::read(reader)?,
			locktime: Readable::read(reader)?,
			partial_signature_with_nonce: Readable::read(reader)?,
		})
	}
}

impl Writeable for SimpleTaprootSentCommitmentSignature {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.funding_txid.write(writer)?;
		self.nonce_index.write(writer)?;
		self.partial_signature_with_nonce.write(writer)
	}
}

impl Readable for SimpleTaprootSentCommitmentSignature {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Ok(Self {
			funding_txid: Readable::read(reader)?,
			nonce_index: Readable::read(reader)?,
			partial_signature_with_nonce: Readable::read(reader)?,
		})
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

/// Restart-persisted per-funding simple-taproot public nonce entries.
#[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct SimpleTaprootNonceEntries(pub Vec<SimpleTaprootNonceEntry>);

impl SimpleTaprootNonceEntries {
	/// Returns the nonce for a funding transaction, if one is known.
	pub fn get(&self, funding_txid: Txid) -> Option<Musig2PublicNonce> {
		self.0
			.iter()
			.find(|entry| entry.funding_txid == funding_txid)
			.map(|entry| entry.public_nonce)
	}

	/// Inserts or replaces a funding transaction's advertised public nonce.
	pub fn upsert(&mut self, entry: SimpleTaprootNonceEntry) {
		if let Some(existing) =
			self.0.iter_mut().find(|existing| existing.funding_txid == entry.funding_txid)
		{
			*existing = entry;
		} else {
			self.0.push(entry);
		}
	}

	/// Returns true when no nonces are stored.
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}
}

impl Writeable for SimpleTaprootNonceEntries {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		CollectionLength(self.0.len() as u64).write(writer)?;
		for entry in self.0.iter() {
			entry.write(writer)?;
		}
		Ok(())
	}
}

impl Readable for SimpleTaprootNonceEntries {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let len: CollectionLength = Readable::read(reader)?;
		let mut entries = Vec::new();
		for _ in 0..len.0 {
			entries.push(Readable::read(reader)?);
		}
		Ok(Self(entries))
	}
}

/// Restart-persisted simple-taproot commitment signatures available for retransmission.
#[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct SimpleTaprootSentCommitmentSignatures(pub Vec<SimpleTaprootSentCommitmentSignature>);

impl SimpleTaprootSentCommitmentSignatures {
	/// Returns a previously sent partial signature for a funding txid and nonce index.
	pub fn get(
		&self, funding_txid: Txid, nonce_index: u64,
	) -> Option<SimpleTaprootPartialSignatureWithNonce> {
		self.0
			.iter()
			.find(|entry| entry.funding_txid == funding_txid && entry.nonce_index == nonce_index)
			.map(|entry| entry.partial_signature_with_nonce)
	}

	/// Inserts or replaces a sent partial signature.
	pub fn upsert(&mut self, entry: SimpleTaprootSentCommitmentSignature) {
		if let Some(existing) = self.0.iter_mut().find(|existing| {
			existing.funding_txid == entry.funding_txid && existing.nonce_index == entry.nonce_index
		}) {
			*existing = entry;
		} else {
			self.0.push(entry);
		}
	}

	/// Returns true when no signatures are stored.
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}
}

impl Writeable for SimpleTaprootSentCommitmentSignatures {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		CollectionLength(self.0.len() as u64).write(writer)?;
		for entry in self.0.iter() {
			entry.write(writer)?;
		}
		Ok(())
	}
}

impl Readable for SimpleTaprootSentCommitmentSignatures {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let len: CollectionLength = Readable::read(reader)?;
		let mut entries = Vec::new();
		for _ in 0..len.0 {
			entries.push(Readable::read(reader)?);
		}
		Ok(Self(entries))
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

/// The simple-taproot signing path that a MuSig2 nonce is assigned to.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum SimpleTaprootNonceScope {
	/// A commitment transaction signature nonce.
	Commitment,
	/// A nonce consumed while signing a counterparty commitment transaction.
	CounterpartyCommitment,
	/// Legacy cooperative-close nonce domain retained for old persisted data.
	CooperativeClose,
	/// A force-close signature nonce.
	ForceClose,
	/// A closee nonce advertised before the exact close transaction is known.
	CooperativeCloseClosee,
	/// A closer nonce signing a transaction with only the closer output.
	CooperativeCloseCloserOutputOnly,
	/// A closer nonce signing a transaction with only the closee output.
	CooperativeCloseCloseeOutputOnly,
	/// A closer nonce signing a transaction with both closer and closee outputs.
	CooperativeCloseCloserAndCloseeOutputs,
}

impl SimpleTaprootNonceScope {
	fn wire_value(self) -> u8 {
		match self {
			Self::Commitment => 0,
			Self::CounterpartyCommitment => 1,
			Self::CooperativeClose => 2,
			Self::ForceClose => 3,
			Self::CooperativeCloseClosee => 4,
			Self::CooperativeCloseCloserOutputOnly => 5,
			Self::CooperativeCloseCloseeOutputOnly => 6,
			Self::CooperativeCloseCloserAndCloseeOutputs => 7,
		}
	}

	fn from_wire_value(value: u8) -> Result<Self, DecodeError> {
		match value {
			0 => Ok(Self::Commitment),
			1 => Ok(Self::CounterpartyCommitment),
			2 => Ok(Self::CooperativeClose),
			3 => Ok(Self::ForceClose),
			4 => Ok(Self::CooperativeCloseClosee),
			5 => Ok(Self::CooperativeCloseCloserOutputOnly),
			6 => Ok(Self::CooperativeCloseCloseeOutputOnly),
			7 => Ok(Self::CooperativeCloseCloserAndCloseeOutputs),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

impl Writeable for SimpleTaprootNonceScope {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.wire_value().write(writer)
	}
}

impl Readable for SimpleTaprootNonceScope {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Self::from_wire_value(Readable::read(reader)?)
	}
}

/// A unique MuSig2 nonce use within a simple-taproot channel.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct SimpleTaprootNonceUse {
	/// Funding transaction ID for the channel or splice being signed.
	pub funding_txid: Txid,
	/// Commitment or close nonce index.
	pub nonce_index: u64,
	/// Signing path using this nonce.
	pub scope: SimpleTaprootNonceScope,
}

impl SimpleTaprootNonceUse {
	/// Builds a nonce-use key.
	pub fn new(funding_txid: Txid, nonce_index: u64, scope: SimpleTaprootNonceScope) -> Self {
		Self { funding_txid, nonce_index, scope }
	}

	#[cfg(feature = "simple_taproot_musig2")]
	fn extra_input(&self) -> [u8; 41] {
		let mut extra_input = [0; 41];
		extra_input[..32].copy_from_slice(self.funding_txid.as_byte_array());
		extra_input[32..40].copy_from_slice(&self.nonce_index.to_be_bytes());
		extra_input[40] = self.scope.wire_value();
		extra_input
	}
}

impl Writeable for SimpleTaprootNonceUse {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.funding_txid.write(writer)?;
		self.nonce_index.write(writer)?;
		self.scope.write(writer)
	}
}

impl Readable for SimpleTaprootNonceUse {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Ok(Self {
			funding_txid: Readable::read(reader)?,
			nonce_index: Readable::read(reader)?,
			scope: Readable::read(reader)?,
		})
	}
}

/// Restart-persistable record of MuSig2 nonces already consumed for signing.
#[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct SimpleTaprootNonceState {
	used_nonces: Vec<SimpleTaprootNonceUse>,
}

impl SimpleTaprootNonceState {
	/// Builds an empty nonce-use state.
	pub fn new() -> Self {
		Self { used_nonces: Vec::new() }
	}

	/// Returns the nonce-use records already consumed for signing.
	pub fn used_nonces(&self) -> &[SimpleTaprootNonceUse] {
		&self.used_nonces
	}

	/// Returns true if this nonce use has already been consumed.
	pub fn is_used(&self, nonce_use: &SimpleTaprootNonceUse) -> bool {
		self.used_nonces.iter().any(|used| used == nonce_use)
	}

	/// Marks a nonce use as consumed, rejecting duplicate use.
	pub fn mark_used(
		&mut self, nonce_use: SimpleTaprootNonceUse,
	) -> Result<(), SimpleTaprootMusigError> {
		if self.is_used(&nonce_use) {
			return Err(SimpleTaprootMusigError::DuplicateNonceUse);
		}
		self.used_nonces.push(nonce_use);
		Ok(())
	}
}

impl Writeable for SimpleTaprootNonceState {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		CollectionLength(self.used_nonces.len() as u64).write(writer)?;
		for nonce_use in self.used_nonces.iter() {
			nonce_use.write(writer)?;
		}
		Ok(())
	}
}

impl Readable for SimpleTaprootNonceState {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let len: CollectionLength = Readable::read(reader)?;
		let mut used_nonces = Vec::new();
		for _ in 0..len.0 {
			used_nonces.push(Readable::read(reader)?);
		}
		Ok(Self { used_nonces })
	}
}

/// A BIP-327 MuSig2 secret nonce.
#[cfg(feature = "simple_taproot_musig2")]
#[derive(Clone, PartialEq, Eq)]
pub struct SimpleTaprootSecretNonce([u8; MUSIG2_SECRET_NONCE_LEN]);

#[cfg(feature = "simple_taproot_musig2")]
impl core::fmt::Debug for SimpleTaprootSecretNonce {
	fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
		formatter.write_str("SimpleTaprootSecretNonce(<redacted>)")
	}
}

#[cfg(feature = "simple_taproot_musig2")]
impl SimpleTaprootSecretNonce {
	/// Builds a secret nonce after validating the BIP-327 encoding.
	pub fn from_bytes(
		bytes: [u8; MUSIG2_SECRET_NONCE_LEN],
	) -> Result<Self, SimpleTaprootMusigError> {
		musig2::SecNonce::from_bytes(&bytes).map_err(|_| SimpleTaprootMusigError::InvalidNonce)?;
		Ok(Self(bytes))
	}

	/// Returns the fixed-width secret nonce bytes.
	pub fn as_bytes(&self) -> &[u8; MUSIG2_SECRET_NONCE_LEN] {
		&self.0
	}

	/// Returns the public nonce corresponding to this secret nonce.
	pub fn public_nonce(&self) -> Result<Musig2PublicNonce, SimpleTaprootMusigError> {
		let secret_nonce = self.to_musig2()?;
		musig_public_nonce_to_wire(&secret_nonce.public_nonce())
	}

	fn from_musig2(secret_nonce: musig2::SecNonce) -> Self {
		Self(secret_nonce.serialize())
	}

	fn to_musig2(&self) -> Result<musig2::SecNonce, SimpleTaprootMusigError> {
		musig2::SecNonce::from_bytes(&self.0).map_err(|_| SimpleTaprootMusigError::InvalidNonce)
	}
}

/// A generated simple-taproot MuSig2 nonce pair.
#[cfg(feature = "simple_taproot_musig2")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimpleTaprootNoncePair {
	/// Secret nonce. This must be consumed at most once.
	pub secret_nonce: SimpleTaprootSecretNonce,
	/// Public nonce to share with the counterparty.
	pub public_nonce: Musig2PublicNonce,
}

/// A sorted MuSig2 key aggregation context for simple-taproot funding keys.
#[cfg(feature = "simple_taproot_musig2")]
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct SimpleTaprootKeyAggContext {
	sorted_pubkeys: Vec<PublicKey>,
}

#[cfg(feature = "simple_taproot_musig2")]
impl SimpleTaprootKeyAggContext {
	/// Builds a key aggregation context after BIP-327 key sorting.
	pub fn new(mut pubkeys: Vec<PublicKey>) -> Result<Self, SimpleTaprootMusigError> {
		if pubkeys.is_empty() {
			return Err(SimpleTaprootMusigError::EmptySignerSet);
		}
		pubkeys.sort_by(|a, b| a.serialize().cmp(&b.serialize()));
		Ok(Self { sorted_pubkeys: pubkeys })
	}

	/// Builds a two-party funding-key aggregation context.
	pub fn for_funding_keys(local: PublicKey, remote: PublicKey) -> Self {
		Self::new(vec![local, remote]).expect("two funding keys are never empty")
	}

	/// Returns the sorted funding keys used by this aggregation context.
	pub fn sorted_pubkeys(&self) -> &[PublicKey] {
		&self.sorted_pubkeys
	}

	/// Returns the aggregate x-only public key.
	pub fn aggregate_xonly_public_key(&self) -> Result<XOnlyPublicKey, SimpleTaprootMusigError> {
		let musig_ctx = self.musig_context()?;
		let aggregate: musig2::secp::Point = musig_ctx.aggregated_pubkey();
		XOnlyPublicKey::from_slice(&aggregate.serialize_xonly())
			.map_err(|_| SimpleTaprootMusigError::InvalidKey)
	}

	/// Returns the BIP86 funding scriptPubKey for the sorted aggregate funding key.
	///
	/// Simple-taproot funding has no script path at this stage, so the aggregate
	/// MuSig2 key is used as the Taproot internal key and tweaked with an empty
	/// merkle root.
	pub fn bip86_funding_script_pubkey<C: Verification>(
		&self, secp_ctx: &Secp256k1<C>,
	) -> Result<ScriptBuf, SimpleTaprootMusigError> {
		self.funding_script_pubkey(secp_ctx, None)
	}

	/// Returns the funding scriptPubKey for the sorted aggregate funding key.
	///
	/// Passing a tapscript root matches LND's taproot-overlay/Taproot Asset
	/// channel behavior, where the funding MuSig2 key commits to the asset
	/// tree via the BIP341 tap tweak. Passing `None` preserves the BIP86
	/// simple-taproot behavior with no script path.
	pub fn funding_script_pubkey<C: Verification>(
		&self, secp_ctx: &Secp256k1<C>, tapscript_root: Option<[u8; 32]>,
	) -> Result<ScriptBuf, SimpleTaprootMusigError> {
		let internal_key = self.aggregate_xonly_public_key()?;
		let merkle_root = tapscript_root.map(TapNodeHash::from_byte_array);
		Ok(ScriptBuf::new_p2tr(secp_ctx, internal_key, merkle_root))
	}

	/// Returns the aggregate x-only public key after the BIP86 taproot tweak.
	pub fn bip86_aggregate_xonly_public_key(
		&self,
	) -> Result<XOnlyPublicKey, SimpleTaprootMusigError> {
		self.tweaked_aggregate_xonly_public_key(None)
	}

	/// Returns the aggregate x-only public key after the selected taproot tweak.
	pub fn tweaked_aggregate_xonly_public_key(
		&self, tapscript_root: Option<[u8; 32]>,
	) -> Result<XOnlyPublicKey, SimpleTaprootMusigError> {
		let musig_ctx = self.taproot_musig_context(tapscript_root)?;
		let aggregate: musig2::secp::Point = musig_ctx.aggregated_pubkey();
		XOnlyPublicKey::from_slice(&aggregate.serialize_xonly())
			.map_err(|_| SimpleTaprootMusigError::InvalidKey)
	}

	/// Generates a BIP-327 secret/public nonce pair from caller-supplied entropy.
	pub fn generate_nonce_pair(
		&self, signer_secret_key: &SecretKey, nonce_seed: [u8; 32], message: &[u8],
		nonce_use: &SimpleTaprootNonceUse,
	) -> Result<SimpleTaprootNoncePair, SimpleTaprootMusigError> {
		self.generate_nonce_pair_with_tapscript_root(
			signer_secret_key,
			nonce_seed,
			message,
			nonce_use,
			None,
		)
	}

	/// Generates a BIP-327 secret/public nonce pair from caller-supplied entropy.
	pub fn generate_nonce_pair_with_tapscript_root(
		&self, signer_secret_key: &SecretKey, nonce_seed: [u8; 32], message: &[u8],
		nonce_use: &SimpleTaprootNonceUse, _tapscript_root: Option<[u8; 32]>,
	) -> Result<SimpleTaprootNoncePair, SimpleTaprootMusigError> {
		let signer_scalar = musig_scalar(signer_secret_key)?;
		let musig_ctx = self.musig_context()?;
		let aggregate: musig2::secp::Point = musig_ctx.aggregated_pubkey();
		let extra_input = nonce_use.extra_input();
		// The Taproot Asset tapscript root is learned after the initial
		// simple-taproot nonces are exchanged. Keep nonce derivation bound to
		// the untweaked key set so the nonce we verify later is the same nonce
		// we already sent, while signing and verification below still bind the
		// final partial signatures to the root-tweaked output key.
		let secret_nonce =
			musig2::SecNonce::generate(nonce_seed, signer_scalar, aggregate, message, extra_input);
		let public_nonce = musig_public_nonce_to_wire(&secret_nonce.public_nonce())?;
		Ok(SimpleTaprootNoncePair {
			secret_nonce: SimpleTaprootSecretNonce::from_musig2(secret_nonce),
			public_nonce,
		})
	}

	/// Signs a message with a fresh secret nonce and records the nonce as consumed.
	pub fn sign_partial(
		&self, signer_secret_key: &SecretKey, secret_nonce: SimpleTaprootSecretNonce,
		public_nonces: &[Musig2PublicNonce], message: &[u8], nonce_use: SimpleTaprootNonceUse,
		nonce_state: &mut SimpleTaprootNonceState,
	) -> Result<SimpleTaprootPartialSignatureWithNonce, SimpleTaprootMusigError> {
		self.sign_partial_with_tapscript_root(
			signer_secret_key,
			secret_nonce,
			public_nonces,
			message,
			nonce_use,
			nonce_state,
			None,
		)
	}

	/// Signs a message with a fresh secret nonce and records the nonce as consumed.
	pub fn sign_partial_with_tapscript_root(
		&self, signer_secret_key: &SecretKey, secret_nonce: SimpleTaprootSecretNonce,
		public_nonces: &[Musig2PublicNonce], message: &[u8], nonce_use: SimpleTaprootNonceUse,
		nonce_state: &mut SimpleTaprootNonceState, tapscript_root: Option<[u8; 32]>,
	) -> Result<SimpleTaprootPartialSignatureWithNonce, SimpleTaprootMusigError> {
		if nonce_state.is_used(&nonce_use) {
			return Err(SimpleTaprootMusigError::DuplicateNonceUse);
		}
		let secret_nonce = secret_nonce.to_musig2()?;
		let local_public_nonce = musig_public_nonce_to_wire(&secret_nonce.public_nonce())?;
		let aggregate_nonce = aggregate_musig_public_nonces(public_nonces)?;
		let signer_scalar = musig_scalar(signer_secret_key)?;
		let musig_ctx = self.taproot_musig_context(tapscript_root)?;
		let partial_signature: musig2::PartialSignature = musig2::sign_partial(
			&musig_ctx,
			signer_scalar,
			secret_nonce,
			&aggregate_nonce,
			message,
		)
		.map_err(|_| SimpleTaprootMusigError::InvalidSignature)?;
		nonce_state.mark_used(nonce_use)?;
		Ok(SimpleTaprootPartialSignatureWithNonce::new(
			SimpleTaprootPartialSignature::from_bytes(partial_signature.serialize()),
			local_public_nonce,
		))
	}

	/// Verifies a peer's MuSig2 partial signature.
	pub fn verify_partial(
		&self, signer_pubkey: &PublicKey, signer_public_nonce: &Musig2PublicNonce,
		partial_signature: &SimpleTaprootPartialSignature, public_nonces: &[Musig2PublicNonce],
		message: &[u8],
	) -> Result<(), SimpleTaprootMusigError> {
		self.verify_partial_with_tapscript_root(
			signer_pubkey,
			signer_public_nonce,
			partial_signature,
			public_nonces,
			message,
			None,
		)
	}

	/// Verifies a peer's MuSig2 partial signature under the selected taproot tweak.
	pub fn verify_partial_with_tapscript_root(
		&self, signer_pubkey: &PublicKey, signer_public_nonce: &Musig2PublicNonce,
		partial_signature: &SimpleTaprootPartialSignature, public_nonces: &[Musig2PublicNonce],
		message: &[u8], tapscript_root: Option<[u8; 32]>,
	) -> Result<(), SimpleTaprootMusigError> {
		let musig_ctx = self.taproot_musig_context(tapscript_root)?;
		let aggregate_nonce = aggregate_musig_public_nonces(public_nonces)?;
		let signer_pubkey = musig_point(signer_pubkey)?;
		let signer_public_nonce = musig_public_nonce_from_wire(signer_public_nonce)?;
		let partial_signature = musig_partial_signature(partial_signature)?;
		musig2::verify_partial(
			&musig_ctx,
			partial_signature,
			&aggregate_nonce,
			signer_pubkey,
			&signer_public_nonce,
			message,
		)
		.map_err(|_| SimpleTaprootMusigError::InvalidSignature)
	}

	/// Aggregates verified MuSig2 partial signatures into a final Schnorr signature.
	pub fn aggregate_final_signature(
		&self, partial_signatures: &[SimpleTaprootPartialSignature],
		public_nonces: &[Musig2PublicNonce], message: &[u8],
	) -> Result<schnorr::Signature, SimpleTaprootMusigError> {
		self.aggregate_final_signature_with_tapscript_root(
			partial_signatures,
			public_nonces,
			message,
			None,
		)
	}

	/// Aggregates verified partial signatures under the selected taproot tweak.
	pub fn aggregate_final_signature_with_tapscript_root(
		&self, partial_signatures: &[SimpleTaprootPartialSignature],
		public_nonces: &[Musig2PublicNonce], message: &[u8], tapscript_root: Option<[u8; 32]>,
	) -> Result<schnorr::Signature, SimpleTaprootMusigError> {
		let musig_ctx = self.taproot_musig_context(tapscript_root)?;
		let aggregate_nonce = aggregate_musig_public_nonces(public_nonces)?;
		let mut signatures = Vec::new();
		for partial_signature in partial_signatures.iter() {
			signatures.push(musig_partial_signature(partial_signature)?);
		}
		let final_signature: musig2::CompactSignature =
			musig2::aggregate_partial_signatures(&musig_ctx, &aggregate_nonce, signatures, message)
				.map_err(|_| SimpleTaprootMusigError::InvalidSignature)?;
		schnorr::Signature::from_slice(&final_signature.serialize())
			.map_err(|_| SimpleTaprootMusigError::InvalidSignature)
	}

	/// Verifies an aggregated Schnorr signature against this aggregate key.
	pub fn verify_final_signature(
		&self, signature: &schnorr::Signature, message: &[u8],
	) -> Result<(), SimpleTaprootMusigError> {
		self.verify_final_signature_with_tapscript_root(signature, message, None)
	}

	/// Verifies an aggregated Schnorr signature against the selected aggregate key.
	pub fn verify_final_signature_with_tapscript_root(
		&self, signature: &schnorr::Signature, message: &[u8], tapscript_root: Option<[u8; 32]>,
	) -> Result<(), SimpleTaprootMusigError> {
		let musig_ctx = self.taproot_musig_context(tapscript_root)?;
		let aggregate: musig2::secp::Point = musig_ctx.aggregated_pubkey();
		musig2::verify_single(aggregate, signature.serialize(), message)
			.map_err(|_| SimpleTaprootMusigError::InvalidSignature)
	}

	fn taproot_musig_context(
		&self, tapscript_root: Option<[u8; 32]>,
	) -> Result<musig2::KeyAggContext, SimpleTaprootMusigError> {
		let musig_ctx = self.musig_context()?;
		match tapscript_root {
			Some(root) => musig_ctx.with_taproot_tweak(&root),
			None => musig_ctx.with_unspendable_taproot_tweak(),
		}
		.map_err(|_| SimpleTaprootMusigError::InvalidKey)
	}

	fn musig_context(&self) -> Result<musig2::KeyAggContext, SimpleTaprootMusigError> {
		let mut points = Vec::new();
		for pubkey in self.sorted_pubkeys.iter() {
			points.push(musig_point(pubkey)?);
		}
		musig2::KeyAggContext::new(points).map_err(|_| SimpleTaprootMusigError::InvalidKey)
	}
}

#[cfg(feature = "simple_taproot_musig2")]
fn simple_taproot_nums_xonly_key() -> Result<XOnlyPublicKey, SimpleTaprootMusigError> {
	let nums_point = PublicKey::from_slice(&SIMPLE_TAPROOT_NUMS_POINT_BYTES)
		.map_err(|_| SimpleTaprootMusigError::InvalidKey)?;
	Ok(nums_point.x_only_public_key().0)
}

#[cfg(feature = "simple_taproot_musig2")]
fn xonly_key(public_key: &PublicKey) -> XOnlyPublicKey {
	public_key.x_only_public_key().0
}

#[cfg(feature = "simple_taproot_musig2")]
fn leaf_spend_info(
	spend_info: &TaprootSpendInfo, script: ScriptBuf,
) -> Result<SimpleTaprootLeafSpendInfo, SimpleTaprootMusigError> {
	let control_block = spend_info
		.control_block(&(script.clone(), LeafVersion::TapScript))
		.ok_or(SimpleTaprootMusigError::InvalidKey)?
		.serialize();
	Ok(SimpleTaprootLeafSpendInfo { script, control_block })
}

#[cfg(feature = "simple_taproot_musig2")]
fn tapscript_root(spend_info: &TaprootSpendInfo) -> Result<[u8; 32], SimpleTaprootMusigError> {
	Ok(spend_info.merkle_root().ok_or(SimpleTaprootMusigError::InvalidKey)?.to_byte_array())
}

#[cfg(feature = "simple_taproot_musig2")]
fn p2tr_script_pubkey(spend_info: &TaprootSpendInfo) -> ScriptBuf {
	ScriptBuf::new_p2tr_tweaked(spend_info.output_key())
}

/// Returns the staging simple-taproot `to_local` delay tapscript used by LND's
/// `simple-taproot-overlay` channel type.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_to_local_delay_script(
	local_delayed_pubkey: &PublicKey, contest_delay: u16,
) -> ScriptBuf {
	Builder::new()
		.push_x_only_key(&xonly_key(local_delayed_pubkey))
		.push_opcode(opcodes::all::OP_CHECKSIG)
		.push_int(contest_delay as i64)
		.push_opcode(opcodes::all::OP_CSV)
		.push_opcode(opcodes::all::OP_DROP)
		.into_script()
}

/// Returns the BOLT simple-taproot `to_local` revocation tapscript.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_to_local_revocation_script(
	local_delayed_pubkey: &PublicKey, revocation_pubkey: &PublicKey,
) -> ScriptBuf {
	Builder::new()
		.push_x_only_key(&xonly_key(local_delayed_pubkey))
		.push_opcode(opcodes::all::OP_DROP)
		.push_x_only_key(&xonly_key(revocation_pubkey))
		.push_opcode(opcodes::all::OP_CHECKSIG)
		.into_script()
}

/// Returns all script-path spend data for a BOLT simple-taproot `to_local` output.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_to_local_spend_info<C: Verification>(
	secp_ctx: &Secp256k1<C>, local_delayed_pubkey: &PublicKey, revocation_pubkey: &PublicKey,
	contest_delay: u16,
) -> Result<SimpleTaprootToLocalSpendInfo, SimpleTaprootMusigError> {
	simple_taproot_to_local_spend_info_with_aux_leaf(
		secp_ctx,
		local_delayed_pubkey,
		revocation_pubkey,
		contest_delay,
		None,
	)
}

/// Returns all script-path spend data for a BOLT simple-taproot `to_local` output, optionally
/// including a Taproot Asset auxiliary leaf at the top level.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_to_local_spend_info_with_aux_leaf<C: Verification>(
	secp_ctx: &Secp256k1<C>, local_delayed_pubkey: &PublicKey, revocation_pubkey: &PublicKey,
	contest_delay: u16, auxiliary_leaf_script: Option<&Script>,
) -> Result<SimpleTaprootToLocalSpendInfo, SimpleTaprootMusigError> {
	let delay_script = simple_taproot_to_local_delay_script(local_delayed_pubkey, contest_delay);
	let revocation_script =
		simple_taproot_to_local_revocation_script(local_delayed_pubkey, revocation_pubkey);
	let mut builder = TaprootBuilder::new();
	if let Some(auxiliary_leaf_script) = auxiliary_leaf_script {
		builder = builder
			.add_leaf(2, revocation_script.clone())
			.map_err(|_| SimpleTaprootMusigError::InvalidKey)?
			.add_leaf(2, delay_script.clone())
			.map_err(|_| SimpleTaprootMusigError::InvalidKey)?
			.add_leaf(1, auxiliary_leaf_script.to_owned())
			.map_err(|_| SimpleTaprootMusigError::InvalidKey)?;
	} else {
		builder = builder
			.add_leaf(1, revocation_script.clone())
			.map_err(|_| SimpleTaprootMusigError::InvalidKey)?
			.add_leaf(1, delay_script.clone())
			.map_err(|_| SimpleTaprootMusigError::InvalidKey)?;
	}
	let spend_info = builder
		.finalize(secp_ctx, simple_taproot_nums_xonly_key()?)
		.map_err(|_| SimpleTaprootMusigError::InvalidKey)?;
	let script_pubkey = p2tr_script_pubkey(&spend_info);
	let tapscript_root = tapscript_root(&spend_info)?;
	let tap_tweak = spend_info.tap_tweak().to_byte_array();
	let delay = leaf_spend_info(&spend_info, delay_script)?;
	let revocation = leaf_spend_info(&spend_info, revocation_script)?;
	Ok(SimpleTaprootToLocalSpendInfo {
		script_pubkey,
		tapscript_root,
		tap_tweak,
		delay,
		revocation,
	})
}

/// Returns the staging simple-taproot `to_remote` settlement tapscript used by
/// LND's `simple-taproot-overlay` channel type.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_to_remote_script(remote_pubkey: &PublicKey) -> ScriptBuf {
	Builder::new()
		.push_x_only_key(&xonly_key(remote_pubkey))
		.push_opcode(opcodes::all::OP_CHECKSIG)
		.push_opcode(opcodes::all::OP_PUSHNUM_1)
		.push_opcode(opcodes::all::OP_CSV)
		.push_opcode(opcodes::all::OP_DROP)
		.into_script()
}

/// Returns all script-path spend data for a BOLT simple-taproot `to_remote` output.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_to_remote_spend_info<C: Verification>(
	secp_ctx: &Secp256k1<C>, remote_pubkey: &PublicKey,
) -> Result<SimpleTaprootSingleLeafSpendInfo, SimpleTaprootMusigError> {
	simple_taproot_to_remote_spend_info_with_aux_leaf(secp_ctx, remote_pubkey, None)
}

/// Returns all script-path spend data for a BOLT simple-taproot `to_remote` output, optionally
/// including a Taproot Asset auxiliary leaf at the top level.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_to_remote_spend_info_with_aux_leaf<C: Verification>(
	secp_ctx: &Secp256k1<C>, remote_pubkey: &PublicKey, auxiliary_leaf_script: Option<&Script>,
) -> Result<SimpleTaprootSingleLeafSpendInfo, SimpleTaprootMusigError> {
	let script = simple_taproot_to_remote_script(remote_pubkey);
	let mut builder = TaprootBuilder::new();
	if let Some(auxiliary_leaf_script) = auxiliary_leaf_script {
		builder = builder
			.add_leaf(1, script.clone())
			.map_err(|_| SimpleTaprootMusigError::InvalidKey)?
			.add_leaf(1, auxiliary_leaf_script.to_owned())
			.map_err(|_| SimpleTaprootMusigError::InvalidKey)?;
	} else {
		builder =
			builder.add_leaf(0, script.clone()).map_err(|_| SimpleTaprootMusigError::InvalidKey)?;
	}
	let spend_info = builder
		.finalize(secp_ctx, simple_taproot_nums_xonly_key()?)
		.map_err(|_| SimpleTaprootMusigError::InvalidKey)?;
	let script_pubkey = p2tr_script_pubkey(&spend_info);
	let tapscript_root = tapscript_root(&spend_info)?;
	let tap_tweak = spend_info.tap_tweak().to_byte_array();
	let spend = leaf_spend_info(&spend_info, script)?;
	Ok(SimpleTaprootSingleLeafSpendInfo { script_pubkey, tapscript_root, tap_tweak, spend })
}

/// Returns the BOLT simple-taproot anchor sweep tapscript.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_anchor_script() -> ScriptBuf {
	Builder::new()
		.push_opcode(opcodes::all::OP_PUSHNUM_16)
		.push_opcode(opcodes::all::OP_CSV)
		.into_script()
}

/// Returns all script-path spend data for a BOLT simple-taproot anchor output.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_anchor_spend_info<C: Verification>(
	secp_ctx: &Secp256k1<C>, anchor_internal_key: &PublicKey,
) -> Result<SimpleTaprootSingleLeafSpendInfo, SimpleTaprootMusigError> {
	let script = simple_taproot_anchor_script();
	let spend_info = TaprootBuilder::new()
		.add_leaf(0, script.clone())
		.map_err(|_| SimpleTaprootMusigError::InvalidKey)?
		.finalize(secp_ctx, xonly_key(anchor_internal_key))
		.map_err(|_| SimpleTaprootMusigError::InvalidKey)?;
	let script_pubkey = p2tr_script_pubkey(&spend_info);
	let tapscript_root = tapscript_root(&spend_info)?;
	let tap_tweak = spend_info.tap_tweak().to_byte_array();
	let spend = leaf_spend_info(&spend_info, script)?;
	Ok(SimpleTaprootSingleLeafSpendInfo { script_pubkey, tapscript_root, tap_tweak, spend })
}

/// Returns the BOLT simple-taproot offered-HTLC timeout tapscript.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_offered_htlc_timeout_script(
	local_htlc_pubkey: &PublicKey, remote_htlc_pubkey: &PublicKey,
) -> ScriptBuf {
	Builder::new()
		.push_x_only_key(&xonly_key(local_htlc_pubkey))
		.push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
		.push_x_only_key(&xonly_key(remote_htlc_pubkey))
		.push_opcode(opcodes::all::OP_CHECKSIG)
		.into_script()
}

/// Returns the BOLT simple-taproot offered-HTLC success tapscript.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_offered_htlc_success_script(
	remote_htlc_pubkey: &PublicKey, payment_hash: &PaymentHash,
) -> ScriptBuf {
	simple_taproot_offered_htlc_success_script_for_variant(
		remote_htlc_pubkey,
		payment_hash,
		SimpleTaprootHtlcScriptVariant::Final,
	)
}

/// Returns the simple-taproot offered-HTLC success tapscript for a script variant.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_offered_htlc_success_script_for_variant(
	remote_htlc_pubkey: &PublicKey, payment_hash: &PaymentHash,
	variant: SimpleTaprootHtlcScriptVariant,
) -> ScriptBuf {
	let payment_hash160 = Ripemd160::hash(&payment_hash.0[..]).to_byte_array();
	let mut builder = Builder::new()
		.push_opcode(opcodes::all::OP_SIZE)
		.push_int(32)
		.push_opcode(opcodes::all::OP_EQUALVERIFY)
		.push_opcode(opcodes::all::OP_HASH160)
		.push_slice(&payment_hash160)
		.push_opcode(opcodes::all::OP_EQUALVERIFY)
		.push_x_only_key(&xonly_key(remote_htlc_pubkey));

	match variant {
		SimpleTaprootHtlcScriptVariant::Staging => {
			builder = builder.push_opcode(opcodes::all::OP_CHECKSIG);
			builder = builder
				.push_opcode(opcodes::all::OP_PUSHNUM_1)
				.push_opcode(opcodes::all::OP_CSV)
				.push_opcode(opcodes::all::OP_DROP);
		},
		SimpleTaprootHtlcScriptVariant::Final => {
			builder = builder.push_opcode(opcodes::all::OP_CHECKSIGVERIFY);
			builder =
				builder.push_opcode(opcodes::all::OP_PUSHNUM_1).push_opcode(opcodes::all::OP_CSV);
		},
	}

	builder.into_script()
}

/// Returns the BOLT simple-taproot accepted-HTLC timeout tapscript.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_accepted_htlc_timeout_script(
	remote_htlc_pubkey: &PublicKey, cltv_expiry: u32,
) -> ScriptBuf {
	simple_taproot_accepted_htlc_timeout_script_for_variant(
		remote_htlc_pubkey,
		cltv_expiry,
		SimpleTaprootHtlcScriptVariant::Final,
	)
}

/// Returns the simple-taproot accepted-HTLC timeout tapscript for a script variant.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_accepted_htlc_timeout_script_for_variant(
	remote_htlc_pubkey: &PublicKey, cltv_expiry: u32, variant: SimpleTaprootHtlcScriptVariant,
) -> ScriptBuf {
	let mut builder = Builder::new()
		.push_x_only_key(&xonly_key(remote_htlc_pubkey))
		.push_opcode(match variant {
			SimpleTaprootHtlcScriptVariant::Staging => opcodes::all::OP_CHECKSIG,
			SimpleTaprootHtlcScriptVariant::Final => opcodes::all::OP_CHECKSIGVERIFY,
		})
		.push_opcode(opcodes::all::OP_PUSHNUM_1)
		.push_opcode(opcodes::all::OP_CSV)
		.push_opcode(match variant {
			SimpleTaprootHtlcScriptVariant::Staging => opcodes::all::OP_DROP,
			SimpleTaprootHtlcScriptVariant::Final => opcodes::all::OP_VERIFY,
		})
		.push_int(cltv_expiry as i64)
		.push_opcode(opcodes::all::OP_CLTV);
	if variant == SimpleTaprootHtlcScriptVariant::Staging {
		builder = builder.push_opcode(opcodes::all::OP_DROP);
	}
	builder.into_script()
}

/// Returns the BOLT simple-taproot accepted-HTLC success tapscript.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_accepted_htlc_success_script(
	local_htlc_pubkey: &PublicKey, remote_htlc_pubkey: &PublicKey, payment_hash: &PaymentHash,
) -> ScriptBuf {
	let payment_hash160 = Ripemd160::hash(&payment_hash.0[..]).to_byte_array();
	Builder::new()
		.push_opcode(opcodes::all::OP_SIZE)
		.push_int(32)
		.push_opcode(opcodes::all::OP_EQUALVERIFY)
		.push_opcode(opcodes::all::OP_HASH160)
		.push_slice(&payment_hash160)
		.push_opcode(opcodes::all::OP_EQUALVERIFY)
		.push_x_only_key(&xonly_key(remote_htlc_pubkey))
		.push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
		.push_x_only_key(&xonly_key(local_htlc_pubkey))
		.push_opcode(opcodes::all::OP_CHECKSIG)
		.into_script()
}

/// Returns all script-path spend data for a BOLT simple-taproot HTLC output.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_htlc_spend_info<C: Verification>(
	secp_ctx: &Secp256k1<C>, offered: bool, payment_hash: &PaymentHash, cltv_expiry: u32,
	local_htlc_pubkey: &PublicKey, remote_htlc_pubkey: &PublicKey, revocation_pubkey: &PublicKey,
) -> Result<SimpleTaprootHtlcSpendInfo, SimpleTaprootMusigError> {
	simple_taproot_htlc_spend_info_with_aux_leaf(
		secp_ctx,
		offered,
		payment_hash,
		cltv_expiry,
		local_htlc_pubkey,
		remote_htlc_pubkey,
		revocation_pubkey,
		None,
	)
}

/// Returns all script-path spend data for a BOLT simple-taproot HTLC output, optionally
/// including a Taproot Asset auxiliary leaf at the top level.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_htlc_spend_info_with_aux_leaf<C: Verification>(
	secp_ctx: &Secp256k1<C>, offered: bool, payment_hash: &PaymentHash, cltv_expiry: u32,
	local_htlc_pubkey: &PublicKey, remote_htlc_pubkey: &PublicKey, revocation_pubkey: &PublicKey,
	auxiliary_leaf_script: Option<&Script>,
) -> Result<SimpleTaprootHtlcSpendInfo, SimpleTaprootMusigError> {
	simple_taproot_htlc_spend_info_with_aux_leaf_for_variant(
		secp_ctx,
		offered,
		payment_hash,
		cltv_expiry,
		local_htlc_pubkey,
		remote_htlc_pubkey,
		revocation_pubkey,
		auxiliary_leaf_script,
		SimpleTaprootHtlcScriptVariant::Final,
	)
}

/// Returns script-path spend data for a simple-taproot HTLC output using the requested
/// staging/final script variant.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_htlc_spend_info_with_aux_leaf_for_variant<C: Verification>(
	secp_ctx: &Secp256k1<C>, offered: bool, payment_hash: &PaymentHash, cltv_expiry: u32,
	local_htlc_pubkey: &PublicKey, remote_htlc_pubkey: &PublicKey, revocation_pubkey: &PublicKey,
	auxiliary_leaf_script: Option<&Script>, variant: SimpleTaprootHtlcScriptVariant,
) -> Result<SimpleTaprootHtlcSpendInfo, SimpleTaprootMusigError> {
	let (timeout_script, success_script) = if offered {
		(
			simple_taproot_offered_htlc_timeout_script(local_htlc_pubkey, remote_htlc_pubkey),
			simple_taproot_offered_htlc_success_script_for_variant(
				remote_htlc_pubkey,
				payment_hash,
				variant,
			),
		)
	} else {
		(
			simple_taproot_accepted_htlc_timeout_script_for_variant(
				local_htlc_pubkey,
				cltv_expiry,
				variant,
			),
			simple_taproot_accepted_htlc_success_script(
				local_htlc_pubkey,
				remote_htlc_pubkey,
				payment_hash,
			),
		)
	};
	let mut builder = TaprootBuilder::new();
	if let Some(auxiliary_leaf_script) = auxiliary_leaf_script {
		builder = builder
			.add_leaf(2, timeout_script.clone())
			.map_err(|_| SimpleTaprootMusigError::InvalidKey)?
			.add_leaf(2, success_script.clone())
			.map_err(|_| SimpleTaprootMusigError::InvalidKey)?
			.add_leaf(1, auxiliary_leaf_script.to_owned())
			.map_err(|_| SimpleTaprootMusigError::InvalidKey)?;
	} else {
		builder = builder
			.add_leaf(1, timeout_script.clone())
			.map_err(|_| SimpleTaprootMusigError::InvalidKey)?
			.add_leaf(1, success_script.clone())
			.map_err(|_| SimpleTaprootMusigError::InvalidKey)?;
	}
	let spend_info = builder
		.finalize(secp_ctx, xonly_key(revocation_pubkey))
		.map_err(|_| SimpleTaprootMusigError::InvalidKey)?;
	let script_pubkey = p2tr_script_pubkey(&spend_info);
	let tapscript_root = tapscript_root(&spend_info)?;
	let tap_tweak = spend_info.tap_tweak().to_byte_array();
	let timeout = leaf_spend_info(&spend_info, timeout_script)?;
	let success = leaf_spend_info(&spend_info, success_script)?;
	Ok(SimpleTaprootHtlcSpendInfo { script_pubkey, tapscript_root, tap_tweak, timeout, success })
}

/// Returns all script-path spend data for a simple-taproot second-level HTLC output.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_second_level_htlc_spend_info<C: Verification>(
	secp_ctx: &Secp256k1<C>, local_delayed_pubkey: &PublicKey, revocation_pubkey: &PublicKey,
	contest_delay: u16,
) -> Result<SimpleTaprootSingleLeafSpendInfo, SimpleTaprootMusigError> {
	let script = simple_taproot_to_local_delay_script(local_delayed_pubkey, contest_delay);
	let spend_info = TaprootBuilder::new()
		.add_leaf(0, script.clone())
		.map_err(|_| SimpleTaprootMusigError::InvalidKey)?
		.finalize(secp_ctx, xonly_key(revocation_pubkey))
		.map_err(|_| SimpleTaprootMusigError::InvalidKey)?;
	let script_pubkey = p2tr_script_pubkey(&spend_info);
	let tapscript_root = tapscript_root(&spend_info)?;
	let tap_tweak = spend_info.tap_tweak().to_byte_array();
	let spend = leaf_spend_info(&spend_info, script)?;
	Ok(SimpleTaprootSingleLeafSpendInfo { script_pubkey, tapscript_root, tap_tweak, spend })
}

/// Computes the BIP342 script-spend sighash for a second-level simple-taproot HTLC transaction.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_htlc_tapscript_sighash(
	htlc_tx: &Transaction, input_index: usize, previous_output: TxOut,
	leaf: &SimpleTaprootLeafSpendInfo,
) -> Result<[u8; 32], SimpleTaprootMusigError> {
	let prevouts = [previous_output];
	let prevouts = sighash::Prevouts::All(&prevouts);
	let leaf_hash = TapLeafHash::from_script(&leaf.script, LeafVersion::TapScript);
	let sighash = SighashCache::new(htlc_tx)
		.taproot_script_spend_signature_hash(
			input_index,
			&prevouts,
			leaf_hash,
			TapSighashType::SinglePlusAnyoneCanPay,
		)
		.map_err(|_| SimpleTaprootMusigError::InvalidSignature)?;
	Ok(sighash.to_byte_array())
}

/// Signs a second-level simple-taproot HTLC transaction with a BIP340 tapscript signature.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_sign_htlc_tapscript<C: Signing>(
	secp_ctx: &Secp256k1<C>, htlc_tx: &Transaction, input_index: usize, previous_output: TxOut,
	leaf: &SimpleTaprootLeafSpendInfo, signer_secret_key: &SecretKey, aux_rand: &[u8; 32],
) -> Result<TaprootSignature, SimpleTaprootMusigError> {
	let sighash =
		simple_taproot_htlc_tapscript_sighash(htlc_tx, input_index, previous_output, leaf)?;
	let message = Message::from_digest(sighash);
	let keypair = Keypair::from_secret_key(secp_ctx, signer_secret_key);
	let signature = secp_ctx.sign_schnorr_with_aux_rand(&message, &keypair, aux_rand);
	Ok(TaprootSignature { signature, sighash_type: TapSighashType::SinglePlusAnyoneCanPay })
}

/// Verifies a BIP340 tapscript signature for a second-level simple-taproot HTLC transaction.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_verify_htlc_tapscript_signature<C: Verification>(
	secp_ctx: &Secp256k1<C>, htlc_tx: &Transaction, input_index: usize, previous_output: TxOut,
	leaf: &SimpleTaprootLeafSpendInfo, signer_pubkey: &PublicKey, signature: &TaprootSignature,
) -> Result<(), SimpleTaprootMusigError> {
	if signature.sighash_type != TapSighashType::SinglePlusAnyoneCanPay {
		return Err(SimpleTaprootMusigError::InvalidSignature);
	}
	let sighash =
		simple_taproot_htlc_tapscript_sighash(htlc_tx, input_index, previous_output, leaf)?;
	let message = Message::from_digest(sighash);
	secp_ctx
		.verify_schnorr(&signature.signature, &message, &xonly_key(signer_pubkey))
		.map_err(|_| SimpleTaprootMusigError::InvalidSignature)
}

/// Builds the BOLT simple-taproot second-level HTLC witness stack.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_htlc_input_witness(
	spend_path: SimpleTaprootHtlcSpendPath, remote_signature: Option<&TaprootSignature>,
	local_signature: Option<&TaprootSignature>, preimage: Option<&[u8; 32]>,
	leaf: &SimpleTaprootLeafSpendInfo,
) -> Result<Witness, SimpleTaprootMusigError> {
	let mut witness = Witness::new();
	match spend_path {
		SimpleTaprootHtlcSpendPath::OfferedTimeout => {
			witness
				.push(remote_signature.ok_or(SimpleTaprootMusigError::InvalidSignature)?.to_vec());
			witness
				.push(local_signature.ok_or(SimpleTaprootMusigError::InvalidSignature)?.to_vec());
		},
		SimpleTaprootHtlcSpendPath::OfferedSuccess => {
			witness
				.push(remote_signature.ok_or(SimpleTaprootMusigError::InvalidSignature)?.to_vec());
			witness.push(preimage.ok_or(SimpleTaprootMusigError::InvalidSignature)?.to_vec());
		},
		SimpleTaprootHtlcSpendPath::AcceptedTimeout => {
			witness
				.push(local_signature.ok_or(SimpleTaprootMusigError::InvalidSignature)?.to_vec());
		},
		SimpleTaprootHtlcSpendPath::AcceptedSuccess => {
			witness
				.push(local_signature.ok_or(SimpleTaprootMusigError::InvalidSignature)?.to_vec());
			witness
				.push(remote_signature.ok_or(SimpleTaprootMusigError::InvalidSignature)?.to_vec());
			witness.push(preimage.ok_or(SimpleTaprootMusigError::InvalidSignature)?.to_vec());
		},
	}
	witness.push(leaf.script.to_bytes());
	witness.push(leaf.control_block.clone());
	Ok(witness)
}

/// Signs and assembles a BOLT simple-taproot second-level HTLC witness.
#[cfg(feature = "simple_taproot_musig2")]
pub fn simple_taproot_sign_htlc_spend<C: Signing + Verification>(
	secp_ctx: &Secp256k1<C>, htlc_tx: &Transaction, input_index: usize, previous_amount: Amount,
	previous_spend_info: &SimpleTaprootHtlcSpendInfo, leaf: &SimpleTaprootLeafSpendInfo,
	spend_path: SimpleTaprootHtlcSpendPath, local_htlc_secret_key: Option<&SecretKey>,
	remote_htlc_secret_key: Option<&SecretKey>, preimage: Option<&[u8; 32]>, aux_rand: &[u8; 32],
) -> Result<SimpleTaprootSignedHtlcSpend, SimpleTaprootMusigError> {
	let previous_output =
		TxOut { value: previous_amount, script_pubkey: previous_spend_info.script_pubkey.clone() };
	let needs_local_signature = matches!(
		spend_path,
		SimpleTaprootHtlcSpendPath::OfferedTimeout
			| SimpleTaprootHtlcSpendPath::AcceptedTimeout
			| SimpleTaprootHtlcSpendPath::AcceptedSuccess
	);
	let needs_remote_signature = matches!(
		spend_path,
		SimpleTaprootHtlcSpendPath::OfferedTimeout
			| SimpleTaprootHtlcSpendPath::OfferedSuccess
			| SimpleTaprootHtlcSpendPath::AcceptedSuccess
	);
	let local_signature = if needs_local_signature {
		let local_htlc_secret_key =
			local_htlc_secret_key.ok_or(SimpleTaprootMusigError::InvalidSignature)?;
		let signature = simple_taproot_sign_htlc_tapscript(
			secp_ctx,
			htlc_tx,
			input_index,
			previous_output.clone(),
			leaf,
			local_htlc_secret_key,
			aux_rand,
		)?;
		simple_taproot_verify_htlc_tapscript_signature(
			secp_ctx,
			htlc_tx,
			input_index,
			previous_output.clone(),
			leaf,
			&PublicKey::from_secret_key(secp_ctx, local_htlc_secret_key),
			&signature,
		)?;
		Some(signature)
	} else {
		None
	};
	let remote_signature = if needs_remote_signature {
		let remote_htlc_secret_key =
			remote_htlc_secret_key.ok_or(SimpleTaprootMusigError::InvalidSignature)?;
		let signature = simple_taproot_sign_htlc_tapscript(
			secp_ctx,
			htlc_tx,
			input_index,
			previous_output.clone(),
			leaf,
			remote_htlc_secret_key,
			aux_rand,
		)?;
		simple_taproot_verify_htlc_tapscript_signature(
			secp_ctx,
			htlc_tx,
			input_index,
			previous_output.clone(),
			leaf,
			&PublicKey::from_secret_key(secp_ctx, remote_htlc_secret_key),
			&signature,
		)?;
		Some(signature)
	} else {
		None
	};
	let sighash = simple_taproot_htlc_tapscript_sighash(
		htlc_tx,
		input_index,
		TxOut { value: previous_amount, script_pubkey: previous_spend_info.script_pubkey.clone() },
		leaf,
	)?;
	let witness = simple_taproot_htlc_input_witness(
		spend_path,
		remote_signature.as_ref(),
		local_signature.as_ref(),
		preimage,
		leaf,
	)?;
	Ok(SimpleTaprootSignedHtlcSpend { sighash, local_signature, remote_signature, witness })
}

/// Derives a deterministic simple-taproot counter nonce seed from LDK's shachain seed.
#[cfg(feature = "simple_taproot_musig2")]
pub fn derive_simple_taproot_counter_nonce_seed(
	commitment_seed: &[u8; 32], nonce_use: &SimpleTaprootNonceUse,
) -> [u8; 32] {
	let mut root_key = Vec::new();
	root_key.extend_from_slice(b"taproot-rev-root");
	root_key.extend_from_slice(nonce_use.funding_txid.as_byte_array());
	let mut root_hmac = HmacEngine::<Sha256>::new(&root_key);
	root_hmac.input(&Sha256::hash(commitment_seed).to_byte_array());
	let musig2_shachain_root = Hmac::from_engine(root_hmac).to_byte_array();

	let commitment_secret =
		crate::ln::chan_utils::build_commitment_secret(commitment_seed, nonce_use.nonce_index);
	let mut leaf_hmac = HmacEngine::<Sha256>::new(&musig2_shachain_root);
	leaf_hmac.input(&commitment_secret);
	leaf_hmac.input(&[nonce_use.scope.wire_value()]);
	Hmac::from_engine(leaf_hmac).to_byte_array()
}

/// Derives a domain-separated JIT nonce seed from caller-supplied entropy.
#[cfg(feature = "simple_taproot_musig2")]
pub fn derive_simple_taproot_jit_nonce_seed(
	entropy: &[u8; 32], nonce_use: &SimpleTaprootNonceUse,
) -> [u8; 32] {
	let mut hmac = HmacEngine::<Sha256>::new(b"simple-taproot-jit-nonce");
	hmac.input(entropy);
	hmac.input(&nonce_use.extra_input());
	Hmac::from_engine(hmac).to_byte_array()
}

#[cfg(feature = "simple_taproot_musig2")]
fn musig_point(pubkey: &PublicKey) -> Result<musig2::secp::Point, SimpleTaprootMusigError> {
	musig2::secp::Point::from_slice(&pubkey.serialize())
		.map_err(|_| SimpleTaprootMusigError::InvalidKey)
}

#[cfg(feature = "simple_taproot_musig2")]
fn musig_scalar(secret_key: &SecretKey) -> Result<musig2::secp::Scalar, SimpleTaprootMusigError> {
	musig2::secp::Scalar::from_slice(&secret_key.secret_bytes())
		.map_err(|_| SimpleTaprootMusigError::InvalidKey)
}

#[cfg(feature = "simple_taproot_musig2")]
fn musig_public_nonce_from_wire(
	nonce: &Musig2PublicNonce,
) -> Result<musig2::PubNonce, SimpleTaprootMusigError> {
	musig2::PubNonce::from_bytes(nonce.as_bytes())
		.map_err(|_| SimpleTaprootMusigError::InvalidNonce)
}

#[cfg(feature = "simple_taproot_musig2")]
fn musig_public_nonce_to_wire(
	nonce: &musig2::PubNonce,
) -> Result<Musig2PublicNonce, SimpleTaprootMusigError> {
	Musig2PublicNonce::from_bytes(nonce.serialize())
		.map_err(|_| SimpleTaprootMusigError::InvalidNonce)
}

#[cfg(feature = "simple_taproot_musig2")]
fn musig_partial_signature(
	partial_signature: &SimpleTaprootPartialSignature,
) -> Result<musig2::PartialSignature, SimpleTaprootMusigError> {
	musig2::secp::MaybeScalar::from_slice(partial_signature.as_bytes())
		.map_err(|_| SimpleTaprootMusigError::InvalidSignature)
}

#[cfg(feature = "simple_taproot_musig2")]
fn aggregate_musig_public_nonces(
	public_nonces: &[Musig2PublicNonce],
) -> Result<musig2::AggNonce, SimpleTaprootMusigError> {
	if public_nonces.is_empty() {
		return Err(SimpleTaprootMusigError::InvalidNonce);
	}
	let mut parsed_nonces = Vec::new();
	for nonce in public_nonces.iter() {
		parsed_nonces.push(musig_public_nonce_from_wire(nonce)?);
	}
	Ok(musig2::AggNonce::sum(parsed_nonces.iter()))
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
	#[cfg(not(feature = "simple_taproot_musig2"))]
	use bitcoin::hashes::Hash as _;
	#[cfg(feature = "simple_taproot_musig2")]
	use bitcoin::hex::FromHex;
	#[cfg(feature = "simple_taproot_musig2")]
	use bitcoin::secp256k1::{Secp256k1, SecretKey};

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

	#[test]
	fn nonce_state_rejects_duplicate_after_restart() {
		let nonce_use = SimpleTaprootNonceUse::new(
			Txid::from_slice(&[5; 32]).unwrap(),
			7,
			SimpleTaprootNonceScope::Commitment,
		);
		let mut state = SimpleTaprootNonceState::new();
		state.mark_used(nonce_use).unwrap();
		assert_eq!(state.mark_used(nonce_use), Err(SimpleTaprootMusigError::DuplicateNonceUse));

		let mut encoded = Vec::new();
		state.write(&mut encoded).unwrap();
		let mut decoded = SimpleTaprootNonceState::read(&mut &encoded[..]).unwrap();
		assert!(decoded.is_used(&nonce_use));
		assert_eq!(decoded.mark_used(nonce_use), Err(SimpleTaprootMusigError::DuplicateNonceUse));
	}

	#[test]
	fn persisted_nonce_and_sent_signature_sets_upsert_and_round_trip() {
		let funding_txid = Txid::from_slice(&[6; 32]).unwrap();
		let mut nonce_entries = SimpleTaprootNonceEntries::default();
		nonce_entries
			.upsert(SimpleTaprootNonceEntry { funding_txid, public_nonce: sample_nonce(1) });
		nonce_entries
			.upsert(SimpleTaprootNonceEntry { funding_txid, public_nonce: sample_nonce(2) });
		assert_eq!(nonce_entries.0.len(), 1);
		assert_eq!(nonce_entries.get(funding_txid), Some(sample_nonce(2)));
		let mut encoded_nonces = Vec::new();
		nonce_entries.write(&mut encoded_nonces).unwrap();
		let decoded_nonces = SimpleTaprootNonceEntries::read(&mut &encoded_nonces[..]).unwrap();
		assert_eq!(decoded_nonces, nonce_entries);

		let first_signature = SimpleTaprootPartialSignatureWithNonce::new(
			SimpleTaprootPartialSignature::from_bytes([8; MUSIG2_PARTIAL_SIGNATURE_LEN]),
			sample_nonce(1),
		);
		let second_signature = SimpleTaprootPartialSignatureWithNonce::new(
			SimpleTaprootPartialSignature::from_bytes([9; MUSIG2_PARTIAL_SIGNATURE_LEN]),
			sample_nonce(2),
		);
		let mut sent_signatures = SimpleTaprootSentCommitmentSignatures::default();
		sent_signatures.upsert(SimpleTaprootSentCommitmentSignature {
			funding_txid,
			nonce_index: 42,
			partial_signature_with_nonce: first_signature,
		});
		sent_signatures.upsert(SimpleTaprootSentCommitmentSignature {
			funding_txid,
			nonce_index: 42,
			partial_signature_with_nonce: second_signature,
		});
		assert_eq!(sent_signatures.0.len(), 1);
		assert_eq!(sent_signatures.get(funding_txid, 42), Some(second_signature));
		let mut encoded_signatures = Vec::new();
		sent_signatures.write(&mut encoded_signatures).unwrap();
		let decoded_signatures =
			SimpleTaprootSentCommitmentSignatures::read(&mut &encoded_signatures[..]).unwrap();
		assert_eq!(decoded_signatures, sent_signatures);
	}

	#[cfg(feature = "simple_taproot_musig2")]
	#[test]
	fn musig2_signatures_aggregate_and_verify() {
		let secp_ctx = Secp256k1::new();
		let alice_secret = SecretKey::from_slice(&[1; 32]).unwrap();
		let bob_secret = SecretKey::from_slice(&[2; 32]).unwrap();
		let alice_pubkey = PublicKey::from_secret_key(&secp_ctx, &alice_secret);
		let bob_pubkey = PublicKey::from_secret_key(&secp_ctx, &bob_secret);
		let key_agg_ctx = SimpleTaprootKeyAggContext::for_funding_keys(bob_pubkey, alice_pubkey);
		assert!(
			key_agg_ctx.sorted_pubkeys()[0].serialize()
				< key_agg_ctx.sorted_pubkeys()[1].serialize()
		);
		let _aggregate_key = key_agg_ctx.aggregate_xonly_public_key().unwrap();

		let nonce_use = SimpleTaprootNonceUse::new(
			Txid::from_slice(&[9; 32]).unwrap(),
			42,
			SimpleTaprootNonceScope::Commitment,
		);
		let message = Sha256::hash(b"simple taproot commitment").to_byte_array();
		let alice_seed = derive_simple_taproot_jit_nonce_seed(&[7; 32], &nonce_use);
		let bob_seed = derive_simple_taproot_jit_nonce_seed(&[8; 32], &nonce_use);
		let alice_nonce = key_agg_ctx
			.generate_nonce_pair(&alice_secret, alice_seed, &message, &nonce_use)
			.unwrap();
		let bob_nonce =
			key_agg_ctx.generate_nonce_pair(&bob_secret, bob_seed, &message, &nonce_use).unwrap();
		let public_nonces = [alice_nonce.public_nonce, bob_nonce.public_nonce];

		let mut alice_state = SimpleTaprootNonceState::new();
		let alice_partial = key_agg_ctx
			.sign_partial(
				&alice_secret,
				alice_nonce.secret_nonce.clone(),
				&public_nonces,
				&message,
				nonce_use,
				&mut alice_state,
			)
			.unwrap();
		assert_eq!(
			key_agg_ctx.sign_partial(
				&alice_secret,
				alice_nonce.secret_nonce,
				&public_nonces,
				&message,
				nonce_use,
				&mut alice_state,
			),
			Err(SimpleTaprootMusigError::DuplicateNonceUse)
		);

		let mut bob_state = SimpleTaprootNonceState::new();
		let bob_partial = key_agg_ctx
			.sign_partial(
				&bob_secret,
				bob_nonce.secret_nonce,
				&public_nonces,
				&message,
				nonce_use,
				&mut bob_state,
			)
			.unwrap();

		key_agg_ctx
			.verify_partial(
				&alice_pubkey,
				&alice_partial.public_nonce,
				&alice_partial.partial_signature,
				&public_nonces,
				&message,
			)
			.unwrap();
		key_agg_ctx
			.verify_partial(
				&bob_pubkey,
				&bob_partial.public_nonce,
				&bob_partial.partial_signature,
				&public_nonces,
				&message,
			)
			.unwrap();

		let mut bad_signature = *bob_partial.partial_signature.as_bytes();
		bad_signature[0] ^= 1;
		assert_eq!(
			key_agg_ctx.verify_partial(
				&bob_pubkey,
				&bob_partial.public_nonce,
				&SimpleTaprootPartialSignature::from_bytes(bad_signature),
				&public_nonces,
				&message,
			),
			Err(SimpleTaprootMusigError::InvalidSignature)
		);

		let final_signature = key_agg_ctx
			.aggregate_final_signature(
				&[alice_partial.partial_signature, bob_partial.partial_signature],
				&public_nonces,
				&message,
			)
			.unwrap();
		key_agg_ctx.verify_final_signature(&final_signature, &message).unwrap();
		let bip86_key = key_agg_ctx.bip86_aggregate_xonly_public_key().unwrap();
		let message = Message::from_digest_slice(&message).unwrap();
		secp_ctx.verify_schnorr(&final_signature, &message, &bip86_key).unwrap();
		let untweaked_key = key_agg_ctx.aggregate_xonly_public_key().unwrap();
		assert!(secp_ctx.verify_schnorr(&final_signature, &message, &untweaked_key).is_err());
	}

	#[cfg(feature = "simple_taproot_musig2")]
	#[test]
	fn musig2_tapscript_root_tweak_signs_and_verifies() {
		let secp_ctx = Secp256k1::new();
		let alice_secret = SecretKey::from_slice(&[11; 32]).unwrap();
		let bob_secret = SecretKey::from_slice(&[12; 32]).unwrap();
		let alice_pubkey = PublicKey::from_secret_key(&secp_ctx, &alice_secret);
		let bob_pubkey = PublicKey::from_secret_key(&secp_ctx, &bob_secret);
		let key_agg_ctx = SimpleTaprootKeyAggContext::for_funding_keys(alice_pubkey, bob_pubkey);
		let asset_root = Sha256::hash(b"taproot asset funding root").to_byte_array();
		let wrong_root = Sha256::hash(b"wrong taproot asset funding root").to_byte_array();

		let funding_script =
			key_agg_ctx.funding_script_pubkey(&secp_ctx, Some(asset_root)).unwrap();
		assert_eq!(
			funding_script,
			ScriptBuf::new_p2tr(
				&secp_ctx,
				key_agg_ctx.aggregate_xonly_public_key().unwrap(),
				Some(TapNodeHash::from_byte_array(asset_root))
			)
		);
		assert_ne!(funding_script, key_agg_ctx.bip86_funding_script_pubkey(&secp_ctx).unwrap());

		let nonce_use = SimpleTaprootNonceUse::new(
			Txid::from_slice(&[31; 32]).unwrap(),
			0,
			SimpleTaprootNonceScope::Commitment,
		);
		let message = Sha256::hash(b"taproot asset commitment").to_byte_array();
		let alice_seed = derive_simple_taproot_jit_nonce_seed(&[13; 32], &nonce_use);
		let bob_seed = derive_simple_taproot_jit_nonce_seed(&[14; 32], &nonce_use);
		let alice_nonce = key_agg_ctx
			.generate_nonce_pair_with_tapscript_root(
				&alice_secret,
				alice_seed,
				&message,
				&nonce_use,
				Some(asset_root),
			)
			.unwrap();
		assert_eq!(
			alice_nonce.public_nonce,
			key_agg_ctx
				.generate_nonce_pair(&alice_secret, alice_seed, &message, &nonce_use)
				.unwrap()
				.public_nonce
		);
		let bob_nonce = key_agg_ctx
			.generate_nonce_pair_with_tapscript_root(
				&bob_secret,
				bob_seed,
				&message,
				&nonce_use,
				Some(asset_root),
			)
			.unwrap();
		let public_nonces = [alice_nonce.public_nonce, bob_nonce.public_nonce];
		let mut alice_state = SimpleTaprootNonceState::new();
		let alice_partial = key_agg_ctx
			.sign_partial_with_tapscript_root(
				&alice_secret,
				alice_nonce.secret_nonce,
				&public_nonces,
				&message,
				nonce_use,
				&mut alice_state,
				Some(asset_root),
			)
			.unwrap();
		let mut bob_state = SimpleTaprootNonceState::new();
		let bob_partial = key_agg_ctx
			.sign_partial_with_tapscript_root(
				&bob_secret,
				bob_nonce.secret_nonce,
				&public_nonces,
				&message,
				nonce_use,
				&mut bob_state,
				Some(asset_root),
			)
			.unwrap();

		key_agg_ctx
			.verify_partial_with_tapscript_root(
				&alice_pubkey,
				&alice_partial.public_nonce,
				&alice_partial.partial_signature,
				&public_nonces,
				&message,
				Some(asset_root),
			)
			.unwrap();
		assert_eq!(
			key_agg_ctx.verify_partial(
				&alice_pubkey,
				&alice_partial.public_nonce,
				&alice_partial.partial_signature,
				&public_nonces,
				&message,
			),
			Err(SimpleTaprootMusigError::InvalidSignature)
		);
		assert_eq!(
			key_agg_ctx.verify_partial_with_tapscript_root(
				&alice_pubkey,
				&alice_partial.public_nonce,
				&alice_partial.partial_signature,
				&public_nonces,
				&message,
				Some(wrong_root),
			),
			Err(SimpleTaprootMusigError::InvalidSignature)
		);

		let final_signature = key_agg_ctx
			.aggregate_final_signature_with_tapscript_root(
				&[alice_partial.partial_signature, bob_partial.partial_signature],
				&public_nonces,
				&message,
				Some(asset_root),
			)
			.unwrap();
		key_agg_ctx
			.verify_final_signature_with_tapscript_root(
				&final_signature,
				&message,
				Some(asset_root),
			)
			.unwrap();
		assert_eq!(
			key_agg_ctx.verify_final_signature(&final_signature, &message),
			Err(SimpleTaprootMusigError::InvalidSignature)
		);
	}

	#[cfg(feature = "simple_taproot_musig2")]
	#[test]
	fn verifies_lnd_simple_taproot_commitment_vector() {
		use bitcoin::consensus::encode::deserialize;
		use bitcoin::hex::FromHex as _;

		let secp_ctx = Secp256k1::verification_only();
		let local_pubkey = PublicKey::from_slice(
			&Vec::<u8>::from_hex(
				"03b7203dec7c13896b6ff1f58b24f84458c441720a12b5a57426397e22f0a8c78b",
			)
			.unwrap(),
		)
		.unwrap();
		let remote_pubkey = PublicKey::from_slice(
			&Vec::<u8>::from_hex(
				"02956e6845a6f346f97c5e028c0f8ab38a76b0124fd7184deab60f682b3e657fdb",
			)
			.unwrap(),
		)
		.unwrap();
		let local_nonce = Musig2PublicNonce::from_slice(
			&Vec::<u8>::from_hex(
				"025f2272ea289c5fe9d52d411f5a50a6d4882341bf0ecb201d5675850a2ba0b09d025bc489cf67752134ba81f8d7f1146d7455baf3190de75a6a661e2405212991a9",
			)
			.unwrap(),
		)
		.unwrap();
		let remote_nonce = Musig2PublicNonce::from_slice(
			&Vec::<u8>::from_hex(
				"02d324627074522af8cf4287caf1e073a3493550b99aed2697e58f476ec402e272039c25fc616207e15917b7145cefcb4c9c702580baf255597d2fa115564a74a130",
			)
			.unwrap(),
		)
		.unwrap();
		let remote_partial = SimpleTaprootPartialSignature::from_slice(
			&Vec::<u8>::from_hex(
				"3fa93659d4c2d590eadbd422595a37597ed58607e026a91f4e6e19329134a931",
			)
			.unwrap(),
		)
		.unwrap();
		let commitment_tx: Transaction = deserialize(
			&Vec::<u8>::from_hex(
				"020000000001015474cba49124ab0c4327c244bb2907059585c4af3fa5f3469701534120fec0170000000000c5fe1780044a010000000000002251201249c50576fdf914caa14f9221370b986df520bdbc73f57d5056a86ee03e5ac44a01000000000000225120f67ab012701705f3203d132f909a6810ef18c5da4c11d986cb50818803b8344ec0c62d00000000002251203609bb705034e5629aa6ec05c5ca906ac89ac08b34c4583c259521ec3017440874946a00000000002251203e1fcbbd06c8a7414704612c72be9834a75d86ed85b29f0ef0c52e1950afaff30140a4a9eb512a2f4094efdd2c566f1f20cc8a6e2c307a4a44cc3f9fea7fa147dd7038f1b048aa43fa0b4009175c1c37c37b96c01058541f9e1b61110fce4e831d9f55dc1920",
			)
			.unwrap(),
		)
		.unwrap();
		let funding_output = TxOut {
			value: Amount::from_sat(10_000_000),
			script_pubkey: ScriptBuf::from_hex(
				"5120d0ebb4909d563a7ae1213fddede4ae54132fba0ef0b97ee3f8469191fecd348e",
			)
			.unwrap(),
		};
		let prevouts = [funding_output];
		let prevouts = sighash::Prevouts::All(&prevouts);
		let message = SighashCache::new(&commitment_tx)
			.taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default)
			.unwrap()
			.to_byte_array();
		let key_agg_ctx = SimpleTaprootKeyAggContext::for_funding_keys(local_pubkey, remote_pubkey);

		assert_eq!(
			key_agg_ctx.bip86_funding_script_pubkey(&secp_ctx).unwrap(),
			ScriptBuf::from_hex(
				"5120d0ebb4909d563a7ae1213fddede4ae54132fba0ef0b97ee3f8469191fecd348e",
			)
			.unwrap()
		);
		key_agg_ctx
			.verify_partial(
				&remote_pubkey,
				&remote_nonce,
				&remote_partial,
				&[local_nonce, remote_nonce],
				&message,
			)
			.unwrap();
	}

	#[cfg(feature = "simple_taproot_musig2")]
	#[test]
	fn bip86_funding_script_matches_bolt_vector() {
		let secp_ctx = Secp256k1::new();
		let local_funding_pubkey = PublicKey::from_slice(
			&Vec::<u8>::from_hex(
				"03b7203dec7c13896b6ff1f58b24f84458c441720a12b5a57426397e22f0a8c78b",
			)
			.unwrap(),
		)
		.unwrap();
		let remote_funding_pubkey = PublicKey::from_slice(
			&Vec::<u8>::from_hex(
				"02956e6845a6f346f97c5e028c0f8ab38a76b0124fd7184deab60f682b3e657fdb",
			)
			.unwrap(),
		)
		.unwrap();
		let key_agg_ctx = SimpleTaprootKeyAggContext::for_funding_keys(
			local_funding_pubkey,
			remote_funding_pubkey,
		);
		let script_pubkey = key_agg_ctx.bip86_funding_script_pubkey(&secp_ctx).unwrap();
		assert_eq!(
			script_pubkey.as_bytes(),
			&Vec::<u8>::from_hex(
				"5120d0ebb4909d563a7ae1213fddede4ae54132fba0ef0b97ee3f8469191fecd348e",
			)
			.unwrap()[..]
		);
	}

	#[cfg(feature = "simple_taproot_musig2")]
	#[test]
	fn verifies_lnd_taproot_commitment_partial_signature_vector() {
		let local_funding_pubkey =
			pubkey_from_hex("03b7203dec7c13896b6ff1f58b24f84458c441720a12b5a57426397e22f0a8c78b");
		let remote_funding_pubkey =
			pubkey_from_hex("02956e6845a6f346f97c5e028c0f8ab38a76b0124fd7184deab60f682b3e657fdb");
		let key_agg_ctx = SimpleTaprootKeyAggContext::for_funding_keys(
			local_funding_pubkey,
			remote_funding_pubkey,
		);
		let local_nonce = Musig2PublicNonce::from_slice(
			&Vec::<u8>::from_hex(
				"025f2272ea289c5fe9d52d411f5a50a6d4882341bf0ecb201d5675850a2ba0b09d025bc489cf67752134ba81f8d7f1146d7455baf3190de75a6a661e2405212991a9",
			)
			.unwrap(),
		)
		.unwrap();
		let remote_nonce = Musig2PublicNonce::from_slice(
			&Vec::<u8>::from_hex(
				"02d324627074522af8cf4287caf1e073a3493550b99aed2697e58f476ec402e272039c25fc616207e15917b7145cefcb4c9c702580baf255597d2fa115564a74a130",
			)
			.unwrap(),
		)
		.unwrap();
		let remote_partial = SimpleTaprootPartialSignature::from_bytes(
			Vec::<u8>::from_hex("3fa93659d4c2d590eadbd422595a37597ed58607e026a91f4e6e19329134a931")
				.unwrap()
				.try_into()
				.unwrap(),
		);
		let commitment_tx: Transaction = bitcoin::consensus::encode::deserialize(
			&Vec::<u8>::from_hex(
				"020000000001015474cba49124ab0c4327c244bb2907059585c4af3fa5f3469701534120fec0170000000000c5fe1780044a010000000000002251201249c50576fdf914caa14f9221370b986df520bdbc73f57d5056a86ee03e5ac44a01000000000000225120f67ab012701705f3203d132f909a6810ef18c5da4c11d986cb50818803b8344ec0c62d00000000002251203609bb705034e5629aa6ec05c5ca906ac89ac08b34c4583c259521ec3017440874946a00000000002251203e1fcbbd06c8a7414704612c72be9834a75d86ed85b29f0ef0c52e1950afaff30140a4a9eb512a2f4094efdd2c566f1f20cc8a6e2c307a4a44cc3f9fea7fa147dd7038f1b048aa43fa0b4009175c1c37c37b96c01058541f9e1b61110fce4e831d9f55dc1920",
			)
			.unwrap()
			.as_slice(),
		)
		.unwrap();
		let funding_output = TxOut {
			value: Amount::from_sat(10_000_000),
			script_pubkey: ScriptBuf::from_bytes(
				Vec::<u8>::from_hex(
					"5120d0ebb4909d563a7ae1213fddede4ae54132fba0ef0b97ee3f8469191fecd348e",
				)
				.unwrap(),
			),
		};
		let prevouts = [funding_output];
		let prevouts = sighash::Prevouts::All(&prevouts);
		let message = sighash::SighashCache::new(&commitment_tx)
			.taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default)
			.unwrap()
			.to_byte_array();
		key_agg_ctx
			.verify_partial(
				&remote_funding_pubkey,
				&remote_nonce,
				&remote_partial,
				&[local_nonce, remote_nonce],
				&message,
			)
			.unwrap();
	}

	#[cfg(feature = "simple_taproot_musig2")]
	fn pubkey_from_hex(hex: &str) -> PublicKey {
		PublicKey::from_slice(&Vec::<u8>::from_hex(hex).unwrap()).unwrap()
	}

	#[cfg(feature = "simple_taproot_musig2")]
	fn assert_script_hex(script: &ScriptBuf, expected_hex: &str) {
		assert_eq!(script.to_hex_string(), expected_hex);
	}

	#[cfg(feature = "simple_taproot_musig2")]
	fn assert_leaf_hash(script: &ScriptBuf, expected_hex: &str) {
		assert_eq!(
			TapLeafHash::from_script(script, LeafVersion::TapScript).to_byte_array(),
			hash_from_hex(expected_hex)
		);
	}

	#[cfg(feature = "simple_taproot_musig2")]
	fn hash_from_hex(hex: &str) -> [u8; 32] {
		Vec::<u8>::from_hex(hex).unwrap().try_into().unwrap()
	}

	#[cfg(feature = "simple_taproot_musig2")]
	#[test]
	fn commitment_output_scripts_match_lnd_staging_overlay_vectors() {
		let secp_ctx = Secp256k1::new();
		let local_delayed_pubkey =
			pubkey_from_hex("0315ec0138eb42f1ab4603042123988d53c854e89d1d87aa4dbb97a57482029c05");
		let revocation_pubkey =
			pubkey_from_hex("03d4c77088d346bce67c13bbbf82ca112588f4b1c9595a1f8af3be9b2f95a109a0");
		let remote_payment_pubkey =
			pubkey_from_hex("03595f2ef2a51d2250a21077dbea4a7fc3ce550f10676996bf63719e2a71d1f4c9");

		let to_local = simple_taproot_to_local_spend_info(
			&secp_ctx,
			&local_delayed_pubkey,
			&revocation_pubkey,
			144,
		)
		.unwrap();
		assert_script_hex(
			&to_local.revocation.script,
			"2015ec0138eb42f1ab4603042123988d53c854e89d1d87aa4dbb97a57482029c057520d4c77088d346bce67c13bbbf82ca112588f4b1c9595a1f8af3be9b2f95a109a0ac",
		);
		assert_leaf_hash(
			&to_local.revocation.script,
			"8fcd64d212bbbf1bcec2360bbf229963240d05992fc2efb482fe6dca85b9469a",
		);
		assert_script_hex(
			&to_local.delay.script,
			"2015ec0138eb42f1ab4603042123988d53c854e89d1d87aa4dbb97a57482029c05ac029000b275",
		);
		assert_leaf_hash(
			&to_local.delay.script,
			"c8fdbfe551448cc7a8b825a713e7c3af0e0776db6f77b0a911c1da8443e167cc",
		);
		assert_eq!(
			to_local.tapscript_root,
			hash_from_hex("3727872ab504288d1c0608abadfa0e4cf4a7bda51f0314473115f10e0e41e285")
		);
		assert_script_hex(
			&to_local.script_pubkey,
			"51207b49ec6082e5fe6cd59ab23ab3030a918928dab1e3ea202b5c0faba770a830bf",
		);
		assert_eq!(to_local.delay.control_block.len(), 65);
		assert_eq!(to_local.revocation.control_block.len(), 65);
		assert_ne!(to_local.tap_tweak, [0; 32]);

		let to_remote =
			simple_taproot_to_remote_spend_info(&secp_ctx, &remote_payment_pubkey).unwrap();
		assert_script_hex(
			&to_remote.spend.script,
			"20595f2ef2a51d2250a21077dbea4a7fc3ce550f10676996bf63719e2a71d1f4c9ac51b275",
		);
		assert_leaf_hash(
			&to_remote.spend.script,
			"657f34b36707dae72b379e576c6b888c15df491a400a0bcd8eda4731771385b9",
		);
		assert_eq!(
			to_remote.tapscript_root,
			hash_from_hex("657f34b36707dae72b379e576c6b888c15df491a400a0bcd8eda4731771385b9")
		);
		assert_script_hex(
			&to_remote.script_pubkey,
			"51206b1a8421cb92be16a6a754426d4a6df8bfb7e2cd16d07c654039294a1df7328b",
		);
		assert_eq!(to_remote.spend.control_block.len(), 33);
		assert_ne!(to_remote.tap_tweak, [0; 32]);

		let local_anchor =
			simple_taproot_anchor_spend_info(&secp_ctx, &local_delayed_pubkey).unwrap();
		assert_script_hex(&local_anchor.spend.script, "60b2");
		assert_leaf_hash(
			&local_anchor.spend.script,
			"2b88a8f3f52386d61d5b3f2d822df659c35214d7360ed05352ad7ddc1ab03912",
		);
		assert_eq!(
			local_anchor.tapscript_root,
			hash_from_hex("2b88a8f3f52386d61d5b3f2d822df659c35214d7360ed05352ad7ddc1ab03912")
		);
		assert_script_hex(
			&local_anchor.script_pubkey,
			"5120f67ab012701705f3203d132f909a6810ef18c5da4c11d986cb50818803b8344e",
		);
		assert_eq!(local_anchor.spend.control_block.len(), 33);
		assert_ne!(local_anchor.tap_tweak, [0; 32]);

		let remote_anchor =
			simple_taproot_anchor_spend_info(&secp_ctx, &remote_payment_pubkey).unwrap();
		assert_script_hex(
			&remote_anchor.script_pubkey,
			"51201249c50576fdf914caa14f9221370b986df520bdbc73f57d5056a86ee03e5ac4",
		);
	}

	#[cfg(feature = "simple_taproot_musig2")]
	#[test]
	fn commitment_output_scripts_accept_taproot_asset_aux_leaves() {
		let secp_ctx = Secp256k1::new();
		let local_delayed_pubkey =
			pubkey_from_hex("0315ec0138eb42f1ab4603042123988d53c854e89d1d87aa4dbb97a57482029c05");
		let revocation_pubkey =
			pubkey_from_hex("03d4c77088d346bce67c13bbbf82ca112588f4b1c9595a1f8af3be9b2f95a109a0");
		let remote_payment_pubkey =
			pubkey_from_hex("03595f2ef2a51d2250a21077dbea4a7fc3ce550f10676996bf63719e2a71d1f4c9");
		let aux_leaf = ScriptBuf::from(
			Vec::<u8>::from_hex(
				"6a47e8543f2ab163faf693971a653e54efe3d8056c52164c6b8bbf597b6ddb280217dbbe364ce4e17da32f1d0ce6f4c4befc50d3d791fa0f00183b286e9f33de89000000000000007d",
			)
			.unwrap(),
		);

		let base_to_remote =
			simple_taproot_to_remote_spend_info(&secp_ctx, &remote_payment_pubkey).unwrap();
		let asset_to_remote = simple_taproot_to_remote_spend_info_with_aux_leaf(
			&secp_ctx,
			&remote_payment_pubkey,
			Some(aux_leaf.as_script()),
		)
		.unwrap();
		assert_ne!(base_to_remote.script_pubkey, asset_to_remote.script_pubkey);
		assert_ne!(base_to_remote.tapscript_root, asset_to_remote.tapscript_root);
		assert_eq!(asset_to_remote.spend.control_block.len(), 65);

		let base_to_local = simple_taproot_to_local_spend_info(
			&secp_ctx,
			&local_delayed_pubkey,
			&revocation_pubkey,
			144,
		)
		.unwrap();
		let asset_to_local = simple_taproot_to_local_spend_info_with_aux_leaf(
			&secp_ctx,
			&local_delayed_pubkey,
			&revocation_pubkey,
			144,
			Some(aux_leaf.as_script()),
		)
		.unwrap();
		assert_ne!(base_to_local.script_pubkey, asset_to_local.script_pubkey);
		assert_ne!(base_to_local.tapscript_root, asset_to_local.tapscript_root);
		assert_eq!(asset_to_local.delay.control_block.len(), 97);
		assert_eq!(asset_to_local.revocation.control_block.len(), 97);
	}

	#[cfg(feature = "simple_taproot_musig2")]
	#[test]
	fn taproot_asset_to_local_script_matches_litd_initial_commitment_vector() {
		let secp_ctx = Secp256k1::new();
		let local_delayed_pubkey =
			pubkey_from_hex("02d74d7a2695a4343b85021736266c14002a924c3058365171b2fd479c2dbcadb8");
		let revocation_pubkey =
			pubkey_from_hex("02dfcf93bab0607db26e9e36767b2ed6266ed6de09c63dff939143168cc0c758e9");
		let aux_leaf = ScriptBuf::from(
			Vec::<u8>::from_hex(
				"6a47e8543f2ab163faf693971a653e54efe3d8056c52164c6b8bbf597b6ddb28020d752aed73081a6ebdaf454038debcec162e8820eb260ef5e7d6138eb3500d28000000000000007d",
			)
			.unwrap(),
		);

		let base_to_local = simple_taproot_to_local_spend_info(
			&secp_ctx,
			&local_delayed_pubkey,
			&revocation_pubkey,
			0,
		)
		.unwrap();
		assert_script_hex(
			&base_to_local.script_pubkey,
			"5120cbbd4b8a6d3d8a3f38133b48aae35593005f6129f368f55c4508fef703c95870",
		);

		let zero_csv_asset_to_local = simple_taproot_to_local_spend_info_with_aux_leaf(
			&secp_ctx,
			&local_delayed_pubkey,
			&revocation_pubkey,
			0,
			Some(aux_leaf.as_script()),
		)
		.unwrap();
		assert_script_hex(
			&zero_csv_asset_to_local.script_pubkey,
			"5120c7ae498ef02eaa3141f73042eb21640ea6b659cd2d49244b395fda273a49795d",
		);

		let asset_to_local = simple_taproot_to_local_spend_info_with_aux_leaf(
			&secp_ctx,
			&local_delayed_pubkey,
			&revocation_pubkey,
			144,
			Some(aux_leaf.as_script()),
		)
		.unwrap();
		assert_script_hex(
			&asset_to_local.script_pubkey,
			"51205c4d17a56be11d9403abc370ba104ecbdfcc7e6b9f6f4042de09a0d038f9b921",
		);
	}

	#[cfg(feature = "simple_taproot_musig2")]
	#[test]
	fn htlc_and_second_level_scripts_match_bolt_vectors() {
		let secp_ctx = Secp256k1::new();
		let local_delayed_pubkey =
			pubkey_from_hex("0315ec0138eb42f1ab4603042123988d53c854e89d1d87aa4dbb97a57482029c05");
		let revocation_pubkey =
			pubkey_from_hex("03d4c77088d346bce67c13bbbf82ca112588f4b1c9595a1f8af3be9b2f95a109a0");
		let local_htlc_pubkey =
			pubkey_from_hex("0271e82ef65d5c667159036bfcf662cac2f6c41e38323d148bbbd00fdcd923739e");
		let remote_htlc_pubkey =
			pubkey_from_hex("032deba21cf03c42362c9f912094f62ba045a040a2060882ba1ed3abf1f664a47d");
		let payment_hash = PaymentHash(Sha256::hash(&[0; 32]).to_byte_array());

		let offered = simple_taproot_htlc_spend_info(
			&secp_ctx,
			true,
			&payment_hash,
			500,
			&local_htlc_pubkey,
			&remote_htlc_pubkey,
			&revocation_pubkey,
		)
		.unwrap();
		assert_script_hex(
			&offered.success.script,
			"82012088a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688202deba21cf03c42362c9f912094f62ba045a040a2060882ba1ed3abf1f664a47dad51b2",
		);
		assert_leaf_hash(
			&offered.success.script,
			"cd4b7ba74d132998f2bcea85f76082f5018e614c86f27f2631b6569c4914320f",
		);
		assert_script_hex(
			&offered.timeout.script,
			"2071e82ef65d5c667159036bfcf662cac2f6c41e38323d148bbbd00fdcd923739ead202deba21cf03c42362c9f912094f62ba045a040a2060882ba1ed3abf1f664a47dac",
		);
		assert_leaf_hash(
			&offered.timeout.script,
			"dd0bd08b3df902c399f5493a682f6c50c476c89e233ba454e89a234d2d16ffe3",
		);
		assert_eq!(
			offered.tapscript_root,
			hash_from_hex("f36c8bd45002c5264cfce9944211e7bc6ea974a6b90cf99a87812d18acf28a2a")
		);
		assert_script_hex(
			&offered.script_pubkey,
			"51203e5c3be9f4ce7ae07c28ad5e0eb0ab617c06eeb82b8d6ef10a5bf561848df5f0",
		);
		assert_eq!(offered.success.control_block.len(), 65);
		assert_eq!(offered.timeout.control_block.len(), 65);
		assert_ne!(offered.tap_tweak, [0; 32]);

		let accepted = simple_taproot_htlc_spend_info(
			&secp_ctx,
			false,
			&payment_hash,
			500,
			&local_htlc_pubkey,
			&remote_htlc_pubkey,
			&revocation_pubkey,
		)
		.unwrap();
		assert_script_hex(
			&accepted.success.script,
			"82012088a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688202deba21cf03c42362c9f912094f62ba045a040a2060882ba1ed3abf1f664a47dad2071e82ef65d5c667159036bfcf662cac2f6c41e38323d148bbbd00fdcd923739eac",
		);
		assert_leaf_hash(
			&accepted.success.script,
			"69192ca730d4480044ade8741b8bd0845a32880aebaf58bc6f9186f8d2be8cbf",
		);
		assert_script_hex(
			&accepted.timeout.script,
			"2071e82ef65d5c667159036bfcf662cac2f6c41e38323d148bbbd00fdcd923739ead51b26902f401b1",
		);
		assert_leaf_hash(
			&accepted.timeout.script,
			"4da43c795365bf757ed1e9656d12ea744b4cf52b01719a3ea94e6569115623f0",
		);
		assert_eq!(
			accepted.tapscript_root,
			hash_from_hex("1a990caa4bb0ed41ceb19e7466fcea5d9b31e3da968f348f6223201c5831d0a3")
		);
		assert_script_hex(
			&accepted.script_pubkey,
			"51209aadbdd9aff986e5ea086cf53ae062972d33d0a5c7f5fb986dafec7fa6d7e6ea",
		);
		assert_eq!(accepted.success.control_block.len(), 65);
		assert_eq!(accepted.timeout.control_block.len(), 65);
		assert_ne!(accepted.tap_tweak, [0; 32]);

		let second_level = simple_taproot_second_level_htlc_spend_info(
			&secp_ctx,
			&local_delayed_pubkey,
			&revocation_pubkey,
			144,
		)
		.unwrap();
		assert_script_hex(
			&second_level.spend.script,
			"2015ec0138eb42f1ab4603042123988d53c854e89d1d87aa4dbb97a57482029c05ac029000b275",
		);
		assert_leaf_hash(
			&second_level.spend.script,
			"c8fdbfe551448cc7a8b825a713e7c3af0e0776db6f77b0a911c1da8443e167cc",
		);
		assert_eq!(
			second_level.tapscript_root,
			hash_from_hex("c8fdbfe551448cc7a8b825a713e7c3af0e0776db6f77b0a911c1da8443e167cc")
		);
		assert_script_hex(
			&second_level.script_pubkey,
			"51205cf3964a0c10272a8fb62e9e1b87afb712265641eb89462f2df18cf1f43cf0c3",
		);
		assert_eq!(second_level.spend.control_block.len(), 33);
		assert_ne!(second_level.tap_tweak, [0; 32]);
	}

	#[cfg(feature = "simple_taproot_musig2")]
	#[test]
	fn htlc_second_level_spends_sign_and_build_witnesses() {
		let secp_ctx = Secp256k1::new();
		let local_secret = SecretKey::from_slice(&[2; 32]).unwrap();
		let remote_secret = SecretKey::from_slice(&[3; 32]).unwrap();
		let revocation_secret = SecretKey::from_slice(&[4; 32]).unwrap();
		let delayed_secret = SecretKey::from_slice(&[5; 32]).unwrap();
		let local_htlc_pubkey = PublicKey::from_secret_key(&secp_ctx, &local_secret);
		let remote_htlc_pubkey = PublicKey::from_secret_key(&secp_ctx, &remote_secret);
		let revocation_pubkey = PublicKey::from_secret_key(&secp_ctx, &revocation_secret);
		let delayed_pubkey = PublicKey::from_secret_key(&secp_ctx, &delayed_secret);
		let preimage = [42; 32];
		let payment_hash = PaymentHash(Sha256::hash(&preimage).to_byte_array());
		let commitment_txid = Txid::from_slice(&[7; 32]).unwrap();
		let aux_rand = [0; 32];

		let offered = simple_taproot_htlc_spend_info(
			&secp_ctx,
			true,
			&payment_hash,
			500,
			&local_htlc_pubkey,
			&remote_htlc_pubkey,
			&revocation_pubkey,
		)
		.unwrap();
		let second_level = simple_taproot_second_level_htlc_spend_info(
			&secp_ctx,
			&delayed_pubkey,
			&revocation_pubkey,
			144,
		)
		.unwrap();
		let timeout_tx = Transaction {
			version: bitcoin::transaction::Version::TWO,
			lock_time: bitcoin::absolute::LockTime::from_consensus(500),
			input: vec![bitcoin::TxIn {
				previous_output: bitcoin::OutPoint { txid: commitment_txid, vout: 0 },
				script_sig: ScriptBuf::new(),
				sequence: bitcoin::Sequence(1),
				witness: Witness::new(),
			}],
			output: vec![TxOut {
				value: Amount::from_sat(50_000),
				script_pubkey: second_level.script_pubkey.clone(),
			}],
		};
		let signed_timeout = simple_taproot_sign_htlc_spend(
			&secp_ctx,
			&timeout_tx,
			0,
			Amount::from_sat(50_000),
			&offered,
			&offered.timeout,
			SimpleTaprootHtlcSpendPath::OfferedTimeout,
			Some(&local_secret),
			Some(&remote_secret),
			None,
			&aux_rand,
		)
		.unwrap();
		assert_ne!(signed_timeout.sighash, [0; 32]);
		assert_eq!(signed_timeout.witness.len(), 4);
		let local_timeout_signature = signed_timeout.local_signature.as_ref().unwrap().to_vec();
		let remote_timeout_signature = signed_timeout.remote_signature.as_ref().unwrap().to_vec();
		assert_eq!(local_timeout_signature.len(), 65);
		assert_eq!(remote_timeout_signature.len(), 65);
		assert_eq!(&signed_timeout.witness[0], remote_timeout_signature.as_slice());
		assert_eq!(&signed_timeout.witness[1], local_timeout_signature.as_slice());

		let accepted = simple_taproot_htlc_spend_info(
			&secp_ctx,
			false,
			&payment_hash,
			500,
			&local_htlc_pubkey,
			&remote_htlc_pubkey,
			&revocation_pubkey,
		)
		.unwrap();
		let signed_accepted_timeout = simple_taproot_sign_htlc_spend(
			&secp_ctx,
			&timeout_tx,
			0,
			Amount::from_sat(50_000),
			&accepted,
			&accepted.timeout,
			SimpleTaprootHtlcSpendPath::AcceptedTimeout,
			Some(&local_secret),
			None,
			None,
			&aux_rand,
		)
		.unwrap();
		assert_eq!(signed_accepted_timeout.witness.len(), 3);
		let local_accepted_timeout_signature =
			signed_accepted_timeout.local_signature.as_ref().unwrap().to_vec();
		assert!(signed_accepted_timeout.remote_signature.is_none());
		assert_eq!(
			&signed_accepted_timeout.witness[0],
			local_accepted_timeout_signature.as_slice()
		);

		let success_tx = Transaction {
			version: bitcoin::transaction::Version::TWO,
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![bitcoin::TxIn {
				previous_output: bitcoin::OutPoint { txid: commitment_txid, vout: 1 },
				script_sig: ScriptBuf::new(),
				sequence: bitcoin::Sequence(1),
				witness: Witness::new(),
			}],
			output: vec![TxOut {
				value: Amount::from_sat(50_000),
				script_pubkey: second_level.script_pubkey,
			}],
		};
		let signed_offered_success = simple_taproot_sign_htlc_spend(
			&secp_ctx,
			&success_tx,
			0,
			Amount::from_sat(50_000),
			&offered,
			&offered.success,
			SimpleTaprootHtlcSpendPath::OfferedSuccess,
			None,
			Some(&remote_secret),
			Some(&preimage),
			&aux_rand,
		)
		.unwrap();
		assert_eq!(signed_offered_success.witness.len(), 4);
		assert!(signed_offered_success.local_signature.is_none());
		let remote_offered_success_signature =
			signed_offered_success.remote_signature.as_ref().unwrap().to_vec();
		assert_eq!(&signed_offered_success.witness[0], remote_offered_success_signature.as_slice());
		assert_eq!(&signed_offered_success.witness[1], &preimage[..]);

		let signed_success = simple_taproot_sign_htlc_spend(
			&secp_ctx,
			&success_tx,
			0,
			Amount::from_sat(50_000),
			&accepted,
			&accepted.success,
			SimpleTaprootHtlcSpendPath::AcceptedSuccess,
			Some(&local_secret),
			Some(&remote_secret),
			Some(&preimage),
			&aux_rand,
		)
		.unwrap();
		assert_ne!(signed_success.sighash, [0; 32]);
		assert_eq!(signed_success.witness.len(), 5);
		let local_success_signature = signed_success.local_signature.as_ref().unwrap().to_vec();
		let remote_success_signature = signed_success.remote_signature.as_ref().unwrap().to_vec();
		assert_eq!(local_success_signature.len(), 65);
		assert_eq!(remote_success_signature.len(), 65);
		assert_eq!(&signed_success.witness[0], local_success_signature.as_slice());
		assert_eq!(&signed_success.witness[1], remote_success_signature.as_slice());
		assert_eq!(&signed_success.witness[2], &preimage[..]);
	}

	#[cfg(feature = "simple_taproot_musig2")]
	#[test]
	fn counter_and_jit_nonce_seeds_are_domain_separated() {
		let funding_txid = Txid::from_slice(&[10; 32]).unwrap();
		let commitment_use =
			SimpleTaprootNonceUse::new(funding_txid, 11, SimpleTaprootNonceScope::Commitment);
		let counterparty_commitment_use = SimpleTaprootNonceUse::new(
			funding_txid,
			11,
			SimpleTaprootNonceScope::CounterpartyCommitment,
		);
		let close_use =
			SimpleTaprootNonceUse::new(funding_txid, 11, SimpleTaprootNonceScope::CooperativeClose);
		let closee_use = SimpleTaprootNonceUse::new(
			funding_txid,
			11,
			SimpleTaprootNonceScope::CooperativeCloseClosee,
		);
		let close_both_outputs_use = SimpleTaprootNonceUse::new(
			funding_txid,
			11,
			SimpleTaprootNonceScope::CooperativeCloseCloserAndCloseeOutputs,
		);
		let force_close_use =
			SimpleTaprootNonceUse::new(funding_txid, 11, SimpleTaprootNonceScope::ForceClose);

		let commitment_seed = [12; 32];
		let commitment_nonce_seed =
			derive_simple_taproot_counter_nonce_seed(&commitment_seed, &commitment_use);
		let counterparty_commitment_nonce_seed = derive_simple_taproot_counter_nonce_seed(
			&commitment_seed,
			&counterparty_commitment_use,
		);
		let close_nonce_seed =
			derive_simple_taproot_counter_nonce_seed(&commitment_seed, &close_use);
		let closee_nonce_seed =
			derive_simple_taproot_counter_nonce_seed(&commitment_seed, &closee_use);
		let close_both_outputs_nonce_seed =
			derive_simple_taproot_counter_nonce_seed(&commitment_seed, &close_both_outputs_use);
		let force_close_nonce_seed =
			derive_simple_taproot_counter_nonce_seed(&commitment_seed, &force_close_use);
		assert_ne!(commitment_nonce_seed, counterparty_commitment_nonce_seed);
		assert_ne!(commitment_nonce_seed, close_nonce_seed);
		assert_ne!(commitment_nonce_seed, force_close_nonce_seed);
		assert_ne!(counterparty_commitment_nonce_seed, close_nonce_seed);
		assert_ne!(counterparty_commitment_nonce_seed, force_close_nonce_seed);
		assert_ne!(close_nonce_seed, force_close_nonce_seed);
		assert_ne!(close_nonce_seed, closee_nonce_seed);
		assert_ne!(closee_nonce_seed, close_both_outputs_nonce_seed);
		assert_ne!(close_both_outputs_nonce_seed, force_close_nonce_seed);

		let jit_nonce_seed = derive_simple_taproot_jit_nonce_seed(&[13; 32], &commitment_use);
		assert_ne!(commitment_nonce_seed, jit_nonce_seed);
	}
}
