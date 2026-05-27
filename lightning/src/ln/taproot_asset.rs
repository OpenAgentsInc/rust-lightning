// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! OpenAgentsInc experimental Taproot Asset channel negotiation helpers.
//!
//! This module intentionally handles only the explicit feature and channel-type
//! gate for single-asset Taproot Asset channels. The funding, monitor, and
//! HTLC helpers below are deliberately bounded integration surfaces that let
//! `tap-ldk` wire asset-channel state into LDK without changing BTC-only
//! behavior.

use crate::chain::transaction::OutPoint;
use crate::io::{Cursor, Read};
use crate::ln::types::ChannelId;
use crate::util::ser::{BigSize, Readable};

use bitcoin::hashes::{sha256::Hash as Sha256, Hash as _, HashEngine as _};
use bitcoin::secp256k1::PublicKey;
use lightning_types::features::{ChannelTypeFeatures, InitFeatures};

/// The only Taproot Asset channel protocol version accepted by this
/// experimental fork surface.
pub const SUPPORTED_TAPROOT_ASSET_CHANNEL_PROTOCOL_VERSION: u16 = 1;

/// The byte length of a Taproot Asset ID.
pub const TAPROOT_ASSET_ID_LEN: usize = 32;

/// The schema version for Taproot Asset monitor aux blobs.
pub const TAPROOT_ASSET_MONITOR_AUX_BLOB_SCHEMA_VERSION: u16 = 1;

/// The protocol version for Taproot Asset HTLC metadata.
pub const TAPROOT_ASSET_HTLC_METADATA_PROTOCOL_VERSION: u16 =
	SUPPORTED_TAPROOT_ASSET_CHANNEL_PROTOCOL_VERSION;

/// Asset proof ownership is attached to the commitment transaction spend path.
pub const TAPROOT_ASSET_RECOVERY_SPEND_COMMITMENT: u8 = 1;
/// Asset proof ownership is attached to a second-level HTLC spend path.
pub const TAPROOT_ASSET_RECOVERY_SPEND_SECOND_LEVEL_HTLC: u8 = 2;
/// Asset proof ownership is attached to the final wallet sweep output.
pub const TAPROOT_ASSET_RECOVERY_SPEND_FINAL_SWEEP: u8 = 3;

const TAPROOT_ASSET_HTLC_BLOB_ASSET_ID_RECORD_TYPE: u64 = 0;
const TAPROOT_ASSET_HTLC_BLOB_AMOUNT_RECORD_TYPE: u64 = 1;
const TAPROOT_ASSET_HTLC_BLOB_OUTER_RECORD_TYPE: u64 = 1;

/// Describes the single asset that an experimental Taproot Asset channel is
/// allowed to carry.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaprootAssetChannelDescriptor {
	asset_id: [u8; TAPROOT_ASSET_ID_LEN],
	protocol_version: u16,
}

impl TaprootAssetChannelDescriptor {
	/// Builds a descriptor for a single-asset Taproot Asset channel.
	pub fn new(
		asset_id: [u8; TAPROOT_ASSET_ID_LEN], protocol_version: u16,
	) -> Result<Self, TaprootAssetChannelNegotiationError> {
		if asset_id == [0; TAPROOT_ASSET_ID_LEN] {
			return Err(TaprootAssetChannelNegotiationError::MalformedAssetId);
		}
		if protocol_version != SUPPORTED_TAPROOT_ASSET_CHANNEL_PROTOCOL_VERSION {
			return Err(TaprootAssetChannelNegotiationError::UnsupportedProtocolVersion);
		}
		Ok(Self { asset_id, protocol_version })
	}

	/// Returns the asset ID bound to this channel descriptor.
	pub fn asset_id(&self) -> &[u8; TAPROOT_ASSET_ID_LEN] {
		&self.asset_id
	}

	/// Returns the protocol version bound to this channel descriptor.
	pub fn protocol_version(&self) -> u16 {
		self.protocol_version
	}
}

/// The result of a successful experimental Taproot Asset channel negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaprootAssetChannelNegotiation {
	/// The single-asset descriptor supplied by the caller.
	pub descriptor: TaprootAssetChannelDescriptor,
	/// The channel type that must be used in `open_channel`/`accept_channel`.
	pub channel_type: ChannelTypeFeatures,
}

/// The Taproot Asset proof/root material supplied before an asset-channel
/// funding transition is allowed to advance.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaprootAssetFundingProofMaterial {
	/// The asset ID resolved from the funding proof set.
	pub asset_id: [u8; TAPROOT_ASSET_ID_LEN],
	/// The expected genesis identity for the funded asset.
	pub genesis_id: [u8; TAPROOT_ASSET_ID_LEN],
	/// The expected group key, when the asset belongs to a grouped issuance.
	pub group_key: Option<[u8; TAPROOT_ASSET_ID_LEN]>,
	/// The proof root hash reconstructed from the proof fragments.
	pub proof_root_hash: [u8; TAPROOT_ASSET_ID_LEN],
	/// The proof root sum reconstructed from the proof fragments.
	pub proof_root_sum: u64,
	/// Number of proof fragments reconstructed by the caller.
	pub complete_fragment_count: u16,
	/// Number of proof fragments required for this funding flow.
	pub expected_fragment_count: u16,
}

/// The Taproot Asset funding output material supplied by the funding
/// controller.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaprootAssetFundingOutput {
	/// The Bitcoin funding output that backs the channel.
	pub outpoint: OutPoint,
	/// The asset ID committed in the funding output.
	pub asset_id: [u8; TAPROOT_ASSET_ID_LEN],
	/// The Taproot Asset root hash committed by the funding output.
	pub taproot_asset_root_hash: [u8; TAPROOT_ASSET_ID_LEN],
	/// The Taproot Asset root sum committed by the funding output.
	pub taproot_asset_root_sum: u64,
	/// The caller's digest of the full output commitment.
	pub output_commitment: [u8; TAPROOT_ASSET_ID_LEN],
}

/// The expected asset identity and commitment values for a funding attempt.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaprootAssetFundingExpectations {
	/// The single asset this channel is allowed to fund.
	pub asset_id: [u8; TAPROOT_ASSET_ID_LEN],
	/// The expected genesis identity for the funded asset.
	pub genesis_id: [u8; TAPROOT_ASSET_ID_LEN],
	/// The expected group key, if the asset is grouped.
	pub group_key: Option<[u8; TAPROOT_ASSET_ID_LEN]>,
	/// The expected proof root hash after fragment reconstruction.
	pub proof_root_hash: [u8; TAPROOT_ASSET_ID_LEN],
	/// The expected funding output commitment digest.
	pub output_commitment: [u8; TAPROOT_ASSET_ID_LEN],
	/// The exact asset amount that must be allocated into the channel.
	pub total_amount: u64,
}

/// The local and remote asset allocation for the funded channel.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaprootAssetFundingAllocation {
	/// Amount allocated to the local node.
	pub local_amount: u64,
	/// Amount allocated to the remote node.
	pub remote_amount: u64,
}

/// A bounded asset-channel funding request. Callers must validate this before
/// advancing from funding negotiation into durable channel state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaprootAssetFundingRequest {
	/// The pending channel ID before the funding outpoint-derived channel ID is
	/// known.
	pub pending_channel_id: ChannelId,
	/// The negotiated single-asset channel descriptor.
	pub descriptor: TaprootAssetChannelDescriptor,
	/// The expected funding outpoint for this funding flow.
	pub funding_outpoint: OutPoint,
	/// The local node identity participating in the asset channel.
	pub local_peer_id: PublicKey,
	/// The remote node identity participating in the asset channel.
	pub remote_peer_id: PublicKey,
	/// Proof material reconstructed from Taproot Asset funding messages.
	pub proof_material: TaprootAssetFundingProofMaterial,
	/// Funding output commitment material.
	pub funding_output: TaprootAssetFundingOutput,
	/// Expected asset identity, root, output commitment, and total amount.
	pub expectations: TaprootAssetFundingExpectations,
	/// Local/remote asset allocation.
	pub allocation: TaprootAssetFundingAllocation,
}

/// Approval returned after the asset funding request passes the bounded
/// controller checks.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaprootAssetFundingApproval {
	/// The pending channel ID that was approved.
	pub pending_channel_id: ChannelId,
	/// The eventual funding outpoint.
	pub funding_outpoint: OutPoint,
	/// The asset ID funded by the channel.
	pub asset_id: [u8; TAPROOT_ASSET_ID_LEN],
	/// The approved total asset amount.
	pub total_amount: u64,
}

/// Metadata carried with an asset-channel HTLC.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaprootAssetHtlcMetadata {
	/// Taproot Asset channel protocol version for this metadata.
	pub protocol_version: u16,
	/// Asset ID being transferred.
	pub asset_id: [u8; TAPROOT_ASSET_ID_LEN],
	/// Asset amount being transferred.
	pub asset_amount: u64,
	/// Taproot Asset proof/root reference hash.
	pub proof_root_hash: [u8; TAPROOT_ASSET_ID_LEN],
	/// Taproot Asset proof/root sum.
	pub proof_root_sum: u64,
	/// Quote ID authorizing this asset HTLC.
	pub quote_id: [u8; TAPROOT_ASSET_ID_LEN],
	/// Payment hash for the final-hop payment.
	pub payment_hash: [u8; TAPROOT_ASSET_ID_LEN],
	/// Integrity digest over the final-hop asset metadata.
	pub final_hop_digest: [u8; TAPROOT_ASSET_ID_LEN],
}

/// The asset identity and amount decoded from a Lightning Labs Taproot Asset
/// HTLC blob carried on `update_add_htlc`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaprootAssetHtlcBlob {
	/// Asset ID being transferred.
	pub asset_id: [u8; TAPROOT_ASSET_ID_LEN],
	/// Asset amount being transferred.
	pub asset_amount: u64,
}

impl TaprootAssetHtlcMetadata {
	/// Builds protocol-versioned asset HTLC metadata.
	pub fn new(
		asset_id: [u8; TAPROOT_ASSET_ID_LEN], asset_amount: u64,
		proof_root_hash: [u8; TAPROOT_ASSET_ID_LEN], proof_root_sum: u64,
		quote_id: [u8; TAPROOT_ASSET_ID_LEN], payment_hash: [u8; TAPROOT_ASSET_ID_LEN],
	) -> Result<Self, TaprootAssetHtlcMetadataError> {
		let mut metadata = Self {
			protocol_version: TAPROOT_ASSET_HTLC_METADATA_PROTOCOL_VERSION,
			asset_id,
			asset_amount,
			proof_root_hash,
			proof_root_sum,
			quote_id,
			payment_hash,
			final_hop_digest: [0; TAPROOT_ASSET_ID_LEN],
		};
		metadata.final_hop_digest = metadata.digest();
		metadata.validate_integrity()?;
		Ok(metadata)
	}

	/// Recomputes the final-hop metadata digest.
	pub fn digest(&self) -> [u8; TAPROOT_ASSET_ID_LEN] {
		let mut engine = Sha256::engine();
		engine.input(b"openagents:taproot-asset-htlc-final-hop:v1");
		engine.input(&self.protocol_version.to_be_bytes());
		engine.input(&self.asset_id);
		engine.input(&self.asset_amount.to_be_bytes());
		engine.input(&self.proof_root_hash);
		engine.input(&self.proof_root_sum.to_be_bytes());
		engine.input(&self.quote_id);
		engine.input(&self.payment_hash);
		Sha256::from_engine(engine).to_byte_array()
	}

	/// Checks the metadata's internal integrity before a caller compares it to
	/// an expected quote/payment.
	pub fn validate_integrity(&self) -> Result<(), TaprootAssetHtlcMetadataError> {
		if self.protocol_version != TAPROOT_ASSET_HTLC_METADATA_PROTOCOL_VERSION {
			return Err(TaprootAssetHtlcMetadataError::UnsupportedProtocolVersion);
		}
		if self.asset_id == [0; TAPROOT_ASSET_ID_LEN]
			|| self.asset_amount == 0
			|| self.proof_root_hash == [0; TAPROOT_ASSET_ID_LEN]
			|| self.proof_root_sum == 0
			|| self.proof_root_sum < self.asset_amount
			|| self.quote_id == [0; TAPROOT_ASSET_ID_LEN]
			|| self.payment_hash == [0; TAPROOT_ASSET_ID_LEN]
		{
			return Err(TaprootAssetHtlcMetadataError::MalformedMetadata);
		}
		if self.final_hop_digest != self.digest() {
			return Err(TaprootAssetHtlcMetadataError::FinalHopDigestMismatch);
		}
		Ok(())
	}
}

fn read_taproot_asset_blob_bigsize(
	cursor: &mut Cursor<&[u8]>,
) -> Result<u64, TaprootAssetHtlcBlobError> {
	BigSize::read(cursor)
		.map(|big_size| big_size.0)
		.map_err(|_| TaprootAssetHtlcBlobError::MalformedTlv)
}

fn taproot_asset_htlc_blob_outer_value<'a>(
	payload: &'a [u8],
) -> Result<Option<&'a [u8]>, TaprootAssetHtlcBlobError> {
	let mut cursor = Cursor::new(payload);
	let record_type = read_taproot_asset_blob_bigsize(&mut cursor)?;
	let record_len = read_taproot_asset_blob_bigsize(&mut cursor)?;
	if record_type != TAPROOT_ASSET_HTLC_BLOB_OUTER_RECORD_TYPE || record_len == 8 {
		return Ok(None);
	}

	let start = cursor.position() as usize;
	let len = usize::try_from(record_len).map_err(|_| TaprootAssetHtlcBlobError::MalformedTlv)?;
	let end = start.checked_add(len).ok_or(TaprootAssetHtlcBlobError::MalformedTlv)?;
	if end != payload.len() {
		return Err(TaprootAssetHtlcBlobError::MalformedTlv);
	}
	Ok(Some(&payload[start..end]))
}

fn decode_taproot_asset_htlc_blob_records(
	payload: &[u8],
) -> Result<TaprootAssetHtlcBlob, TaprootAssetHtlcBlobError> {
	let mut cursor = Cursor::new(payload);
	let mut previous_record_type = None;
	let mut asset_id = None;
	let mut asset_amount = None;

	while (cursor.position() as usize) < payload.len() {
		let record_type = read_taproot_asset_blob_bigsize(&mut cursor)?;
		if previous_record_type.map(|previous| record_type <= previous).unwrap_or(false) {
			return Err(TaprootAssetHtlcBlobError::MalformedTlv);
		}
		previous_record_type = Some(record_type);

		let record_len = read_taproot_asset_blob_bigsize(&mut cursor)?;
		let start = cursor.position() as usize;
		let len =
			usize::try_from(record_len).map_err(|_| TaprootAssetHtlcBlobError::MalformedTlv)?;
		let end = start.checked_add(len).ok_or(TaprootAssetHtlcBlobError::MalformedTlv)?;
		if end > payload.len() {
			return Err(TaprootAssetHtlcBlobError::MalformedTlv);
		}

		match record_type {
			TAPROOT_ASSET_HTLC_BLOB_ASSET_ID_RECORD_TYPE => {
				if asset_id.is_some() {
					return Err(TaprootAssetHtlcBlobError::DuplicateField);
				}
				if len != TAPROOT_ASSET_ID_LEN {
					return Err(TaprootAssetHtlcBlobError::MalformedAssetId);
				}
				let mut decoded_asset_id = [0; TAPROOT_ASSET_ID_LEN];
				cursor
					.read_exact(&mut decoded_asset_id)
					.map_err(|_| TaprootAssetHtlcBlobError::MalformedTlv)?;
				asset_id = Some(decoded_asset_id);
			},
			TAPROOT_ASSET_HTLC_BLOB_AMOUNT_RECORD_TYPE => {
				if asset_amount.is_some() {
					return Err(TaprootAssetHtlcBlobError::DuplicateField);
				}
				if len != 8 {
					return Err(TaprootAssetHtlcBlobError::MalformedAmount);
				}
				let mut decoded_amount = [0; 8];
				cursor
					.read_exact(&mut decoded_amount)
					.map_err(|_| TaprootAssetHtlcBlobError::MalformedTlv)?;
				asset_amount = Some(u64::from_be_bytes(decoded_amount));
			},
			unknown if unknown % 2 == 0 => {
				return Err(TaprootAssetHtlcBlobError::UnknownRequiredTlv);
			},
			_ => cursor.set_position(end as u64),
		}

		if cursor.position() as usize != end {
			return Err(TaprootAssetHtlcBlobError::MalformedTlv);
		}
	}

	let asset_id = asset_id.ok_or(TaprootAssetHtlcBlobError::MissingAssetId)?;
	if asset_id == [0; TAPROOT_ASSET_ID_LEN] {
		return Err(TaprootAssetHtlcBlobError::ZeroAssetId);
	}
	let asset_amount = asset_amount.ok_or(TaprootAssetHtlcBlobError::MissingAmount)?;
	if asset_amount == 0 {
		return Err(TaprootAssetHtlcBlobError::ZeroAmount);
	}

	Ok(TaprootAssetHtlcBlob { asset_id, asset_amount })
}

/// Decodes the Lightning Labs Taproot Asset HTLC blob carried on
/// `update_add_htlc`.
///
/// The live `tapd`/`litd` payload currently wraps the HTLC metadata records in
/// an outer TLV record. This decoder accepts both that wrapper and the direct
/// inner records so callers can validate captured live data and locally built
/// blobs through the same bounded surface.
pub fn decode_taproot_asset_htlc_blob(
	payload: &[u8],
) -> Result<TaprootAssetHtlcBlob, TaprootAssetHtlcBlobError> {
	if payload.is_empty() {
		return Err(TaprootAssetHtlcBlobError::Empty);
	}
	if let Some(inner_payload) = taproot_asset_htlc_blob_outer_value(payload)? {
		return decode_taproot_asset_htlc_blob_records(inner_payload);
	}
	decode_taproot_asset_htlc_blob_records(payload)
}

/// Expected final-hop metadata for an asset-channel HTLC.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaprootAssetHtlcMetadataExpectation {
	/// Expected asset ID.
	pub asset_id: [u8; TAPROOT_ASSET_ID_LEN],
	/// Expected asset amount.
	pub asset_amount: u64,
	/// Expected proof/root reference hash.
	pub proof_root_hash: [u8; TAPROOT_ASSET_ID_LEN],
	/// Expected proof/root sum.
	pub proof_root_sum: u64,
	/// Expected accepted quote ID.
	pub quote_id: [u8; TAPROOT_ASSET_ID_LEN],
	/// Expected payment hash.
	pub payment_hash: [u8; TAPROOT_ASSET_ID_LEN],
	/// Whether the quote has been accepted before attaching metadata.
	pub quote_accepted: bool,
	/// Current unix time used for stale quote checks.
	pub now_unix_seconds: u64,
	/// Quote expiry time.
	pub quote_expiry_unix_seconds: u64,
}

/// Final asset allocation exported during cooperative close.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaprootAssetCloseAllocation {
	/// Taproot Asset channel protocol version for this close allocation.
	pub protocol_version: u16,
	/// Channel ID whose close is exporting this allocation.
	pub channel_id: ChannelId,
	/// Asset ID being returned to both channel parties.
	pub asset_id: [u8; TAPROOT_ASSET_ID_LEN],
	/// Latest mutually safe Lightning commitment number.
	pub commitment_number: u64,
	/// Final local asset amount.
	pub local_amount: u64,
	/// Final remote asset amount.
	pub remote_amount: u64,
	/// Taproot Asset proof/root reference hash for the close state.
	pub proof_root_hash: [u8; TAPROOT_ASSET_ID_LEN],
	/// Taproot Asset proof/root sum for the close state.
	pub proof_root_sum: u64,
	/// Digest of the proof material handed to the local wallet.
	pub local_proof_digest: [u8; TAPROOT_ASSET_ID_LEN],
	/// Digest of the proof material handed to the remote wallet.
	pub remote_proof_digest: [u8; TAPROOT_ASSET_ID_LEN],
	/// Integrity digest over the close allocation.
	pub allocation_digest: [u8; TAPROOT_ASSET_ID_LEN],
}

impl TaprootAssetCloseAllocation {
	/// Builds a validated cooperative-close allocation.
	pub fn new(
		channel_id: ChannelId, asset_id: [u8; TAPROOT_ASSET_ID_LEN], commitment_number: u64,
		local_amount: u64, remote_amount: u64, proof_root_hash: [u8; TAPROOT_ASSET_ID_LEN],
		proof_root_sum: u64, local_proof_digest: [u8; TAPROOT_ASSET_ID_LEN],
		remote_proof_digest: [u8; TAPROOT_ASSET_ID_LEN],
	) -> Result<Self, TaprootAssetCloseAllocationError> {
		let mut allocation = Self {
			protocol_version: SUPPORTED_TAPROOT_ASSET_CHANNEL_PROTOCOL_VERSION,
			channel_id,
			asset_id,
			commitment_number,
			local_amount,
			remote_amount,
			proof_root_hash,
			proof_root_sum,
			local_proof_digest,
			remote_proof_digest,
			allocation_digest: [0; TAPROOT_ASSET_ID_LEN],
		};
		allocation.allocation_digest = allocation.digest();
		allocation.validate_integrity()?;
		Ok(allocation)
	}

	/// Recomputes the cooperative-close allocation digest.
	pub fn digest(&self) -> [u8; TAPROOT_ASSET_ID_LEN] {
		let mut engine = Sha256::engine();
		engine.input(b"openagents:taproot-asset-close-allocation:v1");
		engine.input(&self.protocol_version.to_be_bytes());
		engine.input(&self.channel_id.0);
		engine.input(&self.asset_id);
		engine.input(&self.commitment_number.to_be_bytes());
		engine.input(&self.local_amount.to_be_bytes());
		engine.input(&self.remote_amount.to_be_bytes());
		engine.input(&self.proof_root_hash);
		engine.input(&self.proof_root_sum.to_be_bytes());
		engine.input(&self.local_proof_digest);
		engine.input(&self.remote_proof_digest);
		Sha256::from_engine(engine).to_byte_array()
	}

	/// Checks internal close-allocation integrity before a caller compares it
	/// to the latest safe commitment.
	pub fn validate_integrity(&self) -> Result<(), TaprootAssetCloseAllocationError> {
		if self.protocol_version != SUPPORTED_TAPROOT_ASSET_CHANNEL_PROTOCOL_VERSION {
			return Err(TaprootAssetCloseAllocationError::UnsupportedProtocolVersion);
		}
		if self.channel_id.is_zero()
			|| self.asset_id == [0; TAPROOT_ASSET_ID_LEN]
			|| self.proof_root_hash == [0; TAPROOT_ASSET_ID_LEN]
			|| self.local_proof_digest == [0; TAPROOT_ASSET_ID_LEN]
			|| self.remote_proof_digest == [0; TAPROOT_ASSET_ID_LEN]
		{
			return Err(TaprootAssetCloseAllocationError::MalformedAllocation);
		}
		if self.local_amount.checked_add(self.remote_amount).is_none()
			|| self.local_amount + self.remote_amount != self.proof_root_sum
		{
			return Err(TaprootAssetCloseAllocationError::AmountMismatch);
		}
		if self.allocation_digest != self.digest() {
			return Err(TaprootAssetCloseAllocationError::AllocationDigestMismatch);
		}
		Ok(())
	}
}

/// Expected allocation for a cooperative asset-channel close.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaprootAssetCloseAllocationExpectation {
	/// Expected channel ID.
	pub channel_id: ChannelId,
	/// Expected asset ID.
	pub asset_id: [u8; TAPROOT_ASSET_ID_LEN],
	/// Latest safe commitment number.
	pub latest_commitment_number: u64,
	/// Expected final local amount.
	pub local_amount: u64,
	/// Expected final remote amount.
	pub remote_amount: u64,
	/// Expected close proof/root hash.
	pub proof_root_hash: [u8; TAPROOT_ASSET_ID_LEN],
	/// Expected close proof/root sum.
	pub proof_root_sum: u64,
}

/// Proof-ownership state exported by force-close, second-level HTLC, and final
/// sweep paths for an asset channel.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaprootAssetProofOwnershipState {
	/// Taproot Asset channel protocol version for this recovery state.
	pub protocol_version: u16,
	/// Channel ID whose unilateral close path is being recovered.
	pub channel_id: ChannelId,
	/// Asset ID being recovered.
	pub asset_id: [u8; TAPROOT_ASSET_ID_LEN],
	/// Lightning commitment number this recovery state belongs to.
	pub commitment_number: u64,
	/// Recovery spend path, using `TAPROOT_ASSET_RECOVERY_SPEND_*`.
	pub spend_kind: u8,
	/// Whether the Bitcoin spend path has recovered the BTC output.
	pub btc_recovered: bool,
	/// Whether the Taproot Asset ownership proof has been reconstructed.
	pub asset_proof_recovered: bool,
	/// Taproot Asset proof/root reference hash for the recovered output.
	pub proof_root_hash: [u8; TAPROOT_ASSET_ID_LEN],
	/// Taproot Asset proof/root sum for the recovered output.
	pub proof_root_sum: u64,
	/// Digest of the proof material handed to the asset owner.
	pub proof_handoff_digest: [u8; TAPROOT_ASSET_ID_LEN],
	/// Digest of the output that the final sweep or resolver hands to the wallet.
	pub sweep_output_digest: [u8; TAPROOT_ASSET_ID_LEN],
	/// Integrity digest over the proof-ownership recovery state.
	pub ownership_digest: [u8; TAPROOT_ASSET_ID_LEN],
}

impl TaprootAssetProofOwnershipState {
	/// Builds validated proof-ownership recovery state.
	pub fn new(
		channel_id: ChannelId, asset_id: [u8; TAPROOT_ASSET_ID_LEN], commitment_number: u64,
		spend_kind: u8, btc_recovered: bool, asset_proof_recovered: bool,
		proof_root_hash: [u8; TAPROOT_ASSET_ID_LEN], proof_root_sum: u64,
		proof_handoff_digest: [u8; TAPROOT_ASSET_ID_LEN],
		sweep_output_digest: [u8; TAPROOT_ASSET_ID_LEN],
	) -> Result<Self, TaprootAssetProofOwnershipError> {
		let mut state = Self {
			protocol_version: SUPPORTED_TAPROOT_ASSET_CHANNEL_PROTOCOL_VERSION,
			channel_id,
			asset_id,
			commitment_number,
			spend_kind,
			btc_recovered,
			asset_proof_recovered,
			proof_root_hash,
			proof_root_sum,
			proof_handoff_digest,
			sweep_output_digest,
			ownership_digest: [0; TAPROOT_ASSET_ID_LEN],
		};
		state.ownership_digest = state.digest();
		state.validate_integrity()?;
		Ok(state)
	}

	/// Recomputes the proof-ownership recovery digest.
	pub fn digest(&self) -> [u8; TAPROOT_ASSET_ID_LEN] {
		let mut engine = Sha256::engine();
		engine.input(b"openagents:taproot-asset-proof-ownership:v1");
		engine.input(&self.protocol_version.to_be_bytes());
		engine.input(&self.channel_id.0);
		engine.input(&self.asset_id);
		engine.input(&self.commitment_number.to_be_bytes());
		engine.input(&[self.spend_kind]);
		engine.input(&[self.btc_recovered as u8]);
		engine.input(&[self.asset_proof_recovered as u8]);
		engine.input(&self.proof_root_hash);
		engine.input(&self.proof_root_sum.to_be_bytes());
		engine.input(&self.proof_handoff_digest);
		engine.input(&self.sweep_output_digest);
		Sha256::from_engine(engine).to_byte_array()
	}

	/// Checks internal proof-ownership integrity before a caller compares it to
	/// the expected recovery spend path.
	pub fn validate_integrity(&self) -> Result<(), TaprootAssetProofOwnershipError> {
		if self.protocol_version != SUPPORTED_TAPROOT_ASSET_CHANNEL_PROTOCOL_VERSION {
			return Err(TaprootAssetProofOwnershipError::UnsupportedProtocolVersion);
		}
		if self.channel_id.is_zero()
			|| self.asset_id == [0; TAPROOT_ASSET_ID_LEN]
			|| self.proof_root_hash == [0; TAPROOT_ASSET_ID_LEN]
			|| self.proof_root_sum == 0
			|| self.sweep_output_digest == [0; TAPROOT_ASSET_ID_LEN]
		{
			return Err(TaprootAssetProofOwnershipError::MalformedProofOwnership);
		}
		if !matches!(
			self.spend_kind,
			TAPROOT_ASSET_RECOVERY_SPEND_COMMITMENT
				| TAPROOT_ASSET_RECOVERY_SPEND_SECOND_LEVEL_HTLC
				| TAPROOT_ASSET_RECOVERY_SPEND_FINAL_SWEEP
		) {
			return Err(TaprootAssetProofOwnershipError::MalformedProofOwnership);
		}
		if self.btc_recovered && !self.asset_proof_recovered {
			return Err(TaprootAssetProofOwnershipError::PartialRecovery);
		}
		if self.asset_proof_recovered && self.proof_handoff_digest == [0; TAPROOT_ASSET_ID_LEN] {
			return Err(TaprootAssetProofOwnershipError::MissingProofOwnershipMaterial);
		}
		if self.ownership_digest != self.digest() {
			return Err(TaprootAssetProofOwnershipError::OwnershipDigestMismatch);
		}
		Ok(())
	}
}

/// Expected proof-ownership state for an asset-channel unilateral recovery
/// spend path.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaprootAssetProofOwnershipExpectation {
	/// Expected channel ID.
	pub channel_id: ChannelId,
	/// Expected asset ID.
	pub asset_id: [u8; TAPROOT_ASSET_ID_LEN],
	/// Latest safe commitment number for this recovery path.
	pub latest_commitment_number: u64,
	/// Expected recovery spend path.
	pub spend_kind: u8,
	/// Expected proof/root hash.
	pub proof_root_hash: [u8; TAPROOT_ASSET_ID_LEN],
	/// Expected proof/root sum.
	pub proof_root_sum: u64,
	/// Whether this recovery path must include reconstructed asset proof
	/// ownership to be considered recovered.
	pub require_asset_proof: bool,
}

/// Asset-channel state that must be persisted with the matching
/// [`ChannelMonitorUpdate`](crate::chain::channelmonitor::ChannelMonitorUpdate).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaprootAssetMonitorAuxBlob {
	/// Schema version for this aux blob.
	pub schema_version: u16,
	/// Channel ID whose monitor update carries this asset state.
	pub channel_id: ChannelId,
	/// Asset ID for the single-asset channel.
	pub asset_id: [u8; TAPROOT_ASSET_ID_LEN],
	/// Lightning commitment number this asset state belongs to.
	pub commitment_number: u64,
	/// Local asset balance after this commitment.
	pub local_balance: u64,
	/// Remote asset balance after this commitment.
	pub remote_balance: u64,
	/// Digest of the asset state at this commitment.
	pub state_digest: [u8; TAPROOT_ASSET_ID_LEN],
	/// Taproot Asset proof/root reference hash for this state.
	pub proof_root_hash: [u8; TAPROOT_ASSET_ID_LEN],
	/// Taproot Asset proof/root sum for this state.
	pub proof_root_sum: u64,
	/// Digest of nonce material required by the asset signature path.
	pub nonce_digest: [u8; TAPROOT_ASSET_ID_LEN],
	/// Digest of asset signature material for this commitment.
	pub signature_digest: [u8; TAPROOT_ASSET_ID_LEN],
	/// Integrity digest over all fields above.
	pub blob_digest: [u8; TAPROOT_ASSET_ID_LEN],
}

impl TaprootAssetMonitorAuxBlob {
	/// Builds a validated Taproot Asset monitor aux blob.
	pub fn new(
		channel_id: ChannelId, asset_id: [u8; TAPROOT_ASSET_ID_LEN], commitment_number: u64,
		local_balance: u64, remote_balance: u64, state_digest: [u8; TAPROOT_ASSET_ID_LEN],
		proof_root_hash: [u8; TAPROOT_ASSET_ID_LEN], proof_root_sum: u64,
		nonce_digest: [u8; TAPROOT_ASSET_ID_LEN], signature_digest: [u8; TAPROOT_ASSET_ID_LEN],
	) -> Result<Self, TaprootAssetMonitorAuxBlobError> {
		let mut blob = Self {
			schema_version: TAPROOT_ASSET_MONITOR_AUX_BLOB_SCHEMA_VERSION,
			channel_id,
			asset_id,
			commitment_number,
			local_balance,
			remote_balance,
			state_digest,
			proof_root_hash,
			proof_root_sum,
			nonce_digest,
			signature_digest,
			blob_digest: [0; TAPROOT_ASSET_ID_LEN],
		};
		blob.blob_digest = blob.digest();
		blob.validate_integrity()?;
		Ok(blob)
	}

	/// Recomputes the aux blob integrity digest.
	pub fn digest(&self) -> [u8; TAPROOT_ASSET_ID_LEN] {
		let mut engine = Sha256::engine();
		engine.input(b"openagents:taproot-asset-monitor-aux:v1");
		engine.input(&self.schema_version.to_be_bytes());
		engine.input(&self.channel_id.0);
		engine.input(&self.asset_id);
		engine.input(&self.commitment_number.to_be_bytes());
		engine.input(&self.local_balance.to_be_bytes());
		engine.input(&self.remote_balance.to_be_bytes());
		engine.input(&self.state_digest);
		engine.input(&self.proof_root_hash);
		engine.input(&self.proof_root_sum.to_be_bytes());
		engine.input(&self.nonce_digest);
		engine.input(&self.signature_digest);
		Sha256::from_engine(engine).to_byte_array()
	}

	/// Checks the blob's internal integrity independent of any expected
	/// commitment.
	pub fn validate_integrity(&self) -> Result<(), TaprootAssetMonitorAuxBlobError> {
		if self.schema_version != TAPROOT_ASSET_MONITOR_AUX_BLOB_SCHEMA_VERSION {
			return Err(TaprootAssetMonitorAuxBlobError::UnsupportedVersion);
		}
		if self.channel_id.is_zero() {
			return Err(TaprootAssetMonitorAuxBlobError::MalformedBlob);
		}
		if self.asset_id == [0; TAPROOT_ASSET_ID_LEN]
			|| self.state_digest == [0; TAPROOT_ASSET_ID_LEN]
		{
			return Err(TaprootAssetMonitorAuxBlobError::MalformedBlob);
		}
		if self.local_balance.checked_add(self.remote_balance).is_none() {
			return Err(TaprootAssetMonitorAuxBlobError::AmountMismatch);
		}
		if self.proof_root_sum != self.local_balance + self.remote_balance {
			return Err(TaprootAssetMonitorAuxBlobError::AmountMismatch);
		}
		if self.blob_digest != self.digest() {
			return Err(TaprootAssetMonitorAuxBlobError::BlobDigestMismatch);
		}
		Ok(())
	}
}

/// Expected asset-channel monitor aux state for a Lightning monitor update.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaprootAssetMonitorAuxBlobExpectation {
	/// Expected channel ID.
	pub channel_id: ChannelId,
	/// Expected asset ID.
	pub asset_id: [u8; TAPROOT_ASSET_ID_LEN],
	/// Expected Lightning commitment number.
	pub commitment_number: u64,
	/// Expected local asset balance.
	pub local_balance: u64,
	/// Expected remote asset balance.
	pub remote_balance: u64,
	/// Expected asset state digest.
	pub state_digest: [u8; TAPROOT_ASSET_ID_LEN],
	/// Expected Taproot Asset root hash.
	pub proof_root_hash: [u8; TAPROOT_ASSET_ID_LEN],
	/// Expected Taproot Asset root sum.
	pub proof_root_sum: u64,
}

/// Bounded lifecycle state for an experimental single-asset channel layered on
/// the simple-taproot channel type.
///
/// This is the rust-lightning-side state machine boundary used by `tap-ldk`.
/// It deliberately keeps asset state explicit: callers must negotiate the
/// simple-taproot + asset channel type, validate proof-backed funding, attach a
/// monitor aux blob before each asset commitment is accepted, and validate
/// close/recovery material against the latest safe commitment.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TaprootAssetChannelState {
	/// The single asset this channel is allowed to carry.
	pub descriptor: TaprootAssetChannelDescriptor,
	/// The final channel ID used by monitor, HTLC, close, and recovery state.
	pub channel_id: ChannelId,
	/// The funding outpoint backing the channel.
	pub funding_outpoint: OutPoint,
	/// Local asset balance at the latest safe Lightning commitment.
	pub local_balance: u64,
	/// Remote asset balance at the latest safe Lightning commitment.
	pub remote_balance: u64,
	/// Total asset balance committed by the channel funding output.
	pub total_amount: u64,
	/// Taproot Asset proof/root reference hash for the latest state.
	pub proof_root_hash: [u8; TAPROOT_ASSET_ID_LEN],
	/// Taproot Asset proof/root sum for the latest state.
	pub proof_root_sum: u64,
	/// Latest Lightning commitment number for which asset state is durable.
	pub latest_commitment_number: u64,
	/// Whether a cooperative close allocation has finalized this asset state.
	pub closed: bool,
}

impl TaprootAssetChannelState {
	/// Creates asset-channel lifecycle state from a negotiated simple-taproot
	/// asset channel and a proof-backed funding request.
	pub fn from_funding_request(
		local_features: &InitFeatures, remote_features: &InitFeatures,
		proposed_channel_type: &ChannelTypeFeatures, channel_id: ChannelId,
		request: &TaprootAssetFundingRequest,
	) -> Result<Self, TaprootAssetChannelStateError> {
		if channel_id.is_zero() {
			return Err(TaprootAssetChannelStateError::MalformedChannelId);
		}
		validate_single_asset_channel_open(
			local_features,
			remote_features,
			proposed_channel_type,
			request.descriptor,
		)
		.map_err(TaprootAssetChannelStateError::ChannelNotNegotiated)?;
		let approval = validate_asset_channel_funding(request)
			.map_err(TaprootAssetChannelStateError::Funding)?;
		let total_amount = request
			.allocation
			.local_amount
			.checked_add(request.allocation.remote_amount)
			.ok_or(TaprootAssetChannelStateError::AmountMismatch)?;
		if total_amount != approval.total_amount {
			return Err(TaprootAssetChannelStateError::AmountMismatch);
		}
		Ok(Self {
			descriptor: request.descriptor,
			channel_id,
			funding_outpoint: approval.funding_outpoint,
			local_balance: request.allocation.local_amount,
			remote_balance: request.allocation.remote_amount,
			total_amount,
			proof_root_hash: request.proof_material.proof_root_hash,
			proof_root_sum: request.proof_material.proof_root_sum,
			latest_commitment_number: 0,
			closed: false,
		})
	}

	/// Returns the monitor aux expectation for the current state and the given
	/// caller-owned state digest.
	pub fn monitor_aux_expectation(
		&self, state_digest: [u8; TAPROOT_ASSET_ID_LEN],
	) -> TaprootAssetMonitorAuxBlobExpectation {
		TaprootAssetMonitorAuxBlobExpectation {
			channel_id: self.channel_id,
			asset_id: *self.descriptor.asset_id(),
			commitment_number: self.latest_commitment_number,
			local_balance: self.local_balance,
			remote_balance: self.remote_balance,
			state_digest,
			proof_root_hash: self.proof_root_hash,
			proof_root_sum: self.proof_root_sum,
		}
	}

	/// Requires the current state's asset monitor aux blob before the matching
	/// Lightning commitment is treated as durable.
	pub fn require_current_monitor_aux_blob<'a>(
		&self, blob: Option<&'a TaprootAssetMonitorAuxBlob>,
		state_digest: [u8; TAPROOT_ASSET_ID_LEN],
	) -> Result<&'a TaprootAssetMonitorAuxBlob, TaprootAssetChannelStateError> {
		require_asset_monitor_aux_blob(blob, &self.monitor_aux_expectation(state_digest))
			.map_err(TaprootAssetChannelStateError::Monitor)
	}

	/// Applies an asset commitment transition only after the next-state monitor
	/// aux blob is present and valid.
	pub fn apply_commitment_update<'a>(
		&mut self, next_commitment_number: u64, local_to_remote: u64, remote_to_local: u64,
		state_digest: [u8; TAPROOT_ASSET_ID_LEN],
		monitor_blob: Option<&'a TaprootAssetMonitorAuxBlob>,
	) -> Result<&'a TaprootAssetMonitorAuxBlob, TaprootAssetChannelStateError> {
		if self.closed {
			return Err(TaprootAssetChannelStateError::ClosedChannel);
		}
		let expected_next = self
			.latest_commitment_number
			.checked_add(1)
			.ok_or(TaprootAssetChannelStateError::CommitmentNumberOverflow)?;
		if next_commitment_number != expected_next {
			return Err(TaprootAssetChannelStateError::StaleCommitmentNumber);
		}
		let local_after_send = self
			.local_balance
			.checked_sub(local_to_remote)
			.ok_or(TaprootAssetChannelStateError::AmountMismatch)?;
		let remote_after_send = self
			.remote_balance
			.checked_sub(remote_to_local)
			.ok_or(TaprootAssetChannelStateError::AmountMismatch)?;
		let local_balance = local_after_send
			.checked_add(remote_to_local)
			.ok_or(TaprootAssetChannelStateError::AmountMismatch)?;
		let remote_balance = remote_after_send
			.checked_add(local_to_remote)
			.ok_or(TaprootAssetChannelStateError::AmountMismatch)?;
		if local_balance
			.checked_add(remote_balance)
			.ok_or(TaprootAssetChannelStateError::AmountMismatch)?
			!= self.total_amount
		{
			return Err(TaprootAssetChannelStateError::AmountMismatch);
		}
		let expected = TaprootAssetMonitorAuxBlobExpectation {
			channel_id: self.channel_id,
			asset_id: *self.descriptor.asset_id(),
			commitment_number: next_commitment_number,
			local_balance,
			remote_balance,
			state_digest,
			proof_root_hash: self.proof_root_hash,
			proof_root_sum: self.proof_root_sum,
		};
		let blob = require_asset_monitor_aux_blob(monitor_blob, &expected)
			.map_err(TaprootAssetChannelStateError::Monitor)?;
		self.latest_commitment_number = next_commitment_number;
		self.local_balance = local_balance;
		self.remote_balance = remote_balance;
		Ok(blob)
	}

	/// Validates final-hop HTLC metadata against this asset channel's current
	/// proof root.
	pub fn validate_htlc_metadata<'a>(
		&self, metadata: Option<&'a TaprootAssetHtlcMetadata>,
		expected: &TaprootAssetHtlcMetadataExpectation,
	) -> Result<&'a TaprootAssetHtlcMetadata, TaprootAssetChannelStateError> {
		if expected.asset_id != *self.descriptor.asset_id()
			|| expected.proof_root_hash != self.proof_root_hash
			|| expected.proof_root_sum != self.proof_root_sum
		{
			return Err(TaprootAssetChannelStateError::Htlc(
				TaprootAssetHtlcMetadataError::ProofRootMismatch,
			));
		}
		validate_asset_htlc_final_hop(metadata, expected)
			.map_err(TaprootAssetChannelStateError::Htlc)
	}

	/// Finalizes cooperative close allocation for the latest safe asset state.
	pub fn validate_cooperative_close<'a>(
		&mut self, allocation: Option<&'a TaprootAssetCloseAllocation>,
	) -> Result<&'a TaprootAssetCloseAllocation, TaprootAssetChannelStateError> {
		let expected = TaprootAssetCloseAllocationExpectation {
			channel_id: self.channel_id,
			asset_id: *self.descriptor.asset_id(),
			latest_commitment_number: self.latest_commitment_number,
			local_amount: self.local_balance,
			remote_amount: self.remote_balance,
			proof_root_hash: self.proof_root_hash,
			proof_root_sum: self.proof_root_sum,
		};
		let allocation = validate_cooperative_close_asset_allocation(allocation, &expected)
			.map_err(TaprootAssetChannelStateError::Close)?;
		self.closed = true;
		Ok(allocation)
	}

	/// Validates proof ownership for a unilateral recovery spend path.
	pub fn validate_proof_ownership<'a>(
		&self, state: Option<&'a TaprootAssetProofOwnershipState>, spend_kind: u8,
	) -> Result<&'a TaprootAssetProofOwnershipState, TaprootAssetChannelStateError> {
		let expected = TaprootAssetProofOwnershipExpectation {
			channel_id: self.channel_id,
			asset_id: *self.descriptor.asset_id(),
			latest_commitment_number: self.latest_commitment_number,
			spend_kind,
			proof_root_hash: self.proof_root_hash,
			proof_root_sum: self.proof_root_sum,
			require_asset_proof: true,
		};
		validate_asset_proof_ownership_recovery(state, &expected)
			.map_err(TaprootAssetChannelStateError::ProofOwnership)
	}
}

/// Errors returned while checking an experimental Taproot Asset channel
/// negotiation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TaprootAssetChannelNegotiationError {
	/// The local node did not advertise the simple taproot staging feature.
	MissingLocalSimpleTaprootSupport,
	/// The remote peer did not advertise the simple taproot staging feature.
	MissingRemoteSimpleTaprootSupport,
	/// The local node did not advertise the experimental asset-channel feature.
	MissingLocalSupport,
	/// The remote peer did not advertise the experimental asset-channel feature.
	MissingRemoteSupport,
	/// The proposed channel type did not include the simple taproot staging bit.
	MissingSimpleTaprootChannelType,
	/// The proposed channel type did not include the experimental asset-channel
	/// bit.
	MissingAssetChannelType,
	/// The proposed channel type carried optional bits, which channel types must
	/// not do.
	MalformedChannelType,
	/// The proposed channel type was not supported by the local feature set.
	UnsupportedChannelType,
	/// The asset ID was all zeroes and cannot identify a real Taproot Asset.
	MalformedAssetId,
	/// The descriptor used an unsupported protocol version.
	UnsupportedProtocolVersion,
}

/// Errors returned by the bounded asset-channel funding controller.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TaprootAssetFundingError {
	/// The pending channel ID was zero and cannot identify an in-flight funding
	/// flow.
	MissingPendingChannelId,
	/// Local and remote peer identities were equal.
	MalformedPeerIdentity,
	/// The asset ID in the descriptor, proof material, output, or expectations
	/// did not match.
	AssetIdMismatch,
	/// The proof genesis identity did not match the expected genesis identity.
	GenesisMismatch,
	/// The proof group key did not match the expected group key.
	GroupKeyMismatch,
	/// Proof fragments were missing or incomplete.
	MissingProofFragments,
	/// The proof root hash or root sum did not match the expected values.
	ProofRootMismatch,
	/// The funding output outpoint did not match the funding request.
	FundingOutpointMismatch,
	/// The funding output root did not match the reconstructed proof root.
	FundingRootMismatch,
	/// The funding output commitment digest did not match the expected digest.
	OutputCommitmentMismatch,
	/// Local and remote allocation or root sums did not match the expected
	/// total.
	AmountMismatch,
}

/// Errors returned by asset HTLC metadata preparation and final-hop
/// validation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TaprootAssetHtlcMetadataError {
	/// The HTLC metadata path was used without an asset-channel negotiation.
	ChannelNotNegotiated,
	/// An asset-channel HTLC required metadata but none was present.
	MissingAssetMetadata,
	/// The RFQ quote was not accepted before metadata attachment.
	MissingAcceptedQuote,
	/// The metadata used an unsupported protocol version.
	UnsupportedProtocolVersion,
	/// The metadata was zeroed or internally malformed.
	MalformedMetadata,
	/// The metadata asset ID did not match the expected asset.
	AssetIdMismatch,
	/// The metadata asset amount did not match the expected amount.
	AssetAmountMismatch,
	/// The proof/root reference did not match the expected asset proof root.
	ProofRootMismatch,
	/// The quote ID did not match the accepted quote.
	QuoteMismatch,
	/// The accepted quote has expired.
	StaleQuote,
	/// The payment hash did not match the final-hop payment.
	PaymentHashMismatch,
	/// The final-hop metadata digest did not match the serialized fields.
	FinalHopDigestMismatch,
}

/// Errors returned while decoding an `update_add_htlc` Taproot Asset blob.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TaprootAssetHtlcBlobError {
	/// The blob was empty.
	Empty,
	/// The TLV stream was not canonical or its length fields were malformed.
	MalformedTlv,
	/// An unknown even TLV record was present.
	UnknownRequiredTlv,
	/// A known TLV field appeared more than once.
	DuplicateField,
	/// The required asset ID field was missing.
	MissingAssetId,
	/// The required asset amount field was missing.
	MissingAmount,
	/// The asset ID field had an invalid length.
	MalformedAssetId,
	/// The asset amount field had an invalid length.
	MalformedAmount,
	/// The asset ID was all zeros.
	ZeroAssetId,
	/// The asset amount was zero.
	ZeroAmount,
}

/// Errors returned by cooperative asset-channel close allocation validation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TaprootAssetCloseAllocationError {
	/// The close allocation path was used without an asset-channel negotiation.
	ChannelNotNegotiated,
	/// An asset-channel close required an allocation but none was present.
	MissingCloseAllocation,
	/// The close allocation used an unsupported protocol version.
	UnsupportedProtocolVersion,
	/// The close allocation was zeroed or internally malformed.
	MalformedAllocation,
	/// The close allocation channel ID did not match the expected channel.
	ChannelIdMismatch,
	/// The close allocation asset ID did not match the expected asset.
	AssetIdMismatch,
	/// The close allocation commitment number was not the latest safe state.
	CommitmentNumberMismatch,
	/// The close allocation amounts did not conserve the expected root sum.
	AmountMismatch,
	/// The close allocation proof root did not match the expected proof root.
	ProofRootMismatch,
	/// The close allocation digest did not match the serialized fields.
	AllocationDigestMismatch,
}

/// Errors returned by asset-channel proof-ownership recovery validation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TaprootAssetProofOwnershipError {
	/// The recovery path was used without an asset-channel negotiation.
	ChannelNotNegotiated,
	/// An asset-channel recovery path required proof ownership but none was
	/// present.
	MissingProofOwnership,
	/// The recovery state used an unsupported protocol version.
	UnsupportedProtocolVersion,
	/// The recovery state was zeroed, used an unknown spend path, or was
	/// internally malformed.
	MalformedProofOwnership,
	/// The recovery state channel ID did not match the expected channel.
	ChannelIdMismatch,
	/// The recovery state asset ID did not match the expected asset.
	AssetIdMismatch,
	/// The recovery state commitment number was not the latest safe state.
	CommitmentNumberMismatch,
	/// The recovery state spend path did not match the expected resolver path.
	SpendKindMismatch,
	/// The recovery state proof root did not match the expected proof root.
	ProofRootMismatch,
	/// Asset proof ownership was claimed without proof handoff material.
	MissingProofOwnershipMaterial,
	/// BTC was recovered but asset proof ownership was not, so recovery is only
	/// partial.
	PartialRecovery,
	/// The recovery state digest did not match the serialized fields.
	OwnershipDigestMismatch,
}

/// Errors returned by Taproot Asset monitor aux blob validation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TaprootAssetMonitorAuxBlobError {
	/// An asset-channel monitor update was required but no aux blob was present.
	MissingAssetBlob,
	/// The aux blob used an unsupported schema version.
	UnsupportedVersion,
	/// The aux blob was zeroed or internally malformed.
	MalformedBlob,
	/// The aux blob channel ID did not match the monitor update.
	ChannelIdMismatch,
	/// The aux blob asset ID did not match the expected asset.
	AssetIdMismatch,
	/// The aux blob commitment number did not match the Lightning commitment.
	CommitmentNumberMismatch,
	/// The aux blob balance sum did not match the expected total or root sum.
	AmountMismatch,
	/// The aux blob state digest did not match the expected asset state.
	StateDigestMismatch,
	/// The aux blob proof root did not match the expected Taproot Asset root.
	ProofRootMismatch,
	/// The aux blob integrity digest did not match the serialized fields.
	BlobDigestMismatch,
}

/// Errors returned by the bounded rust-lightning asset-channel lifecycle
/// state machine.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TaprootAssetChannelStateError {
	/// The final channel ID was zero.
	MalformedChannelId,
	/// The simple-taproot asset channel was not explicitly negotiated.
	ChannelNotNegotiated(TaprootAssetChannelNegotiationError),
	/// Funding validation failed.
	Funding(TaprootAssetFundingError),
	/// The matching channel monitor aux blob was missing or invalid.
	Monitor(TaprootAssetMonitorAuxBlobError),
	/// HTLC metadata validation failed.
	Htlc(TaprootAssetHtlcMetadataError),
	/// Cooperative close allocation validation failed.
	Close(TaprootAssetCloseAllocationError),
	/// Proof-ownership recovery validation failed.
	ProofOwnership(TaprootAssetProofOwnershipError),
	/// The commitment number did not advance by exactly one.
	StaleCommitmentNumber,
	/// The commitment number overflowed.
	CommitmentNumberOverflow,
	/// The transition did not conserve the channel's asset amount.
	AmountMismatch,
	/// The asset channel was already cooperatively closed.
	ClosedChannel,
}

/// Builds the required channel type for a single-asset Taproot Asset channel.
pub fn single_asset_channel_type() -> ChannelTypeFeatures {
	ChannelTypeFeatures::taproot_asset_single_asset()
}

/// Negotiates the experimental Taproot Asset channel type from local and
/// remote init features.
pub fn negotiate_single_asset_channel(
	local_features: &InitFeatures, remote_features: &InitFeatures,
	descriptor: TaprootAssetChannelDescriptor,
) -> Result<TaprootAssetChannelNegotiation, TaprootAssetChannelNegotiationError> {
	if !local_features.supports_simple_taproot_staging() {
		return Err(TaprootAssetChannelNegotiationError::MissingLocalSimpleTaprootSupport);
	}
	if !remote_features.supports_simple_taproot_staging() {
		return Err(TaprootAssetChannelNegotiationError::MissingRemoteSimpleTaprootSupport);
	}
	if !local_features.supports_taproot_asset_channel() {
		return Err(TaprootAssetChannelNegotiationError::MissingLocalSupport);
	}
	if !remote_features.supports_taproot_asset_channel() {
		return Err(TaprootAssetChannelNegotiationError::MissingRemoteSupport);
	}
	Ok(TaprootAssetChannelNegotiation { descriptor, channel_type: single_asset_channel_type() })
}

/// Validates that a proposed channel type is an explicitly negotiated
/// single-asset Taproot Asset channel.
pub fn validate_single_asset_channel_open(
	local_features: &InitFeatures, remote_features: &InitFeatures,
	proposed_channel_type: &ChannelTypeFeatures, descriptor: TaprootAssetChannelDescriptor,
) -> Result<TaprootAssetChannelNegotiation, TaprootAssetChannelNegotiationError> {
	if !proposed_channel_type.requires_taproot_asset_channel() {
		return Err(TaprootAssetChannelNegotiationError::MissingAssetChannelType);
	}
	if proposed_channel_type.supports_any_optional_bits() {
		return Err(TaprootAssetChannelNegotiationError::MalformedChannelType);
	}

	let negotiation = negotiate_single_asset_channel(local_features, remote_features, descriptor)?;
	let supported_channel_types = ChannelTypeFeatures::from_init(local_features);
	if proposed_channel_type.requires_unknown_bits_from(&supported_channel_types) {
		return Err(TaprootAssetChannelNegotiationError::UnsupportedChannelType);
	}
	if proposed_channel_type != &negotiation.channel_type {
		return Err(TaprootAssetChannelNegotiationError::UnsupportedChannelType);
	}

	Ok(negotiation)
}

/// Validates a bounded Taproot Asset funding request before the caller advances
/// channel funding state.
pub fn validate_asset_channel_funding(
	request: &TaprootAssetFundingRequest,
) -> Result<TaprootAssetFundingApproval, TaprootAssetFundingError> {
	if request.pending_channel_id.is_zero() {
		return Err(TaprootAssetFundingError::MissingPendingChannelId);
	}
	if request.local_peer_id == request.remote_peer_id {
		return Err(TaprootAssetFundingError::MalformedPeerIdentity);
	}

	let descriptor_asset_id = *request.descriptor.asset_id();
	if descriptor_asset_id != request.expectations.asset_id
		|| request.proof_material.asset_id != request.expectations.asset_id
		|| request.funding_output.asset_id != request.expectations.asset_id
	{
		return Err(TaprootAssetFundingError::AssetIdMismatch);
	}

	if request.proof_material.genesis_id != request.expectations.genesis_id {
		return Err(TaprootAssetFundingError::GenesisMismatch);
	}
	if request.proof_material.group_key != request.expectations.group_key {
		return Err(TaprootAssetFundingError::GroupKeyMismatch);
	}
	if request.proof_material.expected_fragment_count == 0
		|| request.proof_material.complete_fragment_count
			< request.proof_material.expected_fragment_count
	{
		return Err(TaprootAssetFundingError::MissingProofFragments);
	}
	if request.proof_material.proof_root_hash != request.expectations.proof_root_hash
		|| request.proof_material.proof_root_sum != request.expectations.total_amount
	{
		return Err(TaprootAssetFundingError::ProofRootMismatch);
	}
	if request.funding_output.outpoint != request.funding_outpoint {
		return Err(TaprootAssetFundingError::FundingOutpointMismatch);
	}
	if request.funding_output.taproot_asset_root_hash != request.proof_material.proof_root_hash
		|| request.funding_output.taproot_asset_root_sum != request.proof_material.proof_root_sum
	{
		return Err(TaprootAssetFundingError::FundingRootMismatch);
	}
	if request.funding_output.output_commitment != request.expectations.output_commitment {
		return Err(TaprootAssetFundingError::OutputCommitmentMismatch);
	}

	let total = request
		.allocation
		.local_amount
		.checked_add(request.allocation.remote_amount)
		.ok_or(TaprootAssetFundingError::AmountMismatch)?;
	if total != request.expectations.total_amount
		|| request.funding_output.taproot_asset_root_sum != request.expectations.total_amount
	{
		return Err(TaprootAssetFundingError::AmountMismatch);
	}

	Ok(TaprootAssetFundingApproval {
		pending_channel_id: request.pending_channel_id,
		funding_outpoint: request.funding_outpoint,
		asset_id: request.expectations.asset_id,
		total_amount: request.expectations.total_amount,
	})
}

/// Prepares asset HTLC metadata after confirming the channel negotiated the
/// experimental single-asset type and the RFQ quote was accepted.
pub fn prepare_asset_htlc_metadata(
	local_features: &InitFeatures, remote_features: &InitFeatures,
	proposed_channel_type: &ChannelTypeFeatures, descriptor: TaprootAssetChannelDescriptor,
	quote_accepted: bool, metadata: TaprootAssetHtlcMetadata,
) -> Result<TaprootAssetHtlcMetadata, TaprootAssetHtlcMetadataError> {
	validate_single_asset_channel_open(
		local_features,
		remote_features,
		proposed_channel_type,
		descriptor,
	)
	.map_err(|_| TaprootAssetHtlcMetadataError::ChannelNotNegotiated)?;
	if !quote_accepted {
		return Err(TaprootAssetHtlcMetadataError::MissingAcceptedQuote);
	}
	metadata.validate_integrity()?;
	if metadata.asset_id != *descriptor.asset_id() {
		return Err(TaprootAssetHtlcMetadataError::AssetIdMismatch);
	}
	Ok(metadata)
}

/// Prepares a cooperative-close asset allocation after confirming the channel
/// negotiated the experimental single-asset type.
pub fn prepare_cooperative_close_asset_allocation(
	local_features: &InitFeatures, remote_features: &InitFeatures,
	proposed_channel_type: &ChannelTypeFeatures, descriptor: TaprootAssetChannelDescriptor,
	allocation: TaprootAssetCloseAllocation,
) -> Result<TaprootAssetCloseAllocation, TaprootAssetCloseAllocationError> {
	validate_single_asset_channel_open(
		local_features,
		remote_features,
		proposed_channel_type,
		descriptor,
	)
	.map_err(|_| TaprootAssetCloseAllocationError::ChannelNotNegotiated)?;
	allocation.validate_integrity()?;
	if allocation.asset_id != *descriptor.asset_id() {
		return Err(TaprootAssetCloseAllocationError::AssetIdMismatch);
	}
	Ok(allocation)
}

/// Prepares proof-ownership recovery state after confirming the channel
/// negotiated the experimental single-asset type.
pub fn prepare_asset_proof_ownership_recovery(
	local_features: &InitFeatures, remote_features: &InitFeatures,
	proposed_channel_type: &ChannelTypeFeatures, descriptor: TaprootAssetChannelDescriptor,
	state: TaprootAssetProofOwnershipState,
) -> Result<TaprootAssetProofOwnershipState, TaprootAssetProofOwnershipError> {
	validate_single_asset_channel_open(
		local_features,
		remote_features,
		proposed_channel_type,
		descriptor,
	)
	.map_err(|_| TaprootAssetProofOwnershipError::ChannelNotNegotiated)?;
	state.validate_integrity()?;
	if state.asset_id != *descriptor.asset_id() {
		return Err(TaprootAssetProofOwnershipError::AssetIdMismatch);
	}
	Ok(state)
}

/// Requires and validates proof ownership before an asset-channel unilateral
/// recovery path is treated as recovered.
pub fn validate_asset_proof_ownership_recovery<'a>(
	state: Option<&'a TaprootAssetProofOwnershipState>,
	expected: &TaprootAssetProofOwnershipExpectation,
) -> Result<&'a TaprootAssetProofOwnershipState, TaprootAssetProofOwnershipError> {
	let state = state.ok_or(TaprootAssetProofOwnershipError::MissingProofOwnership)?;
	state.validate_integrity()?;
	if state.channel_id != expected.channel_id {
		return Err(TaprootAssetProofOwnershipError::ChannelIdMismatch);
	}
	if state.asset_id != expected.asset_id {
		return Err(TaprootAssetProofOwnershipError::AssetIdMismatch);
	}
	if state.commitment_number != expected.latest_commitment_number {
		return Err(TaprootAssetProofOwnershipError::CommitmentNumberMismatch);
	}
	if state.spend_kind != expected.spend_kind {
		return Err(TaprootAssetProofOwnershipError::SpendKindMismatch);
	}
	if state.proof_root_hash != expected.proof_root_hash
		|| state.proof_root_sum != expected.proof_root_sum
	{
		return Err(TaprootAssetProofOwnershipError::ProofRootMismatch);
	}
	if expected.require_asset_proof && !state.asset_proof_recovered {
		return Err(TaprootAssetProofOwnershipError::PartialRecovery);
	}
	Ok(state)
}

/// Requires and validates the cooperative-close allocation for an asset
/// channel before the close is treated as final.
pub fn validate_cooperative_close_asset_allocation<'a>(
	allocation: Option<&'a TaprootAssetCloseAllocation>,
	expected: &TaprootAssetCloseAllocationExpectation,
) -> Result<&'a TaprootAssetCloseAllocation, TaprootAssetCloseAllocationError> {
	let allocation = allocation.ok_or(TaprootAssetCloseAllocationError::MissingCloseAllocation)?;
	allocation.validate_integrity()?;
	if allocation.channel_id != expected.channel_id {
		return Err(TaprootAssetCloseAllocationError::ChannelIdMismatch);
	}
	if allocation.asset_id != expected.asset_id {
		return Err(TaprootAssetCloseAllocationError::AssetIdMismatch);
	}
	if allocation.commitment_number != expected.latest_commitment_number {
		return Err(TaprootAssetCloseAllocationError::CommitmentNumberMismatch);
	}
	if allocation.local_amount != expected.local_amount
		|| allocation.remote_amount != expected.remote_amount
	{
		return Err(TaprootAssetCloseAllocationError::AmountMismatch);
	}
	if allocation.proof_root_hash != expected.proof_root_hash
		|| allocation.proof_root_sum != expected.proof_root_sum
	{
		return Err(TaprootAssetCloseAllocationError::ProofRootMismatch);
	}
	Ok(allocation)
}

/// Requires and validates asset HTLC metadata before final-hop settlement.
pub fn validate_asset_htlc_final_hop<'a>(
	metadata: Option<&'a TaprootAssetHtlcMetadata>, expected: &TaprootAssetHtlcMetadataExpectation,
) -> Result<&'a TaprootAssetHtlcMetadata, TaprootAssetHtlcMetadataError> {
	let metadata = metadata.ok_or(TaprootAssetHtlcMetadataError::MissingAssetMetadata)?;
	metadata.validate_integrity()?;
	if !expected.quote_accepted {
		return Err(TaprootAssetHtlcMetadataError::MissingAcceptedQuote);
	}
	if expected.now_unix_seconds > expected.quote_expiry_unix_seconds {
		return Err(TaprootAssetHtlcMetadataError::StaleQuote);
	}
	if metadata.asset_id != expected.asset_id {
		return Err(TaprootAssetHtlcMetadataError::AssetIdMismatch);
	}
	if metadata.asset_amount != expected.asset_amount {
		return Err(TaprootAssetHtlcMetadataError::AssetAmountMismatch);
	}
	if metadata.proof_root_hash != expected.proof_root_hash
		|| metadata.proof_root_sum != expected.proof_root_sum
	{
		return Err(TaprootAssetHtlcMetadataError::ProofRootMismatch);
	}
	if metadata.quote_id != expected.quote_id {
		return Err(TaprootAssetHtlcMetadataError::QuoteMismatch);
	}
	if metadata.payment_hash != expected.payment_hash {
		return Err(TaprootAssetHtlcMetadataError::PaymentHashMismatch);
	}
	Ok(metadata)
}

/// Requires and validates a Taproot Asset monitor aux blob for a monitor
/// update.
pub fn require_asset_monitor_aux_blob<'a>(
	blob: Option<&'a TaprootAssetMonitorAuxBlob>, expected: &TaprootAssetMonitorAuxBlobExpectation,
) -> Result<&'a TaprootAssetMonitorAuxBlob, TaprootAssetMonitorAuxBlobError> {
	let blob = blob.ok_or(TaprootAssetMonitorAuxBlobError::MissingAssetBlob)?;
	validate_asset_monitor_aux_blob(blob, expected)?;
	Ok(blob)
}

/// Validates that a Taproot Asset monitor aux blob matches the expected
/// Lightning commitment state.
pub fn validate_asset_monitor_aux_blob(
	blob: &TaprootAssetMonitorAuxBlob, expected: &TaprootAssetMonitorAuxBlobExpectation,
) -> Result<(), TaprootAssetMonitorAuxBlobError> {
	blob.validate_integrity()?;
	if blob.channel_id != expected.channel_id {
		return Err(TaprootAssetMonitorAuxBlobError::ChannelIdMismatch);
	}
	if blob.asset_id != expected.asset_id {
		return Err(TaprootAssetMonitorAuxBlobError::AssetIdMismatch);
	}
	if blob.commitment_number != expected.commitment_number {
		return Err(TaprootAssetMonitorAuxBlobError::CommitmentNumberMismatch);
	}
	if blob.local_balance != expected.local_balance
		|| blob.remote_balance != expected.remote_balance
	{
		return Err(TaprootAssetMonitorAuxBlobError::AmountMismatch);
	}
	if blob.proof_root_sum != expected.proof_root_sum {
		return Err(TaprootAssetMonitorAuxBlobError::AmountMismatch);
	}
	if blob.state_digest != expected.state_digest {
		return Err(TaprootAssetMonitorAuxBlobError::StateDigestMismatch);
	}
	if blob.proof_root_hash != expected.proof_root_hash {
		return Err(TaprootAssetMonitorAuxBlobError::ProofRootMismatch);
	}
	Ok(())
}

impl_writeable!(TaprootAssetCloseAllocation, {
	protocol_version,
	channel_id,
	asset_id,
	commitment_number,
	local_amount,
	remote_amount,
	proof_root_hash,
	proof_root_sum,
	local_proof_digest,
	remote_proof_digest,
	allocation_digest
});

impl_writeable!(TaprootAssetProofOwnershipState, {
	protocol_version,
	channel_id,
	asset_id,
	commitment_number,
	spend_kind,
	btc_recovered,
	asset_proof_recovered,
	proof_root_hash,
	proof_root_sum,
	proof_handoff_digest,
	sweep_output_digest,
	ownership_digest
});

impl_writeable!(TaprootAssetHtlcMetadata, {
	protocol_version,
	asset_id,
	asset_amount,
	proof_root_hash,
	proof_root_sum,
	quote_id,
	payment_hash,
	final_hop_digest
});

impl_writeable!(TaprootAssetMonitorAuxBlob, {
	schema_version,
	channel_id,
	asset_id,
	commitment_number,
	local_balance,
	remote_balance,
	state_digest,
	proof_root_hash,
	proof_root_sum,
	nonce_digest,
	signature_digest,
	blob_digest
});

#[cfg(test)]
mod tests {
	use super::*;
	use crate::chain::transaction::OutPoint;
	use crate::ln::types::ChannelId;

	use bitcoin::hash_types::Txid;
	use bitcoin::hashes::Hash;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

	fn asset_id() -> [u8; TAPROOT_ASSET_ID_LEN] {
		[42; TAPROOT_ASSET_ID_LEN]
	}

	fn live_litd_htlc_blob() -> Vec<u8> {
		vec![
			1, 44, 0, 32, 8, 126, 72, 111, 196, 6, 91, 164, 83, 39, 252, 20, 99, 146, 93, 241, 11,
			66, 138, 211, 2, 71, 54, 118, 93, 160, 16, 26, 67, 197, 190, 60, 1, 8, 0, 0, 0, 0, 0,
			0, 0, 1,
		]
	}

	fn live_litd_asset_id() -> [u8; TAPROOT_ASSET_ID_LEN] {
		[
			8, 126, 72, 111, 196, 6, 91, 164, 83, 39, 252, 20, 99, 146, 93, 241, 11, 66, 138, 211,
			2, 71, 54, 118, 93, 160, 16, 26, 67, 197, 190, 60,
		]
	}

	fn descriptor() -> TaprootAssetChannelDescriptor {
		TaprootAssetChannelDescriptor::new(
			asset_id(),
			SUPPORTED_TAPROOT_ASSET_CHANNEL_PROTOCOL_VERSION,
		)
		.unwrap()
	}

	fn asset_features() -> InitFeatures {
		let mut features = InitFeatures::empty();
		features.set_static_remote_key_optional();
		features.set_channel_type_optional();
		features.set_simple_taproot_staging_optional();
		features.set_taproot_asset_channel_optional();
		features
	}

	fn peer(byte: u8) -> PublicKey {
		let secp_ctx = Secp256k1::new();
		let secret_key = SecretKey::from_slice(&[byte; 32]).unwrap();
		PublicKey::from_secret_key(&secp_ctx, &secret_key)
	}

	#[test]
	fn decodes_live_litd_taproot_asset_htlc_blob() {
		let decoded = decode_taproot_asset_htlc_blob(&live_litd_htlc_blob()).unwrap();

		assert_eq!(decoded.asset_id, live_litd_asset_id());
		assert_eq!(decoded.asset_amount, 1);
	}

	#[test]
	fn decodes_direct_taproot_asset_htlc_blob_records() {
		let blob = live_litd_htlc_blob();
		let decoded = decode_taproot_asset_htlc_blob(&blob[2..]).unwrap();

		assert_eq!(decoded.asset_id, live_litd_asset_id());
		assert_eq!(decoded.asset_amount, 1);
	}

	#[test]
	fn rejects_malformed_taproot_asset_htlc_blobs() {
		assert_eq!(decode_taproot_asset_htlc_blob(&[]), Err(TaprootAssetHtlcBlobError::Empty));

		let mut zero_amount = live_litd_htlc_blob();
		*zero_amount.last_mut().unwrap() = 0;
		assert_eq!(
			decode_taproot_asset_htlc_blob(&zero_amount),
			Err(TaprootAssetHtlcBlobError::ZeroAmount)
		);

		let mut unknown_even_required = live_litd_htlc_blob();
		unknown_even_required.splice(46..46, [2, 1, 1]);
		unknown_even_required[1] = 47;
		assert_eq!(
			decode_taproot_asset_htlc_blob(&unknown_even_required),
			Err(TaprootAssetHtlcBlobError::UnknownRequiredTlv)
		);

		let mut bad_asset_id_len = live_litd_htlc_blob();
		bad_asset_id_len[3] = 31;
		assert_eq!(
			decode_taproot_asset_htlc_blob(&bad_asset_id_len),
			Err(TaprootAssetHtlcBlobError::MalformedAssetId)
		);
	}

	fn funding_outpoint() -> OutPoint {
		OutPoint { txid: Txid::from_slice(&[9; 32]).unwrap(), index: 0 }
	}

	fn funding_request() -> TaprootAssetFundingRequest {
		TaprootAssetFundingRequest {
			pending_channel_id: ChannelId::from_bytes([3; 32]),
			descriptor: descriptor(),
			funding_outpoint: funding_outpoint(),
			local_peer_id: peer(2),
			remote_peer_id: peer(3),
			proof_material: TaprootAssetFundingProofMaterial {
				asset_id: asset_id(),
				genesis_id: [4; TAPROOT_ASSET_ID_LEN],
				group_key: Some([5; TAPROOT_ASSET_ID_LEN]),
				proof_root_hash: [6; TAPROOT_ASSET_ID_LEN],
				proof_root_sum: 1_000,
				complete_fragment_count: 2,
				expected_fragment_count: 2,
			},
			funding_output: TaprootAssetFundingOutput {
				outpoint: funding_outpoint(),
				asset_id: asset_id(),
				taproot_asset_root_hash: [6; TAPROOT_ASSET_ID_LEN],
				taproot_asset_root_sum: 1_000,
				output_commitment: [7; TAPROOT_ASSET_ID_LEN],
			},
			expectations: TaprootAssetFundingExpectations {
				asset_id: asset_id(),
				genesis_id: [4; TAPROOT_ASSET_ID_LEN],
				group_key: Some([5; TAPROOT_ASSET_ID_LEN]),
				proof_root_hash: [6; TAPROOT_ASSET_ID_LEN],
				output_commitment: [7; TAPROOT_ASSET_ID_LEN],
				total_amount: 1_000,
			},
			allocation: TaprootAssetFundingAllocation { local_amount: 700, remote_amount: 300 },
		}
	}

	fn monitor_aux_blob() -> TaprootAssetMonitorAuxBlob {
		TaprootAssetMonitorAuxBlob::new(
			ChannelId::from_bytes([3; 32]),
			asset_id(),
			42,
			700,
			300,
			[8; TAPROOT_ASSET_ID_LEN],
			[6; TAPROOT_ASSET_ID_LEN],
			1_000,
			[10; TAPROOT_ASSET_ID_LEN],
			[11; TAPROOT_ASSET_ID_LEN],
		)
		.unwrap()
	}

	fn monitor_aux_expectation() -> TaprootAssetMonitorAuxBlobExpectation {
		TaprootAssetMonitorAuxBlobExpectation {
			channel_id: ChannelId::from_bytes([3; 32]),
			asset_id: asset_id(),
			commitment_number: 42,
			local_balance: 700,
			remote_balance: 300,
			state_digest: [8; TAPROOT_ASSET_ID_LEN],
			proof_root_hash: [6; TAPROOT_ASSET_ID_LEN],
			proof_root_sum: 1_000,
		}
	}

	fn state_monitor_aux_blob(
		commitment_number: u64, local_balance: u64, remote_balance: u64,
		state_digest: [u8; TAPROOT_ASSET_ID_LEN],
	) -> TaprootAssetMonitorAuxBlob {
		TaprootAssetMonitorAuxBlob::new(
			ChannelId::from_bytes([3; 32]),
			asset_id(),
			commitment_number,
			local_balance,
			remote_balance,
			state_digest,
			[6; TAPROOT_ASSET_ID_LEN],
			1_000,
			[10; TAPROOT_ASSET_ID_LEN],
			[11; TAPROOT_ASSET_ID_LEN],
		)
		.unwrap()
	}

	fn htlc_metadata() -> TaprootAssetHtlcMetadata {
		TaprootAssetHtlcMetadata::new(
			asset_id(),
			125,
			[6; TAPROOT_ASSET_ID_LEN],
			1_000,
			[12; TAPROOT_ASSET_ID_LEN],
			[13; TAPROOT_ASSET_ID_LEN],
		)
		.unwrap()
	}

	fn htlc_expectation() -> TaprootAssetHtlcMetadataExpectation {
		TaprootAssetHtlcMetadataExpectation {
			asset_id: asset_id(),
			asset_amount: 125,
			proof_root_hash: [6; TAPROOT_ASSET_ID_LEN],
			proof_root_sum: 1_000,
			quote_id: [12; TAPROOT_ASSET_ID_LEN],
			payment_hash: [13; TAPROOT_ASSET_ID_LEN],
			quote_accepted: true,
			now_unix_seconds: 1_002,
			quote_expiry_unix_seconds: 1_100,
		}
	}

	fn close_allocation() -> TaprootAssetCloseAllocation {
		TaprootAssetCloseAllocation::new(
			ChannelId::from_bytes([3; 32]),
			asset_id(),
			43,
			575,
			425,
			[6; TAPROOT_ASSET_ID_LEN],
			1_000,
			[14; TAPROOT_ASSET_ID_LEN],
			[15; TAPROOT_ASSET_ID_LEN],
		)
		.unwrap()
	}

	fn close_expectation() -> TaprootAssetCloseAllocationExpectation {
		TaprootAssetCloseAllocationExpectation {
			channel_id: ChannelId::from_bytes([3; 32]),
			asset_id: asset_id(),
			latest_commitment_number: 43,
			local_amount: 575,
			remote_amount: 425,
			proof_root_hash: [6; TAPROOT_ASSET_ID_LEN],
			proof_root_sum: 1_000,
		}
	}

	fn proof_ownership_state(spend_kind: u8) -> TaprootAssetProofOwnershipState {
		TaprootAssetProofOwnershipState::new(
			ChannelId::from_bytes([3; 32]),
			asset_id(),
			43,
			spend_kind,
			true,
			true,
			[6; TAPROOT_ASSET_ID_LEN],
			1_000,
			[17; TAPROOT_ASSET_ID_LEN],
			[18; TAPROOT_ASSET_ID_LEN],
		)
		.unwrap()
	}

	fn proof_ownership_expectation(spend_kind: u8) -> TaprootAssetProofOwnershipExpectation {
		TaprootAssetProofOwnershipExpectation {
			channel_id: ChannelId::from_bytes([3; 32]),
			asset_id: asset_id(),
			latest_commitment_number: 43,
			spend_kind,
			proof_root_hash: [6; TAPROOT_ASSET_ID_LEN],
			proof_root_sum: 1_000,
			require_asset_proof: true,
		}
	}

	#[test]
	fn negotiates_single_asset_channel_when_both_peers_support_it() {
		let local = asset_features();
		let remote = asset_features();
		let negotiated = negotiate_single_asset_channel(&local, &remote, descriptor()).unwrap();
		assert_eq!(negotiated.descriptor.asset_id(), &asset_id());
		assert_eq!(
			negotiated.descriptor.protocol_version(),
			SUPPORTED_TAPROOT_ASSET_CHANNEL_PROTOCOL_VERSION
		);
		assert_eq!(negotiated.channel_type, ChannelTypeFeatures::taproot_asset_single_asset());
	}

	#[test]
	fn rejects_missing_local_support() {
		let mut local = InitFeatures::empty();
		local.set_simple_taproot_staging_optional();
		let remote = asset_features();
		assert_eq!(
			negotiate_single_asset_channel(&local, &remote, descriptor()),
			Err(TaprootAssetChannelNegotiationError::MissingLocalSupport)
		);
	}

	#[test]
	fn rejects_missing_remote_support() {
		let local = asset_features();
		let mut remote = InitFeatures::empty();
		remote.set_simple_taproot_staging_optional();
		assert_eq!(
			negotiate_single_asset_channel(&local, &remote, descriptor()),
			Err(TaprootAssetChannelNegotiationError::MissingRemoteSupport)
		);
	}

	#[test]
	fn rejects_missing_simple_taproot_support() {
		let mut local = asset_features();
		local.clear_simple_taproot_staging();
		let remote = asset_features();
		assert_eq!(
			negotiate_single_asset_channel(&local, &remote, descriptor()),
			Err(TaprootAssetChannelNegotiationError::MissingLocalSimpleTaprootSupport)
		);

		let local = asset_features();
		let mut remote = asset_features();
		remote.clear_simple_taproot_staging();
		assert_eq!(
			negotiate_single_asset_channel(&local, &remote, descriptor()),
			Err(TaprootAssetChannelNegotiationError::MissingRemoteSimpleTaprootSupport)
		);
	}

	#[test]
	fn rejects_malformed_asset_id() {
		assert_eq!(
			TaprootAssetChannelDescriptor::new(
				[0; TAPROOT_ASSET_ID_LEN],
				SUPPORTED_TAPROOT_ASSET_CHANNEL_PROTOCOL_VERSION
			),
			Err(TaprootAssetChannelNegotiationError::MalformedAssetId)
		);
	}

	#[test]
	fn rejects_unsupported_protocol_version() {
		assert_eq!(
			TaprootAssetChannelDescriptor::new(asset_id(), 2),
			Err(TaprootAssetChannelNegotiationError::UnsupportedProtocolVersion)
		);
	}

	#[test]
	fn rejects_implicit_btc_channel_upgrade() {
		let local = asset_features();
		let remote = asset_features();
		assert_eq!(
			validate_single_asset_channel_open(
				&local,
				&remote,
				&ChannelTypeFeatures::only_static_remote_key(),
				descriptor()
			),
			Err(TaprootAssetChannelNegotiationError::MissingAssetChannelType)
		);
	}

	#[test]
	fn validates_explicit_asset_channel_open() {
		let local = asset_features();
		let remote = asset_features();
		let channel_type = ChannelTypeFeatures::taproot_asset_single_asset();
		let negotiated =
			validate_single_asset_channel_open(&local, &remote, &channel_type, descriptor())
				.unwrap();
		assert_eq!(negotiated.channel_type, channel_type);
	}

	#[test]
	fn validates_asset_channel_funding() {
		let approval = validate_asset_channel_funding(&funding_request()).unwrap();
		assert_eq!(approval.asset_id, asset_id());
		assert_eq!(approval.total_amount, 1_000);
		assert_eq!(approval.funding_outpoint, funding_outpoint());
	}

	#[test]
	fn asset_channel_state_runs_full_simple_taproot_asset_lifecycle() {
		let local = asset_features();
		let remote = asset_features();
		let channel_type = ChannelTypeFeatures::taproot_asset_single_asset();
		let mut state = TaprootAssetChannelState::from_funding_request(
			&local,
			&remote,
			&channel_type,
			ChannelId::from_bytes([3; 32]),
			&funding_request(),
		)
		.unwrap();
		assert_eq!(state.local_balance, 700);
		assert_eq!(state.remote_balance, 300);
		assert_eq!(state.latest_commitment_number, 0);
		assert!(!state.closed);

		let next_digest = [20; TAPROOT_ASSET_ID_LEN];
		let next_blob = state_monitor_aux_blob(1, 575, 425, next_digest);
		state.apply_commitment_update(1, 125, 0, next_digest, Some(&next_blob)).unwrap();
		assert_eq!(state.local_balance, 575);
		assert_eq!(state.remote_balance, 425);
		assert_eq!(state.latest_commitment_number, 1);

		let metadata = htlc_metadata();
		let expected_htlc = htlc_expectation();
		assert_eq!(
			state.validate_htlc_metadata(Some(&metadata), &expected_htlc).unwrap(),
			&metadata
		);

		let allocation = TaprootAssetCloseAllocation::new(
			ChannelId::from_bytes([3; 32]),
			asset_id(),
			1,
			575,
			425,
			[6; TAPROOT_ASSET_ID_LEN],
			1_000,
			[14; TAPROOT_ASSET_ID_LEN],
			[15; TAPROOT_ASSET_ID_LEN],
		)
		.unwrap();
		assert_eq!(state.validate_cooperative_close(Some(&allocation)).unwrap(), &allocation);
		assert!(state.closed);

		let recovery = TaprootAssetProofOwnershipState::new(
			ChannelId::from_bytes([3; 32]),
			asset_id(),
			1,
			TAPROOT_ASSET_RECOVERY_SPEND_COMMITMENT,
			true,
			true,
			[6; TAPROOT_ASSET_ID_LEN],
			1_000,
			[17; TAPROOT_ASSET_ID_LEN],
			[18; TAPROOT_ASSET_ID_LEN],
		)
		.unwrap();
		assert_eq!(
			state
				.validate_proof_ownership(Some(&recovery), TAPROOT_ASSET_RECOVERY_SPEND_COMMITMENT)
				.unwrap(),
			&recovery
		);
	}

	#[test]
	fn asset_channel_state_requires_monitor_before_commitment_advances() {
		let local = asset_features();
		let remote = asset_features();
		let channel_type = ChannelTypeFeatures::taproot_asset_single_asset();
		let mut state = TaprootAssetChannelState::from_funding_request(
			&local,
			&remote,
			&channel_type,
			ChannelId::from_bytes([3; 32]),
			&funding_request(),
		)
		.unwrap();
		let next_digest = [20; TAPROOT_ASSET_ID_LEN];
		assert_eq!(
			state.apply_commitment_update(1, 125, 0, next_digest, None),
			Err(TaprootAssetChannelStateError::Monitor(
				TaprootAssetMonitorAuxBlobError::MissingAssetBlob
			))
		);
		assert_eq!(state.local_balance, 700);
		assert_eq!(state.remote_balance, 300);
		assert_eq!(state.latest_commitment_number, 0);

		let stale_blob = state_monitor_aux_blob(0, 575, 425, next_digest);
		assert_eq!(
			state.apply_commitment_update(1, 125, 0, next_digest, Some(&stale_blob)),
			Err(TaprootAssetChannelStateError::Monitor(
				TaprootAssetMonitorAuxBlobError::CommitmentNumberMismatch
			))
		);
		assert_eq!(state.local_balance, 700);
		assert_eq!(state.remote_balance, 300);
		assert_eq!(state.latest_commitment_number, 0);
	}

	#[test]
	fn rejects_asset_funding_identity_mismatches() {
		let mut request = funding_request();
		request.proof_material.asset_id = [8; TAPROOT_ASSET_ID_LEN];
		assert_eq!(
			validate_asset_channel_funding(&request),
			Err(TaprootAssetFundingError::AssetIdMismatch)
		);

		let mut request = funding_request();
		request.proof_material.genesis_id = [8; TAPROOT_ASSET_ID_LEN];
		assert_eq!(
			validate_asset_channel_funding(&request),
			Err(TaprootAssetFundingError::GenesisMismatch)
		);

		let mut request = funding_request();
		request.proof_material.group_key = Some([8; TAPROOT_ASSET_ID_LEN]);
		assert_eq!(
			validate_asset_channel_funding(&request),
			Err(TaprootAssetFundingError::GroupKeyMismatch)
		);
	}

	#[test]
	fn rejects_incomplete_asset_funding_material() {
		let mut request = funding_request();
		request.proof_material.complete_fragment_count = 1;
		assert_eq!(
			validate_asset_channel_funding(&request),
			Err(TaprootAssetFundingError::MissingProofFragments)
		);
	}

	#[test]
	fn rejects_asset_funding_root_and_output_mismatches() {
		let mut request = funding_request();
		request.proof_material.proof_root_hash = [8; TAPROOT_ASSET_ID_LEN];
		assert_eq!(
			validate_asset_channel_funding(&request),
			Err(TaprootAssetFundingError::ProofRootMismatch)
		);

		let mut request = funding_request();
		request.funding_output.taproot_asset_root_hash = [8; TAPROOT_ASSET_ID_LEN];
		assert_eq!(
			validate_asset_channel_funding(&request),
			Err(TaprootAssetFundingError::FundingRootMismatch)
		);

		let mut request = funding_request();
		request.funding_output.output_commitment = [8; TAPROOT_ASSET_ID_LEN];
		assert_eq!(
			validate_asset_channel_funding(&request),
			Err(TaprootAssetFundingError::OutputCommitmentMismatch)
		);
	}

	#[test]
	fn rejects_asset_funding_amount_mismatch() {
		let mut request = funding_request();
		request.allocation.remote_amount = 301;
		assert_eq!(
			validate_asset_channel_funding(&request),
			Err(TaprootAssetFundingError::AmountMismatch)
		);
	}

	#[test]
	fn prepares_asset_htlc_metadata_after_quote_acceptance() {
		let local = asset_features();
		let remote = asset_features();
		let channel_type = ChannelTypeFeatures::taproot_asset_single_asset();
		let metadata = htlc_metadata();
		let prepared = prepare_asset_htlc_metadata(
			&local,
			&remote,
			&channel_type,
			descriptor(),
			true,
			metadata,
		)
		.unwrap();
		assert_eq!(prepared, metadata);
	}

	#[test]
	fn asset_htlc_metadata_requires_quote_and_asset_channel_gate() {
		let local = asset_features();
		let remote = asset_features();
		let channel_type = ChannelTypeFeatures::taproot_asset_single_asset();
		assert_eq!(
			prepare_asset_htlc_metadata(
				&local,
				&remote,
				&channel_type,
				descriptor(),
				false,
				htlc_metadata(),
			),
			Err(TaprootAssetHtlcMetadataError::MissingAcceptedQuote)
		);

		let btc_only_features = InitFeatures::empty();
		assert_eq!(
			prepare_asset_htlc_metadata(
				&btc_only_features,
				&remote,
				&channel_type,
				descriptor(),
				true,
				htlc_metadata(),
			),
			Err(TaprootAssetHtlcMetadataError::ChannelNotNegotiated)
		);
	}

	#[test]
	fn validates_asset_htlc_final_hop_metadata() {
		let metadata = htlc_metadata();
		let expected = htlc_expectation();
		assert_eq!(validate_asset_htlc_final_hop(Some(&metadata), &expected).unwrap(), &metadata);
	}

	#[test]
	fn rejects_missing_stale_or_wrong_asset_htlc_metadata() {
		let metadata = htlc_metadata();
		let expected = htlc_expectation();
		assert_eq!(
			validate_asset_htlc_final_hop(None, &expected),
			Err(TaprootAssetHtlcMetadataError::MissingAssetMetadata)
		);

		let mut not_accepted = expected;
		not_accepted.quote_accepted = false;
		assert_eq!(
			validate_asset_htlc_final_hop(Some(&metadata), &not_accepted),
			Err(TaprootAssetHtlcMetadataError::MissingAcceptedQuote)
		);

		let mut stale = expected;
		stale.now_unix_seconds = stale.quote_expiry_unix_seconds + 1;
		assert_eq!(
			validate_asset_htlc_final_hop(Some(&metadata), &stale),
			Err(TaprootAssetHtlcMetadataError::StaleQuote)
		);

		let mut wrong_asset = metadata;
		wrong_asset.asset_id = [14; TAPROOT_ASSET_ID_LEN];
		wrong_asset.final_hop_digest = wrong_asset.digest();
		assert_eq!(
			validate_asset_htlc_final_hop(Some(&wrong_asset), &expected),
			Err(TaprootAssetHtlcMetadataError::AssetIdMismatch)
		);

		let mut wrong_amount = metadata;
		wrong_amount.asset_amount = 126;
		wrong_amount.final_hop_digest = wrong_amount.digest();
		assert_eq!(
			validate_asset_htlc_final_hop(Some(&wrong_amount), &expected),
			Err(TaprootAssetHtlcMetadataError::AssetAmountMismatch)
		);

		let mut wrong_root = metadata;
		wrong_root.proof_root_hash = [14; TAPROOT_ASSET_ID_LEN];
		wrong_root.final_hop_digest = wrong_root.digest();
		assert_eq!(
			validate_asset_htlc_final_hop(Some(&wrong_root), &expected),
			Err(TaprootAssetHtlcMetadataError::ProofRootMismatch)
		);

		let mut wrong_quote = metadata;
		wrong_quote.quote_id = [14; TAPROOT_ASSET_ID_LEN];
		wrong_quote.final_hop_digest = wrong_quote.digest();
		assert_eq!(
			validate_asset_htlc_final_hop(Some(&wrong_quote), &expected),
			Err(TaprootAssetHtlcMetadataError::QuoteMismatch)
		);

		let mut wrong_payment = metadata;
		wrong_payment.payment_hash = [14; TAPROOT_ASSET_ID_LEN];
		wrong_payment.final_hop_digest = wrong_payment.digest();
		assert_eq!(
			validate_asset_htlc_final_hop(Some(&wrong_payment), &expected),
			Err(TaprootAssetHtlcMetadataError::PaymentHashMismatch)
		);

		let mut wrong_digest = metadata;
		wrong_digest.final_hop_digest = [14; TAPROOT_ASSET_ID_LEN];
		assert_eq!(
			validate_asset_htlc_final_hop(Some(&wrong_digest), &expected),
			Err(TaprootAssetHtlcMetadataError::FinalHopDigestMismatch)
		);
	}

	#[test]
	fn prepares_cooperative_close_asset_allocation() {
		let local = asset_features();
		let remote = asset_features();
		let channel_type = ChannelTypeFeatures::taproot_asset_single_asset();
		let allocation = close_allocation();
		let prepared = prepare_cooperative_close_asset_allocation(
			&local,
			&remote,
			&channel_type,
			descriptor(),
			allocation,
		)
		.unwrap();
		assert_eq!(prepared, allocation);
	}

	#[test]
	fn cooperative_close_allocation_requires_asset_channel_gate() {
		let remote = asset_features();
		let channel_type = ChannelTypeFeatures::taproot_asset_single_asset();
		assert_eq!(
			prepare_cooperative_close_asset_allocation(
				&InitFeatures::empty(),
				&remote,
				&channel_type,
				descriptor(),
				close_allocation(),
			),
			Err(TaprootAssetCloseAllocationError::ChannelNotNegotiated)
		);
	}

	#[test]
	fn validates_cooperative_close_asset_allocation() {
		let allocation = close_allocation();
		let expected = close_expectation();
		assert_eq!(
			validate_cooperative_close_asset_allocation(Some(&allocation), &expected).unwrap(),
			&allocation
		);
	}

	#[test]
	fn rejects_missing_stale_or_wrong_close_allocation() {
		let allocation = close_allocation();
		let expected = close_expectation();
		assert_eq!(
			validate_cooperative_close_asset_allocation(None, &expected),
			Err(TaprootAssetCloseAllocationError::MissingCloseAllocation)
		);

		let mut stale = allocation;
		stale.commitment_number = 42;
		stale.allocation_digest = stale.digest();
		assert_eq!(
			validate_cooperative_close_asset_allocation(Some(&stale), &expected),
			Err(TaprootAssetCloseAllocationError::CommitmentNumberMismatch)
		);

		let mut wrong_amount = allocation;
		wrong_amount.local_amount = 574;
		wrong_amount.remote_amount = 426;
		wrong_amount.allocation_digest = wrong_amount.digest();
		assert_eq!(
			validate_cooperative_close_asset_allocation(Some(&wrong_amount), &expected),
			Err(TaprootAssetCloseAllocationError::AmountMismatch)
		);

		let mut wrong_root = allocation;
		wrong_root.proof_root_hash = [16; TAPROOT_ASSET_ID_LEN];
		wrong_root.allocation_digest = wrong_root.digest();
		assert_eq!(
			validate_cooperative_close_asset_allocation(Some(&wrong_root), &expected),
			Err(TaprootAssetCloseAllocationError::ProofRootMismatch)
		);

		let mut wrong_digest = allocation;
		wrong_digest.allocation_digest = [16; TAPROOT_ASSET_ID_LEN];
		assert_eq!(
			validate_cooperative_close_asset_allocation(Some(&wrong_digest), &expected),
			Err(TaprootAssetCloseAllocationError::AllocationDigestMismatch)
		);
	}

	#[test]
	fn validates_monitor_aux_blob() {
		let blob = monitor_aux_blob();
		let expected = monitor_aux_expectation();
		assert!(validate_asset_monitor_aux_blob(&blob, &expected).is_ok());
		assert_eq!(require_asset_monitor_aux_blob(Some(&blob), &expected).unwrap(), &blob);
	}

	#[test]
	fn rejects_missing_or_stale_monitor_aux_blob() {
		let blob = monitor_aux_blob();
		let expected = monitor_aux_expectation();
		assert_eq!(
			require_asset_monitor_aux_blob(None, &expected),
			Err(TaprootAssetMonitorAuxBlobError::MissingAssetBlob)
		);

		let mut stale = expected;
		stale.commitment_number = 43;
		assert_eq!(
			validate_asset_monitor_aux_blob(&blob, &stale),
			Err(TaprootAssetMonitorAuxBlobError::CommitmentNumberMismatch)
		);
	}

	#[test]
	fn rejects_malformed_monitor_aux_blob() {
		let expected = monitor_aux_expectation();
		let mut tampered = monitor_aux_blob();
		tampered.state_digest = [12; TAPROOT_ASSET_ID_LEN];
		assert_eq!(
			validate_asset_monitor_aux_blob(&tampered, &expected),
			Err(TaprootAssetMonitorAuxBlobError::BlobDigestMismatch)
		);

		let mut wrong_root = monitor_aux_blob();
		wrong_root.proof_root_hash = [12; TAPROOT_ASSET_ID_LEN];
		wrong_root.blob_digest = wrong_root.digest();
		assert_eq!(
			validate_asset_monitor_aux_blob(&wrong_root, &expected),
			Err(TaprootAssetMonitorAuxBlobError::ProofRootMismatch)
		);
	}

	#[test]
	fn prepares_asset_proof_ownership_recovery_for_force_close_paths() {
		let local = asset_features();
		let remote = asset_features();
		let channel_type = ChannelTypeFeatures::taproot_asset_single_asset();
		for spend_kind in [
			TAPROOT_ASSET_RECOVERY_SPEND_COMMITMENT,
			TAPROOT_ASSET_RECOVERY_SPEND_SECOND_LEVEL_HTLC,
			TAPROOT_ASSET_RECOVERY_SPEND_FINAL_SWEEP,
		] {
			let state = proof_ownership_state(spend_kind);
			let prepared = prepare_asset_proof_ownership_recovery(
				&local,
				&remote,
				&channel_type,
				descriptor(),
				state,
			)
			.unwrap();
			assert_eq!(prepared, state);
		}
	}

	#[test]
	fn proof_ownership_recovery_requires_asset_channel_gate() {
		let remote = asset_features();
		let channel_type = ChannelTypeFeatures::taproot_asset_single_asset();
		assert_eq!(
			prepare_asset_proof_ownership_recovery(
				&InitFeatures::empty(),
				&remote,
				&channel_type,
				descriptor(),
				proof_ownership_state(TAPROOT_ASSET_RECOVERY_SPEND_COMMITMENT),
			),
			Err(TaprootAssetProofOwnershipError::ChannelNotNegotiated)
		);
	}

	#[test]
	fn validates_asset_proof_ownership_recovery_paths() {
		for spend_kind in [
			TAPROOT_ASSET_RECOVERY_SPEND_COMMITMENT,
			TAPROOT_ASSET_RECOVERY_SPEND_SECOND_LEVEL_HTLC,
			TAPROOT_ASSET_RECOVERY_SPEND_FINAL_SWEEP,
		] {
			let state = proof_ownership_state(spend_kind);
			let expected = proof_ownership_expectation(spend_kind);
			assert_eq!(
				validate_asset_proof_ownership_recovery(Some(&state), &expected).unwrap(),
				&state
			);
		}
	}

	#[test]
	fn rejects_missing_stale_or_wrong_asset_proof_ownership_recovery() {
		let state = proof_ownership_state(TAPROOT_ASSET_RECOVERY_SPEND_COMMITMENT);
		let expected = proof_ownership_expectation(TAPROOT_ASSET_RECOVERY_SPEND_COMMITMENT);
		assert_eq!(
			validate_asset_proof_ownership_recovery(None, &expected),
			Err(TaprootAssetProofOwnershipError::MissingProofOwnership)
		);

		let mut stale = state;
		stale.commitment_number = 42;
		stale.ownership_digest = stale.digest();
		assert_eq!(
			validate_asset_proof_ownership_recovery(Some(&stale), &expected),
			Err(TaprootAssetProofOwnershipError::CommitmentNumberMismatch)
		);

		let mut wrong_kind = state;
		wrong_kind.spend_kind = TAPROOT_ASSET_RECOVERY_SPEND_FINAL_SWEEP;
		wrong_kind.ownership_digest = wrong_kind.digest();
		assert_eq!(
			validate_asset_proof_ownership_recovery(Some(&wrong_kind), &expected),
			Err(TaprootAssetProofOwnershipError::SpendKindMismatch)
		);

		let mut wrong_root = state;
		wrong_root.proof_root_hash = [19; TAPROOT_ASSET_ID_LEN];
		wrong_root.ownership_digest = wrong_root.digest();
		assert_eq!(
			validate_asset_proof_ownership_recovery(Some(&wrong_root), &expected),
			Err(TaprootAssetProofOwnershipError::ProofRootMismatch)
		);

		let mut wrong_digest = state;
		wrong_digest.ownership_digest = [19; TAPROOT_ASSET_ID_LEN];
		assert_eq!(
			validate_asset_proof_ownership_recovery(Some(&wrong_digest), &expected),
			Err(TaprootAssetProofOwnershipError::OwnershipDigestMismatch)
		);
	}

	#[test]
	fn refuses_partial_or_malformed_asset_proof_ownership_recovery() {
		assert_eq!(
			TaprootAssetProofOwnershipState::new(
				ChannelId::from_bytes([3; 32]),
				asset_id(),
				43,
				TAPROOT_ASSET_RECOVERY_SPEND_COMMITMENT,
				true,
				false,
				[6; TAPROOT_ASSET_ID_LEN],
				1_000,
				[17; TAPROOT_ASSET_ID_LEN],
				[18; TAPROOT_ASSET_ID_LEN],
			),
			Err(TaprootAssetProofOwnershipError::PartialRecovery)
		);

		assert_eq!(
			TaprootAssetProofOwnershipState::new(
				ChannelId::from_bytes([3; 32]),
				asset_id(),
				43,
				TAPROOT_ASSET_RECOVERY_SPEND_COMMITMENT,
				false,
				true,
				[6; TAPROOT_ASSET_ID_LEN],
				1_000,
				[0; TAPROOT_ASSET_ID_LEN],
				[18; TAPROOT_ASSET_ID_LEN],
			),
			Err(TaprootAssetProofOwnershipError::MissingProofOwnershipMaterial)
		);

		assert_eq!(
			TaprootAssetProofOwnershipState::new(
				ChannelId::from_bytes([3; 32]),
				asset_id(),
				43,
				99,
				true,
				true,
				[6; TAPROOT_ASSET_ID_LEN],
				1_000,
				[17; TAPROOT_ASSET_ID_LEN],
				[18; TAPROOT_ASSET_ID_LEN],
			),
			Err(TaprootAssetProofOwnershipError::MalformedProofOwnership)
		);
	}
}
