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
//! gate for single-asset Taproot Asset channels. Funding proof validation,
//! asset allocation, commitment persistence, HTLC metadata, and recovery hooks
//! are separate integration surfaces.

use crate::chain::transaction::OutPoint;
use crate::ln::types::ChannelId;

use bitcoin::secp256k1::PublicKey;
use lightning_types::features::{ChannelTypeFeatures, InitFeatures};

/// The only Taproot Asset channel protocol version accepted by this
/// experimental fork surface.
pub const SUPPORTED_TAPROOT_ASSET_CHANNEL_PROTOCOL_VERSION: u16 = 1;

/// The byte length of a Taproot Asset ID.
pub const TAPROOT_ASSET_ID_LEN: usize = 32;

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

/// Errors returned while checking an experimental Taproot Asset channel
/// negotiation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TaprootAssetChannelNegotiationError {
	/// The local node did not advertise the experimental asset-channel feature.
	MissingLocalSupport,
	/// The remote peer did not advertise the experimental asset-channel feature.
	MissingRemoteSupport,
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
		features.set_taproot_asset_channel_optional();
		features
	}

	fn peer(byte: u8) -> PublicKey {
		let secp_ctx = Secp256k1::new();
		let secret_key = SecretKey::from_slice(&[byte; 32]).unwrap();
		PublicKey::from_secret_key(&secp_ctx, &secret_key)
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
		let local = InitFeatures::empty();
		let remote = asset_features();
		assert_eq!(
			negotiate_single_asset_channel(&local, &remote, descriptor()),
			Err(TaprootAssetChannelNegotiationError::MissingLocalSupport)
		);
	}

	#[test]
	fn rejects_missing_remote_support() {
		let local = asset_features();
		let remote = InitFeatures::empty();
		assert_eq!(
			negotiate_single_asset_channel(&local, &remote, descriptor()),
			Err(TaprootAssetChannelNegotiationError::MissingRemoteSupport)
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
}
