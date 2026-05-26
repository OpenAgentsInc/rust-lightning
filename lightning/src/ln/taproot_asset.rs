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

#[cfg(test)]
mod tests {
	use super::*;

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
}
