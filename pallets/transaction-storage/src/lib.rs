// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Transaction storage pallet. Indexes transactions and manages storage proofs.

// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

mod benchmarking;
pub mod weights;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::dispatch::{Dispatchable, GetDispatchInfo, RawOrigin};
use sp_runtime::traits::{BlakeTwo256, CheckedAdd, Hash, One, Saturating, Zero};
use sp_std::{prelude::*, result};
use sp_transaction_storage_proof::{
	encode_index, random_chunk, InherentError, TransactionStorageProof, CHUNK_SIZE,
	INHERENT_IDENTIFIER,
};

// Re-export pallet items so that they can be accessed from the crate namespace.
pub use pallet::*;
pub use weights::WeightInfo;

/// Maximum bytes that can be stored in one transaction.
// Setting higher limit also requires raising the allocator limit.
pub const DEFAULT_MAX_TRANSACTION_SIZE: u32 = 8 * 1024 * 1024;
pub const DEFAULT_MAX_BLOCK_TRANSACTIONS: u32 = 512;

/// Number of transactions and bytes covered by an authorization or authorizations.
#[derive(
	Default,
	PartialEq,
	Eq,
	sp_runtime::RuntimeDebug,
	Encode,
	Decode,
	scale_info::TypeInfo,
	MaxEncodedLen,
)]
pub struct AuthorizationExtent {
	/// Number of transactions.
	pub transactions: u32,
	/// Number of bytes.
	pub bytes: u64,
}

/// For tracking usage of authorizations for a particular account or content hash.
#[derive(Default, PartialEq, Eq, Encode, Decode, scale_info::TypeInfo, MaxEncodedLen)]
struct AuthorizationUsage {
	/// Extent of (unexpired) authorizations used. When an authorization expires, it consumes from
	/// this pool first.
	used: AuthorizationExtent,
	/// Extent of authorizations not yet used.
	unused: AuthorizationExtent,
}

/// Hash of a stored blob of data.
type ContentHash = [u8; 32];

/// The scope of an authorization.
#[derive(Clone, sp_runtime::RuntimeDebug, Encode, Decode, scale_info::TypeInfo, MaxEncodedLen)]
enum AuthorizationScope<AccountId> {
	/// Authorization for the given account to store arbitrary data.
	Account(AccountId),
	/// Authorization for anyone to store data with a specific hash.
	Preimage(ContentHash),
}

/// An authorization to store data.
#[derive(sp_runtime::RuntimeDebug, Encode, Decode, scale_info::TypeInfo, MaxEncodedLen)]
struct Authorization<AccountId> {
	/// Scope of the authorization (account/preimage).
	scope: AuthorizationScope<AccountId>,
	/// Extent of the authorization (number of transactions/bytes).
	extent: AuthorizationExtent,
}

/// State data for a stored transaction.
#[derive(
	Encode,
	Decode,
	Clone,
	sp_runtime::RuntimeDebug,
	PartialEq,
	Eq,
	scale_info::TypeInfo,
	MaxEncodedLen,
)]
pub struct TransactionInfo {
	/// Chunk trie root.
	chunk_root: <BlakeTwo256 as Hash>::Output,
	/// Plain hash of indexed data.
	content_hash: <BlakeTwo256 as Hash>::Output,
	/// Size of indexed data in bytes.
	size: u32,
	/// Total number of chunks added in the block with this transaction. This
	/// is used find transaction info by block chunk index using binary search.
	block_chunks: u32,
}

fn num_chunks(bytes: u32) -> u32 {
	((bytes as u64 + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64) as u32
}

#[frame_support::pallet(dev_mode)]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// The overarching event type.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		/// A dispatchable call.
		type RuntimeCall: Parameter
			+ Dispatchable<RuntimeOrigin = Self::RuntimeOrigin>
			+ GetDispatchInfo
			+ From<frame_system::Call<Self>>;
		/// Weight information for extrinsics in this pallet.
		type WeightInfo: WeightInfo;
		/// Maximum number of indexed transactions in the block.
		type MaxBlockTransactions: Get<u32>;
		/// Maximum data set in a single transaction in bytes.
		type MaxTransactionSize: Get<u32>;
		/// Maximum number of authorization expiries per block. Authorizations will be extended to
		/// avoid exceeding this limit.
		type MaxBlockAuthorizationExpiries: Get<u32>;
		/// Authorizations expire after this many blocks.
		type AuthorizationPeriod: Get<BlockNumberFor<Self>>;
		/// The origin that can authorize data storage.
		type Authorizer: EnsureOrigin<Self::RuntimeOrigin>;
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Not authorized to store the given data.
		NotAuthorized,
		/// Renewed extrinsic is not found.
		RenewedNotFound,
		/// Attempting to store empty transaction
		EmptyTransaction,
		/// Proof was not expected in this block.
		UnexpectedProof,
		/// Proof failed verification.
		InvalidProof,
		/// Unable to verify proof becasue state data is missing.
		MissingStateData,
		/// Double proof check in the block.
		DoubleCheck,
		/// Transaction is too large.
		TransactionTooLarge,
		/// Too many transactions in the block.
		TooManyTransactions,
		/// Attempted to call `store` outside of block execution.
		BadContext,
	}

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_initialize(n: BlockNumberFor<T>) -> Weight {
			let mut weight = Weight::zero();
			let db_weight = T::DbWeight::get();

			// Drop obsolete roots. The proof for `obsolete` will be checked later
			// in this block, so we drop `obsolete` - 1.
			weight.saturating_accrue(db_weight.reads(1));
			let period = <StoragePeriod<T>>::get();
			let obsolete = n.saturating_sub(period.saturating_add(One::one()));
			if obsolete > Zero::zero() {
				weight.saturating_accrue(db_weight.writes(2));
				<Transactions<T>>::remove(obsolete);
				<ChunkCount<T>>::remove(obsolete);
			}

			weight.saturating_accrue(Self::expire_authorizations(n));

			// For `on_finalize`
			weight.saturating_accrue(db_weight.reads_writes(2, 2));

			weight
		}

		fn on_finalize(n: BlockNumberFor<T>) {
			assert!(
				<ProofChecked<T>>::take() || {
					// Proof is not required for early or empty blocks.
					let number = <frame_system::Pallet<T>>::block_number();
					let period = <StoragePeriod<T>>::get();
					let target_number = number.saturating_sub(period);
					target_number.is_zero() || <ChunkCount<T>>::get(target_number) == 0
				},
				"Storage proof must be checked once in the block"
			);
			// Insert new transactions
			let transactions = <BlockTransactions<T>>::take();
			let total_chunks = transactions.last().map_or(0, |t| t.block_chunks);
			if total_chunks != 0 {
				<ChunkCount<T>>::insert(n, total_chunks);
				<Transactions<T>>::insert(n, transactions);
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Index and store data off chain. Minimum data size is 1 bytes, maximum is
		/// `MaxTransactionSize`. Data will be removed after `STORAGE_PERIOD` blocks, unless `renew`
		/// is called.
		/// ## Complexity
		/// - O(n*log(n)) of data size, as all data is pushed to an in-memory trie.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::store(data.len() as u32))]
		pub fn store(origin: OriginFor<T>, data: Vec<u8>) -> DispatchResult {
			ensure!(!data.is_empty(), Error::<T>::EmptyTransaction);
			ensure!(
				data.len() <= T::MaxTransactionSize::get() as usize,
				Error::<T>::TransactionTooLarge
			);
			let content_hash = sp_io::hashing::blake2_256(&data);

			Self::use_authorization(origin, content_hash, data.len() as u32)?;

			// Chunk data and compute storage root
			let chunk_count = num_chunks(data.len() as u32);
			let chunks = data.chunks(CHUNK_SIZE).map(|c| c.to_vec()).collect();
			let root = sp_io::trie::blake2_256_ordered_root(chunks, sp_runtime::StateVersion::V1);

			let extrinsic_index =
				<frame_system::Pallet<T>>::extrinsic_index().ok_or(Error::<T>::BadContext)?;
			sp_io::transaction_index::index(extrinsic_index, data.len() as u32, content_hash);

			let mut index = 0;
			<BlockTransactions<T>>::mutate(|transactions| {
				let total_chunks = transactions.last().map_or(0, |t| t.block_chunks) + chunk_count;
				index = transactions.len() as u32;
				transactions
					.try_push(TransactionInfo {
						chunk_root: root,
						size: data.len() as u32,
						content_hash: content_hash.into(),
						block_chunks: total_chunks,
					})
					.map_err(|_| Error::<T>::TooManyTransactions)?;
				Ok(())
			})?;
			Self::deposit_event(Event::Stored { index });
			Ok(())
		}

		/// Renew previously stored data. Parameters are the block number that contains
		/// previous `store` or `renew` call and transaction index within that block.
		/// Transaction index is emitted in the `Stored` or `Renewed` event.
		/// Requires same authorization as `store`.
		/// ## Complexity
		/// - O(1).
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::renew())]
		pub fn renew(
			origin: OriginFor<T>,
			block: BlockNumberFor<T>,
			index: u32,
		) -> DispatchResultWithPostInfo {
			let transactions = <Transactions<T>>::get(block).ok_or(Error::<T>::RenewedNotFound)?;
			let info = transactions.get(index as usize).ok_or(Error::<T>::RenewedNotFound)?;

			Self::use_authorization(origin, info.content_hash.into(), info.size)?;

			let extrinsic_index =
				<frame_system::Pallet<T>>::extrinsic_index().ok_or(Error::<T>::BadContext)?;
			sp_io::transaction_index::renew(extrinsic_index, info.content_hash.into());

			let mut index = 0;
			<BlockTransactions<T>>::mutate(|transactions| {
				let chunks = num_chunks(info.size);
				let total_chunks = transactions.last().map_or(0, |t| t.block_chunks) + chunks;
				index = transactions.len() as u32;
				transactions
					.try_push(TransactionInfo {
						chunk_root: info.chunk_root,
						size: info.size,
						content_hash: info.content_hash,
						block_chunks: total_chunks,
					})
					.map_err(|_| Error::<T>::TooManyTransactions)
			})?;
			Self::deposit_event(Event::Renewed { index });
			Ok(().into())
		}

		/// Check storage proof for block number `block_number() - StoragePeriod`.
		/// If such block does not exist the proof is expected to be `None`.
		/// ## Complexity
		/// - Linear w.r.t the number of indexed transactions in the proved block for random
		///   probing.
		/// There's a DB read for each transaction.
		#[pallet::call_index(2)]
		#[pallet::weight((T::WeightInfo::check_proof_max(), DispatchClass::Mandatory))]
		pub fn check_proof(
			origin: OriginFor<T>,
			proof: TransactionStorageProof,
		) -> DispatchResultWithPostInfo {
			ensure_none(origin)?;
			ensure!(!ProofChecked::<T>::get(), Error::<T>::DoubleCheck);
			let number = <frame_system::Pallet<T>>::block_number();
			let period = <StoragePeriod<T>>::get();
			let target_number = number.saturating_sub(period);
			ensure!(!target_number.is_zero(), Error::<T>::UnexpectedProof);
			let total_chunks = <ChunkCount<T>>::get(target_number);
			ensure!(total_chunks != 0, Error::<T>::UnexpectedProof);
			let parent_hash = <frame_system::Pallet<T>>::parent_hash();
			let selected_chunk_index = random_chunk(parent_hash.as_ref(), total_chunks);
			let (info, chunk_index) = match <Transactions<T>>::get(target_number) {
				Some(infos) => {
					let index = match infos
						.binary_search_by_key(&selected_chunk_index, |info| info.block_chunks)
					{
						Ok(index) => index,
						Err(index) => index,
					};
					let info = infos.get(index).ok_or(Error::<T>::MissingStateData)?.clone();
					let chunks = num_chunks(info.size);
					let prev_chunks = info.block_chunks - chunks;
					(info, selected_chunk_index - prev_chunks)
				},
				None => return Err(Error::<T>::MissingStateData.into()),
			};
			ensure!(
				sp_io::trie::blake2_256_verify_proof(
					info.chunk_root,
					&proof.proof,
					&encode_index(chunk_index),
					&proof.chunk,
					sp_runtime::StateVersion::V1,
				),
				Error::<T>::InvalidProof
			);
			ProofChecked::<T>::put(true);
			Self::deposit_event(Event::ProofChecked);
			Ok(().into())
		}

		/// Authorize the given account to store the given amount of arbitrary data. The
		/// authorization will expire after a configured number of blocks.
		#[pallet::call_index(3)]
		#[pallet::weight(1)] // TODO
		pub fn authorize_account(
			origin: OriginFor<T>,
			who: T::AccountId,
			transactions: u32,
			bytes: u64,
		) -> DispatchResult {
			T::Authorizer::ensure_origin(origin)?;
			Self::authorize(AuthorizationScope::Account(who.clone()), transactions, bytes);
			Self::deposit_event(Event::AccountAuthorized { who, transactions, bytes });
			Ok(())
		}

		/// Authorize anyone to store a preimage of the given hash. The authorization will expire
		/// after a configured number of blocks.
		#[pallet::call_index(4)]
		#[pallet::weight(1)] // TODO
		pub fn authorize_preimage(
			origin: OriginFor<T>,
			hash: ContentHash,
			max_size: u64,
		) -> DispatchResult {
			T::Authorizer::ensure_origin(origin)?;
			Self::authorize(AuthorizationScope::Preimage(hash), 1, max_size);
			Self::deposit_event(Event::PreimageAuthorized { hash, max_size });
			Ok(())
		}
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// Stored data under specified index.
		Stored { index: u32 },
		/// Renewed data under specified index.
		Renewed { index: u32 },
		/// Storage proof was successfully checked.
		ProofChecked,
		/// An account `who` was authorized to store `bytes` bytes in `transactions` transactions.
		AccountAuthorized { who: T::AccountId, transactions: u32, bytes: u64 },
		/// Authorization was given for a preimage of `hash` (not exceeding `max_size`) to be
		/// stored by anyone.
		PreimageAuthorized { hash: ContentHash, max_size: u64 },
	}

	/// Authorization usage by scope.
	#[pallet::storage]
	pub(super) type AuthorizationUsageByScope<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		AuthorizationScope<T::AccountId>,
		AuthorizationUsage,
		ValueQuery,
	>;

	/// Authorizations, keyed by expiry. Authorizations with no expiry are not added. Note that
	/// authorizations are _not_ removed when they are used, only when they expire.
	#[pallet::storage]
	pub(super) type AuthorizationsByExpiry<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		BlockNumberFor<T>,
		BoundedVec<Authorization<T::AccountId>, T::MaxBlockAuthorizationExpiries>,
		ValueQuery,
	>;

	/// Minimum expiry block for new authorizations, minus 1. This usually has no effect; its
	/// purpose is to avoid overflowing the `BoundedVec`s in `AuthorizationsByExpiry`.
	#[pallet::storage]
	pub(super) type MinAuthorizationExpiryMinus1<T: Config> =
		StorageValue<_, BlockNumberFor<T>, ValueQuery>;

	/// Collection of transaction metadata by block number.
	#[pallet::storage]
	#[pallet::getter(fn transaction_roots)]
	pub(super) type Transactions<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		BlockNumberFor<T>,
		BoundedVec<TransactionInfo, T::MaxBlockTransactions>,
		OptionQuery,
	>;

	/// Count indexed chunks for each block.
	#[pallet::storage]
	pub(super) type ChunkCount<T: Config> =
		StorageMap<_, Blake2_128Concat, BlockNumberFor<T>, u32, ValueQuery>;

	/// Storage period for data in blocks. Should match `sp_storage_proof::DEFAULT_STORAGE_PERIOD`
	/// for block authoring.
	#[pallet::storage]
	pub(super) type StoragePeriod<T: Config> = StorageValue<_, BlockNumberFor<T>, ValueQuery>;

	// Intermediates
	#[pallet::storage]
	pub(super) type BlockTransactions<T: Config> =
		StorageValue<_, BoundedVec<TransactionInfo, T::MaxBlockTransactions>, ValueQuery>;

	/// Was the proof checked in this block?
	#[pallet::storage]
	pub(super) type ProofChecked<T: Config> = StorageValue<_, bool, ValueQuery>;

	#[pallet::genesis_config]
	pub struct GenesisConfig<T: Config> {
		pub storage_period: BlockNumberFor<T>,
	}

	impl<T: Config> Default for GenesisConfig<T> {
		fn default() -> Self {
			Self { storage_period: sp_transaction_storage_proof::DEFAULT_STORAGE_PERIOD.into() }
		}
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			<StoragePeriod<T>>::put(self.storage_period);
		}
	}

	#[pallet::inherent]
	impl<T: Config> ProvideInherent for Pallet<T> {
		type Call = Call<T>;
		type Error = InherentError;
		const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;

		fn create_inherent(data: &InherentData) -> Option<Self::Call> {
			let proof = data
				.get_data::<TransactionStorageProof>(&Self::INHERENT_IDENTIFIER)
				.unwrap_or(None);
			proof.map(|proof| Call::check_proof { proof })
		}

		fn check_inherent(
			_call: &Self::Call,
			_data: &InherentData,
		) -> result::Result<(), Self::Error> {
			Ok(())
		}

		fn is_inherent(call: &Self::Call) -> bool {
			matches!(call, Call::check_proof { .. })
		}
	}

	impl<T: Config> Pallet<T> {
		fn authorize(scope: AuthorizationScope<T::AccountId>, transactions: u32, bytes: u64) {
			let period = T::AuthorizationPeriod::get();
			if period.is_zero() {
				return // Authorizations expire immediately
			}

			// Credit scope. Note that it is possible for authorizations to get lost due to the
			// saturating arithmetic.
			AuthorizationUsageByScope::<T>::mutate(scope.clone(), |usage| {
				usage.unused.transactions = usage.unused.transactions.saturating_add(transactions);
				usage.unused.bytes = usage.unused.bytes.saturating_add(bytes);
			});

			// Determine expiry block
			let Some(expiry) = frame_system::Pallet::<T>::block_number().checked_add(&period)
			else {
				return // Authorization never expires
			};
			let Some(min_expiry) =
				MinAuthorizationExpiryMinus1::<T>::get().checked_add(&1u32.into())
			else {
				return // Authorization never expires
			};
			let expiry = expiry.max(min_expiry);

			// Record authorization for expire_authorizations
			let authorization =
				Authorization { scope, extent: AuthorizationExtent { transactions, bytes } };
			AuthorizationsByExpiry::<T>::mutate(expiry, |authorizations| {
				authorizations.try_push(authorization).expect(
					"Whenever a BoundedVec becomes full, MinAuthorizationExpiryMinus1 is bumped. \
					MinAuthorizationExpiryMinus1 never decreases. \
					Thus a full BoundedVec will never be pushed to again.",
				);
				if authorizations.is_full() {
					MinAuthorizationExpiryMinus1::<T>::put(expiry);
				}
			});
		}

		/// Returns the unused extent of (unexpired) authorizations for the given account.
		pub fn unused_account_authorization_extent(who: T::AccountId) -> AuthorizationExtent {
			AuthorizationUsageByScope::<T>::get(AuthorizationScope::Account(who)).unused
		}

		/// Returns the unused extent of (unexpired) authorizations for the given content hash.
		pub fn unused_preimage_authorization_extent(hash: ContentHash) -> AuthorizationExtent {
			AuthorizationUsageByScope::<T>::get(AuthorizationScope::Preimage(hash)).unused
		}

		fn expire_authorizations(block: BlockNumberFor<T>) -> Weight {
			let mut weight = Weight::zero();
			let db_weight = T::DbWeight::get();

			weight.saturating_accrue(db_weight.reads(1));
			for authorization in AuthorizationsByExpiry::<T>::take(block) {
				weight.saturating_accrue(db_weight.reads_writes(1, 1));
				AuthorizationUsageByScope::<T>::mutate_exists(authorization.scope, |usage_slot| {
					if let Some(usage) = usage_slot {
						let unused_transactions = authorization
							.extent
							.transactions
							.saturating_sub(usage.used.transactions);
						let unused_bytes =
							authorization.extent.bytes.saturating_sub(usage.used.bytes);
						usage.used.transactions = usage
							.used
							.transactions
							.saturating_sub(authorization.extent.transactions);
						usage.used.bytes =
							usage.used.bytes.saturating_sub(authorization.extent.bytes);
						usage.unused.transactions =
							usage.unused.transactions.saturating_sub(unused_transactions);
						usage.unused.bytes = usage.unused.bytes.saturating_sub(unused_bytes);
						if *usage == Default::default() {
							*usage_slot = None;
						}
					}
				});
			}

			weight
		}

		fn use_authorization(origin: OriginFor<T>, hash: ContentHash, size: u32) -> DispatchResult {
			let scope = match origin.into() {
				Ok(RawOrigin::Signed(who)) => AuthorizationScope::Account(who),
				Ok(RawOrigin::None) => AuthorizationScope::Preimage(hash),
				_ => return Err(DispatchError::BadOrigin),
			};
			AuthorizationUsageByScope::<T>::try_mutate(scope, |usage| {
				usage.unused.transactions =
					usage.unused.transactions.checked_sub(1).ok_or(Error::<T>::NotAuthorized)?;
				usage.unused.bytes =
					usage.unused.bytes.checked_sub(size.into()).ok_or(Error::<T>::NotAuthorized)?;
				usage.used.transactions = usage.used.transactions.saturating_add(1);
				usage.used.bytes = usage.used.bytes.saturating_add(size.into());
				Ok(())
			})
		}
	}
}
