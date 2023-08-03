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
use frame_support::dispatch::{Dispatchable, GetDispatchInfo};
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

/// Authorization token counts.
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
struct Tokens {
	/// Number of transactions.
	transactions: u32,
	/// Number of bytes.
	bytes: u64,
}

/// Data associated with an `AccountId`.
#[derive(Default, PartialEq, Eq, Encode, Decode, scale_info::TypeInfo, MaxEncodedLen)]
struct Account {
	/// Spent token count. When a token grant expires, it will consume tokens from this pool first.
	spent: Tokens,
	/// Unspent token count.
	unspent: Tokens,
}

/// Authorization token grant.
#[derive(sp_runtime::RuntimeDebug, Encode, Decode, scale_info::TypeInfo, MaxEncodedLen)]
struct Grant<AccountId> {
	/// Recipient of the tokens.
	who: AccountId,
	/// Token count.
	amount: Tokens,
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

#[frame_support::pallet]
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
		/// Maximum number of grant expiries per block. Grants will be extended to avoid exceeding
		/// this limit.
		type MaxBlockExpiries: Get<u32>;
		/// Grants expire after this many blocks.
		type GrantPeriod: Get<BlockNumberFor<Self>>;
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Account has no transaction authorization tokens.
		NoTransactionTokens,
		/// Account has too few byte authorization tokens.
		InsufficientByteTokens,
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
			weight += db_weight.reads(1);
			let period = <StoragePeriod<T>>::get();
			let obsolete = n.saturating_sub(period.saturating_add(One::one()));
			if obsolete > Zero::zero() {
				weight += db_weight.writes(2);
				<Transactions<T>>::remove(obsolete);
				<ChunkCount<T>>::remove(obsolete);
			}

			weight += Self::expire_grants(n);

			// For `on_finalize`
			weight += db_weight.reads_writes(2, 2);

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
			ensure!(data.len() > 0, Error::<T>::EmptyTransaction);
			ensure!(
				data.len() <= T::MaxTransactionSize::get() as usize,
				Error::<T>::TransactionTooLarge
			);
			let sender = ensure_signed(origin)?;
			Self::apply_fee(sender, data.len() as u32)?;

			// Chunk data and compute storage root
			let chunk_count = num_chunks(data.len() as u32);
			let chunks = data.chunks(CHUNK_SIZE).map(|c| c.to_vec()).collect();
			let root = sp_io::trie::blake2_256_ordered_root(chunks, sp_runtime::StateVersion::V1);

			let content_hash = sp_io::hashing::blake2_256(&data);
			let extrinsic_index =
				<frame_system::Pallet<T>>::extrinsic_index().ok_or(Error::<T>::BadContext)?;
			sp_io::transaction_index::index(extrinsic_index, data.len() as u32, content_hash);

			let mut index = 0;
			<BlockTransactions<T>>::mutate(|transactions| {
				if transactions.len() + 1 > T::MaxBlockTransactions::get() as usize {
					return Err(Error::<T>::TooManyTransactions)
				}
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
		/// Applies same fees as `store`.
		/// ## Complexity
		/// - O(1).
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::renew())]
		pub fn renew(
			origin: OriginFor<T>,
			block: BlockNumberFor<T>,
			index: u32,
		) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin)?;
			let transactions = <Transactions<T>>::get(block).ok_or(Error::<T>::RenewedNotFound)?;
			let info = transactions.get(index as usize).ok_or(Error::<T>::RenewedNotFound)?;
			let extrinsic_index =
				<frame_system::Pallet<T>>::extrinsic_index().ok_or(Error::<T>::BadContext)?;

			Self::apply_fee(sender, info.size)?;

			sp_io::transaction_index::renew(extrinsic_index, info.content_hash.into());

			let mut index = 0;
			<BlockTransactions<T>>::mutate(|transactions| {
				if transactions.len() + 1 > T::MaxBlockTransactions::get() as usize {
					return Err(Error::<T>::TooManyTransactions)
				}
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
	}

	/// Account data.
	#[pallet::storage]
	pub(super) type Accounts<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, Account, ValueQuery>;

	/// Authorization token grants, keyed by expiry. Grants are _not_ removed when they are spent,
	/// only when they expire.
	#[pallet::storage]
	pub(super) type Grants<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		BlockNumberFor<T>,
		BoundedVec<Grant<T::AccountId>, T::MaxBlockExpiries>,
		ValueQuery,
	>;

	/// Minimum expiry block for new grants, minus 1. This usually has no effect; its purpose is to
	/// avoid overflowing the `BoundedVec`s in `Grants`.
	#[pallet::storage]
	pub(super) type MinGrantExpiryMinus1<T: Config> =
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
			<StoragePeriod<T>>::put(&self.storage_period);
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
		/// Grant authorization tokens to the specified account. Grants expire after a configured
		/// number of blocks.
		pub fn authorize(who: T::AccountId, transactions: u32, bytes: u64) {
			let grant_period = T::GrantPeriod::get();
			if grant_period.is_zero() {
				return // Grants expire immediately
			}

			// Credit account. Note that it is possible for tokens to get lost due to the
			// saturating arithmetic.
			Accounts::<T>::mutate(who.clone(), |account| {
				account.unspent.transactions =
					account.unspent.transactions.saturating_add(transactions);
				account.unspent.bytes = account.unspent.bytes.saturating_add(bytes);
			});

			// Determine grant expiry block
			let Some(expiry) = frame_system::Pallet::<T>::block_number().checked_add(&grant_period)
			else {
				return // Grant never expires
			};
			let Some(min_grant_expiry) = MinGrantExpiryMinus1::<T>::get().checked_add(&1u32.into())
			else {
				return // Grant never expires
			};
			let expiry = expiry.max(min_grant_expiry);

			// Record grant
			let grant = Grant { who, amount: Tokens { transactions, bytes } };
			Grants::<T>::mutate(expiry, |grants| {
				grants.try_push(grant).expect(
					"Whenever a BoundedVec becomes full, MinGrantExpiryMinus1 is bumped. \
						MinGrantExpiryMinus1 never decreases. \
						Thus a full BoundedVec will never be pushed to again.",
				);
				if grants.is_full() {
					MinGrantExpiryMinus1::<T>::put(expiry);
				}
			});
		}

		fn expire_grants(block: BlockNumberFor<T>) -> Weight {
			let mut weight = Weight::zero();
			let db_weight = T::DbWeight::get();

			weight += db_weight.reads(1);
			for grant in Grants::<T>::take(block) {
				weight += db_weight.reads_writes(1, 1);
				Accounts::<T>::mutate_exists(grant.who, |account_slot| {
					if let Some(account) = account_slot {
						let unspent_transactions =
							grant.amount.transactions.saturating_sub(account.spent.transactions);
						let unspent_bytes = grant.amount.bytes.saturating_sub(account.spent.bytes);
						account.spent.transactions =
							account.spent.transactions.saturating_sub(grant.amount.transactions);
						account.spent.bytes =
							account.spent.bytes.saturating_sub(grant.amount.bytes);
						account.unspent.transactions =
							account.unspent.transactions.saturating_sub(unspent_transactions);
						account.unspent.bytes = account.unspent.bytes.saturating_sub(unspent_bytes);
						if *account == Default::default() {
							*account_slot = None;
						}
					}
				});
			}

			weight
		}

		fn apply_fee(sender: T::AccountId, size: u32) -> DispatchResult {
			Accounts::<T>::try_mutate(sender, |account| {
				account.unspent.transactions = account
					.unspent
					.transactions
					.checked_sub(1)
					.ok_or(Error::<T>::NoTransactionTokens)?;
				account.unspent.bytes = account
					.unspent
					.bytes
					.checked_sub(size.into())
					.ok_or(Error::<T>::InsufficientByteTokens)?;
				account.spent.transactions = account.spent.transactions.saturating_add(1);
				account.spent.bytes = account.spent.bytes.saturating_add(size.into());
				Ok(())
			})
		}
	}
}
