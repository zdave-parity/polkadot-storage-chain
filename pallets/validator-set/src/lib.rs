// Copyright (C) Gautam Dhameja.
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

//! Validator set pallet. Maintains a set of validators which can be added to or removed from by a
//! privileged origin.
//!
//! Provides a [`SessionManager`] implementation which returns the current validator set from
//! `new_session`. Also provides an [`OnOffenceHandler`] implementation which removes the offending
//! validators from the set (if they would be slashed) and temporarily disables them according to
//! the [`DisableStrategy`].
//!
//! This pallet directly depends on [`pallet_session`] and [`pallet_session::historical`].

#![cfg_attr(not(feature = "std"), no_std)]

mod benchmarking;
mod mock;
mod tests;
pub mod weights;

use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{ensure, pallet_prelude::Weight, traits::Get, DefaultNoBound};
pub use pallet::*;
use pallet_session::SessionManager;
use sp_runtime::Perbill;
use sp_staking::{
	offence::{DisableStrategy, OffenceDetails, OnOffenceHandler},
	SessionIndex,
};
use sp_std::vec::Vec;
pub use weights::WeightInfo;

/// Per-validator data stored by this pallet.
#[derive(Encode, Decode, scale_info::TypeInfo, MaxEncodedLen)]
struct Validator;

#[frame_support::pallet()]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_session::Config {
		/// The overarching event type.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		/// Weight information for extrinsics in this pallet.
		type WeightInfo: WeightInfo;

		/// Origin for adding or removing a validator.
		type AddRemoveOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Maximum number of validators.
		#[pallet::constant]
		type MaxAuthorities: Get<u32>;
	}

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	/// Validator set. Changes to this will take effect in the session after next.
	#[pallet::storage]
	pub(super) type Validators<T: Config> =
		StorageMap<_, Blake2_128Concat, T::ValidatorId, Validator, OptionQuery>;

	/// Number of validators in `Validators`.
	#[pallet::storage]
	pub(super) type NumValidators<T: Config> = StorageValue<_, u32, ValueQuery>;

	/// Validators that should be disabled in the next session.
	///
	/// Validator removal takes effect in the session after next. Validator disabling takes effect
	/// until the end of the session. We extend disables to cover the next session as well (by
	/// adding validators here when we disable them) so that when a validator is both disabled and
	/// removed in response to an offence, there isn't a gap where it is actually present and
	/// enabled.
	#[pallet::storage]
	pub(super) type NextDisabledValidators<T: Config> =
		StorageMap<_, Blake2_128Concat, T::ValidatorId, (), OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// New validator added. Effective in session after next.
		ValidatorAdded(T::ValidatorId),
		/// Validator removed. Effective in session after next.
		ValidatorRemoved(T::ValidatorId),
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Validator is already in the validator set.
		Duplicate,
		/// Validator is not in the validator set.
		NotAValidator,
		/// Adding the validator would take the validator count above the maximum.
		TooManyValidators,
	}

	#[pallet::genesis_config]
	#[derive(DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		pub initial_validators: BoundedVec<T::ValidatorId, T::MaxAuthorities>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			assert!(Validators::<T>::iter().next().is_none(), "Validators are already initialized");
			assert_eq!(NumValidators::<T>::get(), 0);
			for validator_id in &self.initial_validators {
				Validators::<T>::mutate(validator_id, |validator| {
					assert!(
						validator.is_none(),
						"Validator appears twice in initial set of validators"
					);
					*validator = Some(Validator);
				});
			}
			NumValidators::<T>::put(self.initial_validators.len() as u32);
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Add a new validator.
		///
		/// The addition will take effect the session after next.
		///
		/// The origin for this call must be the pallet's `AddRemoveOrigin`. Emits
		/// [`ValidatorAdded`](Event::ValidatorAdded) when successful.
		#[pallet::call_index(0)]
		#[pallet::weight(<T as Config>::WeightInfo::add_validator())]
		pub fn add_validator(origin: OriginFor<T>, validator_id: T::ValidatorId) -> DispatchResult {
			T::AddRemoveOrigin::ensure_origin(origin)?;

			Validators::<T>::mutate(&validator_id, |validator| {
				if !validator.is_none() {
					return Err(Error::<T>::Duplicate)
				}
				*validator = Some(Validator);
				Ok(())
			})?;
			NumValidators::<T>::mutate(|num| {
				if *num >= T::MaxAuthorities::get() {
					return Err(Error::<T>::TooManyValidators)
				}
				*num += 1;
				Ok(())
			})?;

			Self::deposit_event(Event::ValidatorAdded(validator_id));
			Ok(())
		}

		/// Remove a validator.
		///
		/// The removal will take effect the session after next.
		///
		/// The origin for this call must be the pallet's `AddRemoveOrigin`. Emits
		/// [`ValidatorRemoved`](Event::ValidatorRemoved) when successful.
		#[pallet::call_index(1)]
		#[pallet::weight(<T as Config>::WeightInfo::remove_validator())]
		pub fn remove_validator(
			origin: OriginFor<T>,
			validator_id: T::ValidatorId,
		) -> DispatchResult {
			T::AddRemoveOrigin::ensure_origin(origin)?;

			ensure!(Validators::<T>::take(&validator_id).is_some(), Error::<T>::NotAValidator);
			NumValidators::<T>::mutate(|num| *num -= 1);

			Self::deposit_event(Event::ValidatorRemoved(validator_id));
			Ok(())
		}
	}
}

impl<T: Config> SessionManager<T::ValidatorId> for Pallet<T> {
	fn new_session(_new_index: SessionIndex) -> Option<Vec<T::ValidatorId>> {
		Some(Validators::<T>::iter_keys().collect())
	}

	fn end_session(_end_index: SessionIndex) {}

	fn start_session(_start_index: SessionIndex) {
		for (validator_id, _) in NextDisabledValidators::<T>::drain() {
			pallet_session::Pallet::<T>::disable(&validator_id);
		}
	}
}

impl<T: Config>
	OnOffenceHandler<T::AccountId, pallet_session::historical::IdentificationTuple<T>, Weight>
	for Pallet<T>
where
	T: pallet_session::historical::Config,
{
	fn on_offence(
		offenders: &[OffenceDetails<
			T::AccountId,
			pallet_session::historical::IdentificationTuple<T>,
		>],
		slash_fractions: &[Perbill],
		_slash_session: SessionIndex,
		disable_strategy: DisableStrategy,
	) -> Weight {
		let mut weight = Weight::zero();
		let db_weight = T::DbWeight::get();

		for (offender, slash_fraction) in offenders.iter().zip(slash_fractions) {
			// Determine actions to take with this validator
			let remove = !slash_fraction.is_zero();
			let disable = match disable_strategy {
				DisableStrategy::Never => false,
				DisableStrategy::WhenSlashed => !slash_fraction.is_zero(),
				DisableStrategy::Always => true,
			};

			if remove {
				// Note that the validator might already have been removed (explicitly, for another
				// offence, or even by an earlier report of this offence)
				weight.saturating_accrue(db_weight.reads_writes(1, 1));
				if Validators::<T>::take(&offender.offender.0).is_some() {
					weight.saturating_accrue(db_weight.reads_writes(1, 1));
					NumValidators::<T>::mutate(|num| *num -= 1);
				}
			}

			if disable {
				// Lookup validator index in Validators, check if in DisabledValidators
				weight.saturating_accrue(db_weight.reads(2));
				if pallet_session::Pallet::<T>::disable(&offender.offender.0) {
					// Added to DisabledValidators
					weight.saturating_accrue(db_weight.writes(1));
				}

				// Also disable in the next session, as removal won't take effect until the session
				// after next
				weight.saturating_accrue(db_weight.writes(1));
				NextDisabledValidators::<T>::insert(&offender.offender.0, ());
			}
		}

		weight
	}
}
