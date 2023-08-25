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

//! # Validator Set Pallet
//!
//! The Validator Set Pallet allows addition and removal of
//! authorities/validators via extrinsics (transaction calls), in
//! Substrate-based PoA networks. It also integrates with the im-online pallet
//! to automatically remove offline validators.
//!
//! The pallet depends on the Session pallet and implements related traits for session
//! management. Currently it uses periodic session rotation provided by the
//! session pallet to automatically rotate sessions. For this reason, the
//! validator addition and removal becomes effective only after 2 sessions
//! (queuing + applying).

#![cfg_attr(not(feature = "std"), no_std)]

mod benchmarking;
mod mock;
mod tests;
pub mod weights;

use frame_support::{ensure, pallet_prelude::*, traits::Get, DefaultNoBound};
use frame_system::pallet_prelude::*;
pub use pallet::*;
use sp_runtime::Perbill;
use sp_staking::{
	offence::{DisableStrategy, OffenceDetails, OnOffenceHandler},
	SessionIndex,
};
use sp_std::prelude::*;
pub use weights::*;

pub const LOG_TARGET: &str = "runtime::validator-set";

#[frame_support::pallet()]
pub mod pallet {
	use super::*;

	/// Configure the pallet by specifying the parameters and types on which it
	/// depends.
	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_session::Config {
		/// The Event type.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		/// Origin for adding or removing a validator.
		type AddRemoveOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Minimum number of validators to leave in the validator set during
		/// auto removal.
		#[pallet::constant]
		type MinAuthorities: Get<u32>;

		/// Check `MinAuthorities` before removing validators when disabled
		#[pallet::constant]
		type MinAuthoritiesOnDisabled: Get<bool>;

		/// Information on runtime weights.
		type WeightInfo: WeightInfo;
	}

	#[pallet::pallet]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	#[pallet::storage]
	#[pallet::getter(fn validators)]
	pub type Validators<T: Config> = StorageValue<_, Vec<T::ValidatorId>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn disabled_validators)]
	pub type DisabledValidators<T: Config> = StorageValue<_, Vec<T::ValidatorId>, ValueQuery>;

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
		/// Target (post-removal) validator count is below the minimum.
		TooLowValidatorCount,
		/// Validator is already in the validator set.
		Duplicate,
	}

	#[pallet::genesis_config]
	#[derive(DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		pub initial_validators: Vec<T::ValidatorId>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			assert!(
				self.initial_validators.len() >= T::MinAuthorities::get() as usize,
				"Initial set of validators must be at least T::MinAuthorities"
			);
			assert!(<Validators<T>>::get().is_empty(), "Validators are already initialized!");

			<Validators<T>>::put(&self.initial_validators);
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Add a new validator.
		///
		/// New validator's session keys should be set in Session pallet before
		/// calling this.
		///
		/// The origin can be configured using the `AddRemoveOrigin` type in the
		/// host runtime. Can also be set to sudo/root.
		#[pallet::call_index(0)]
		#[pallet::weight(<T as pallet::Config>::WeightInfo::add_validator())]
		pub fn add_validator(origin: OriginFor<T>, validator_id: T::ValidatorId) -> DispatchResult {
			T::AddRemoveOrigin::ensure_origin(origin)?;

			ensure!(!<Validators<T>>::get().contains(&validator_id), Error::<T>::Duplicate);
			<Validators<T>>::mutate(|v| v.push(validator_id.clone()));

			Self::deposit_event(Event::ValidatorAdded(validator_id));
			Ok(())
		}

		/// Remove a validator.
		///
		/// The origin can be configured using the `AddRemoveOrigin` type in the
		/// host runtime. Can also be set to sudo/root.
		#[pallet::call_index(1)]
		#[pallet::weight(<T as pallet::Config>::WeightInfo::remove_validator())]
		pub fn remove_validator(
			origin: OriginFor<T>,
			validator_id: T::ValidatorId,
		) -> DispatchResult {
			T::AddRemoveOrigin::ensure_origin(origin)?;

			let mut validators = <Validators<T>>::get();

			// Ensuring that the post removal, target validator count doesn't go
			// below the minimum.
			ensure!(
				validators.len().saturating_sub(1) >= T::MinAuthorities::get() as usize,
				Error::<T>::TooLowValidatorCount
			);

			validators.retain(|v| *v != validator_id);

			<Validators<T>>::put(validators);

			Self::deposit_event(Event::ValidatorRemoved(validator_id));
			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {
	// Adds disabled validators to a local cache for removal on new session.
	fn mark_disabled_for_removal(validator_id: T::ValidatorId) {
		<DisabledValidators<T>>::mutate(|v| v.push(validator_id));
		log::debug!(target: LOG_TARGET, "Disabled validator marked for auto removal.");
	}

	// Removes disabled validators from the validator set.
	// It is called in the session change hook and removes the validators
	// who were disabled.
	fn remove_disabled_validators() {
		let validators_to_remove = <DisabledValidators<T>>::get();

		match Self::do_remove_validators(&validators_to_remove, T::MinAuthoritiesOnDisabled::get())
		{
			Ok(_) => {
				// Clear the offline validator list to avoid repeated deletion.
				<DisabledValidators<T>>::put(Vec::<T::ValidatorId>::new());
			},
			Err(_) => {
				// Number of active validators was going to drop under `MinAuthorities`
				log::error!(
					target: LOG_TARGET,
					"Number of validators was going to drop below MinAuthorities ({:?}) after removing {:?} disabled validators",
					T::MinAuthorities::get(),
					validators_to_remove.len(),
				);
			},
		}
	}

	fn do_remove_validators(
		validators: &Vec<T::ValidatorId>,
		check_min_authorities: bool,
	) -> Result<(), DispatchError> {
		let validators_len_to_remove = validators.len();
		let current_validators_len = Self::validators().len();

		if check_min_authorities {
			if let Some(validators_left_len) =
				current_validators_len.checked_sub(validators_len_to_remove)
			{
				ensure!(
					validators_left_len >= T::MinAuthorities::get() as usize,
					Error::<T>::TooLowValidatorCount
				);
			}
		}

		<Validators<T>>::mutate(|vs| vs.retain(|v| !validators.contains(v)));

		log::debug!(
			target: LOG_TARGET,
			"Initiated removal of {:?} validators.",
			validators.len(),
		);

		Ok(())
	}
}

// Provides the new set of validators to the session module when session is
// being rotated.
impl<T: Config> pallet_session::SessionManager<T::ValidatorId> for Pallet<T> {
	// Plan a new session and provide new validator set.
	fn new_session(_new_index: u32) -> Option<Vec<T::ValidatorId>> {
		// Remove any disabled validators. This will only work when the runtime
		// also has the offences and session::historical pallets
		Self::remove_disabled_validators();

		log::debug!(target: LOG_TARGET, "New session called; updated validator set provided.");

		Some(Self::validators())
	}

	fn end_session(_end_index: u32) {}

	fn start_session(_start_index: u32) {}
}

// Implementation of `OnOffenceHandler`.
// This is for the Offences + Historical pallets integration.
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
		_slash_fraction: &[Perbill],
		_slash_session: SessionIndex,
		disable_strategy: DisableStrategy,
	) -> Weight {
		let mut weight = Weight::zero();
		let db_weight = T::DbWeight::get();

		offenders.iter().for_each(|o| {
			let offender = o.offender.clone();

			match disable_strategy {
				DisableStrategy::WhenSlashed | DisableStrategy::Always => {
					if pallet_session::Pallet::<T>::disable(&offender.0) {
						// Validator was not yet disabled, it is added to pallet_session
						// `DisabledValidators`
						weight.saturating_accrue(db_weight.reads_writes(1, 1));
						// Validator is added to local `DisabledValidators`
						Self::mark_disabled_for_removal(offender.0.clone());
						weight.saturating_accrue(db_weight.reads_writes(1, 1));
					} else {
						// Validator was already disabled, it is not added to `DisabledValidators`
						// (no writes)
						weight.saturating_accrue(db_weight.reads(1));
					}
				},
				DisableStrategy::Never => {},
			}
		});

		weight
	}
}
