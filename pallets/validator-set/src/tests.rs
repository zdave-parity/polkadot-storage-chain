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

//! Tests for the Validator Set pallet.

#![cfg(test)]

use super::*;
use crate::mock::{authorities, new_test_ext, RuntimeOrigin, Session, Test, ValidatorSet};
use frame_support::{assert_noop, assert_ok, pallet_prelude::*};
use sp_runtime::testing::UintAuthorityId;

#[test]
fn simple_setup_should_work() {
	new_test_ext().execute_with(|| {
		assert_eq!(authorities(), vec![UintAuthorityId(1), UintAuthorityId(2), UintAuthorityId(3)]);
		assert_eq!(ValidatorSet::validators(), vec![1u64, 2u64, 3u64]);
		assert_eq!(Session::validators(), vec![1, 2, 3]);
	});
}

#[test]
fn add_validator_updates_validators_list() {
	new_test_ext().execute_with(|| {
		assert_ok!(ValidatorSet::add_validator(RuntimeOrigin::root(), 4));
		assert_eq!(ValidatorSet::validators(), vec![1u64, 2u64, 3u64, 4u64])
	});
}

#[test]
fn remove_validator_updates_validators_list() {
	new_test_ext().execute_with(|| {
		assert_ok!(ValidatorSet::remove_validator(RuntimeOrigin::root(), 2));
		assert_eq!(ValidatorSet::validators(), &[1, 3]);
		// Add validator again
		assert_ok!(ValidatorSet::add_validator(RuntimeOrigin::root(), 2));
		assert_eq!(ValidatorSet::validators(), &[1, 3, 2]);
	});
}

#[test]
fn add_validator_fails_with_invalid_origin() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ValidatorSet::add_validator(RuntimeOrigin::signed(1), 4),
			DispatchError::BadOrigin
		);
	});
}

#[test]
fn remove_validator_fails_with_invalid_origin() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ValidatorSet::remove_validator(RuntimeOrigin::signed(1), 4),
			DispatchError::BadOrigin
		);
	});
}

#[test]
fn duplicate_check() {
	new_test_ext().execute_with(|| {
		assert_ok!(ValidatorSet::add_validator(RuntimeOrigin::root(), 4));
		assert_eq!(ValidatorSet::validators(), vec![1u64, 2u64, 3u64, 4u64]);
		assert_noop!(
			ValidatorSet::add_validator(RuntimeOrigin::root(), 4),
			Error::<Test>::Duplicate
		);
	});
}
