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

//! Tests for transction-storage pallet.

use super::{Pallet as TransactionStorage, *};
use crate::mock::*;
use frame_support::{assert_noop, assert_ok};
use frame_system::RawOrigin;
use sp_core::blake2_256;
use sp_runtime::traits::{Dispatchable, ValidateUnsigned};
use sp_transaction_storage_proof::registration::build_proof;

const MAX_DATA_SIZE: u32 = DEFAULT_MAX_TRANSACTION_SIZE;

#[test]
fn discards_data() {
	new_test_ext().execute_with(|| {
		run_to_block(1, || None);
		assert_ok!(TransactionStorage::<Test>::store(RawOrigin::None.into(), vec![0u8; 2000]));
		assert_ok!(TransactionStorage::<Test>::store(RawOrigin::None.into(), vec![0u8; 2000]));
		let proof_provider = || {
			let block_num = <frame_system::Pallet<Test>>::block_number();
			if block_num == 11 {
				let parent_hash = <frame_system::Pallet<Test>>::parent_hash();
				Some(
					build_proof(parent_hash.as_ref(), vec![vec![0u8; 2000], vec![0u8; 2000]])
						.unwrap(),
				)
			} else {
				None
			}
		};
		run_to_block(11, proof_provider);
		assert!(Transactions::<Test>::get(1).is_some());
		let transactions = Transactions::<Test>::get(1).unwrap();
		assert_eq!(transactions.len(), 2);
		assert_eq!(ChunkCount::<Test>::get(1), 16);
		run_to_block(12, proof_provider);
		assert!(Transactions::<Test>::get(1).is_none());
		assert_eq!(ChunkCount::<Test>::get(1), 0);
	});
}

#[test]
fn uses_account_authorization() {
	new_test_ext().execute_with(|| {
		run_to_block(1, || None);
		let caller = 1;
		assert_ok!(TransactionStorage::<Test>::authorize_account(
			RawOrigin::Root.into(),
			caller,
			2,
			2001
		));
		assert_eq!(
			TransactionStorage::<Test>::account_authorization_extent(caller),
			AuthorizationExtent { transactions: 2, bytes: 2001 }
		);
		let call = Call::<Test>::store { data: vec![0u8; 2000] };
		assert_noop!(
			TransactionStorage::<Test>::pre_dispatch_signed(&5, &call),
			InvalidTransaction::Payment,
		);
		assert_ok!(TransactionStorage::<Test>::pre_dispatch_signed(&caller, &call));
		assert_eq!(
			TransactionStorage::<Test>::account_authorization_extent(caller),
			AuthorizationExtent { transactions: 1, bytes: 1 }
		);
		let call = Call::<Test>::store { data: vec![0u8; 2] };
		assert_noop!(
			TransactionStorage::<Test>::pre_dispatch_signed(&caller, &call),
			InvalidTransaction::Payment,
		);
	});
}

#[test]
fn uses_preimage_authorization() {
	new_test_ext().execute_with(|| {
		run_to_block(1, || None);
		let data = vec![2; 2000];
		let hash = blake2_256(&data);
		assert_ok!(TransactionStorage::<Test>::authorize_preimage(
			RawOrigin::Root.into(),
			hash,
			2002
		));
		assert_eq!(
			TransactionStorage::<Test>::preimage_authorization_extent(hash),
			AuthorizationExtent { transactions: 1, bytes: 2002 }
		);
		let call = Call::<Test>::store { data: vec![1; 2000] };
		assert_noop!(TransactionStorage::<Test>::pre_dispatch(&call), InvalidTransaction::Payment);
		let call = Call::<Test>::store { data };
		assert_ok!(TransactionStorage::<Test>::pre_dispatch(&call));
		assert_eq!(
			TransactionStorage::<Test>::preimage_authorization_extent(hash),
			AuthorizationExtent { transactions: 0, bytes: 0 }
		);
		assert_ok!(Into::<RuntimeCall>::into(call).dispatch(RawOrigin::None.into()));
		run_to_block(3, || None);
		let call = Call::<Test>::renew { block: 1, index: 0 };
		assert_noop!(TransactionStorage::<Test>::pre_dispatch(&call), InvalidTransaction::Payment);
		assert_ok!(TransactionStorage::<Test>::authorize_preimage(
			RawOrigin::Root.into(),
			hash,
			2000
		));
		assert_ok!(TransactionStorage::<Test>::pre_dispatch(&call));
		assert_eq!(
			TransactionStorage::<Test>::preimage_authorization_extent(hash),
			AuthorizationExtent { transactions: 0, bytes: 0 }
		);
	});
}

#[test]
fn checks_proof() {
	new_test_ext().execute_with(|| {
		run_to_block(1, || None);
		assert_ok!(TransactionStorage::<Test>::store(
			RawOrigin::None.into(),
			vec![0u8; MAX_DATA_SIZE as usize]
		));
		run_to_block(10, || None);
		let parent_hash = <frame_system::Pallet<Test>>::parent_hash();
		let proof =
			build_proof(parent_hash.as_ref(), vec![vec![0u8; MAX_DATA_SIZE as usize]]).unwrap();
		assert_noop!(
			TransactionStorage::<Test>::check_proof(RuntimeOrigin::none(), proof),
			Error::<Test>::UnexpectedProof,
		);
		run_to_block(11, || None);
		let parent_hash = <frame_system::Pallet<Test>>::parent_hash();

		let invalid_proof = build_proof(parent_hash.as_ref(), vec![vec![0u8; 1000]]).unwrap();
		assert_noop!(
			TransactionStorage::<Test>::check_proof(RuntimeOrigin::none(), invalid_proof),
			Error::<Test>::InvalidProof,
		);

		let proof =
			build_proof(parent_hash.as_ref(), vec![vec![0u8; MAX_DATA_SIZE as usize]]).unwrap();
		assert_ok!(TransactionStorage::<Test>::check_proof(RuntimeOrigin::none(), proof));
	});
}

#[test]
fn renews_data() {
	new_test_ext().execute_with(|| {
		run_to_block(1, || None);
		assert_ok!(TransactionStorage::<Test>::store(RawOrigin::None.into(), vec![0u8; 2000]));
		let info = BlockTransactions::<Test>::get().last().unwrap().clone();
		run_to_block(6, || None);
		assert_ok!(TransactionStorage::<Test>::renew(
			RawOrigin::None.into(),
			1, // block
			0, // transaction
		));
		let proof_provider = || {
			let block_num = <frame_system::Pallet<Test>>::block_number();
			if block_num == 11 || block_num == 16 {
				let parent_hash = <frame_system::Pallet<Test>>::parent_hash();
				Some(build_proof(parent_hash.as_ref(), vec![vec![0u8; 2000]]).unwrap())
			} else {
				None
			}
		};
		run_to_block(16, proof_provider);
		assert!(Transactions::<Test>::get(1).is_none());
		assert_eq!(Transactions::<Test>::get(6).unwrap().get(0), Some(info).as_ref());
		run_to_block(17, proof_provider);
		assert!(Transactions::<Test>::get(6).is_none());
	});
}

#[test]
fn authorization_expires() {
	new_test_ext().execute_with(|| {
		run_to_block(1, || None);
		let who = 1;
		assert_ok!(TransactionStorage::<Test>::authorize_account(
			RawOrigin::Root.into(),
			who,
			1,
			2000
		));
		assert_eq!(
			TransactionStorage::<Test>::account_authorization_extent(who),
			AuthorizationExtent { transactions: 1, bytes: 2000 },
		);
		let call = Call::<Test>::store { data: vec![0; 2000] };
		assert_ok!(TransactionStorage::<Test>::validate_signed(&who, &call));
		run_to_block(10, || None);
		assert_eq!(
			TransactionStorage::<Test>::account_authorization_extent(who),
			AuthorizationExtent { transactions: 1, bytes: 2000 },
		);
		assert_ok!(TransactionStorage::<Test>::validate_signed(&who, &call));
		run_to_block(11, || None);
		assert_eq!(
			TransactionStorage::<Test>::account_authorization_extent(who),
			AuthorizationExtent { transactions: 0, bytes: 0 },
		);
		assert_noop!(
			TransactionStorage::<Test>::validate_signed(&who, &call),
			InvalidTransaction::Payment
		);
	});
}
