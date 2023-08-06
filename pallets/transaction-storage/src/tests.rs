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
use sp_transaction_storage_proof::registration::build_proof;

const MAX_DATA_SIZE: u32 = DEFAULT_MAX_TRANSACTION_SIZE;

#[test]
fn discards_data() {
	new_test_ext().execute_with(|| {
		run_to_block(1, || None);
		let caller = 1;
		assert_ok!(TransactionStorage::<Test>::authorize_account(
			RawOrigin::Root.into(),
			caller,
			2,
			4000
		));
		assert_ok!(TransactionStorage::<Test>::store(
			RawOrigin::Signed(caller).into(),
			vec![0u8; 2000]
		));
		assert_ok!(TransactionStorage::<Test>::store(
			RawOrigin::Signed(caller).into(),
			vec![0u8; 2000]
		));
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
		let transctions = Transactions::<Test>::get(1).unwrap();
		assert_eq!(transctions.len(), 2);
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
			2000
		));
		assert_eq!(
			TransactionStorage::<Test>::unused_account_authorization_extent(caller),
			AuthorizationExtent { transactions: 2, bytes: 2000 }
		);
		assert_noop!(
			TransactionStorage::<Test>::store(RawOrigin::Signed(5).into(), vec![0u8; 2000]),
			Error::<Test>::NotAuthorized,
		);
		assert_ok!(TransactionStorage::<Test>::store(
			RawOrigin::Signed(caller).into(),
			vec![0u8; 2000]
		));
		assert_eq!(
			TransactionStorage::<Test>::unused_account_authorization_extent(caller),
			AuthorizationExtent { transactions: 1, bytes: 0 }
		);
		assert_noop!(
			TransactionStorage::<Test>::store(RawOrigin::Signed(caller).into(), vec![0u8; 1]),
			Error::<Test>::NotAuthorized,
		);
	});
}

#[test]
fn uses_preimage_authorization() {
	new_test_ext().execute_with(|| {
		run_to_block(1, || None);
		let data = vec![2; 2000];
		let preimage = blake2_256(&data);
		assert_ok!(TransactionStorage::<Test>::authorize_preimage(
			RawOrigin::Root.into(),
			preimage,
			2002
		));
		assert_eq!(
			TransactionStorage::<Test>::unused_preimage_authorization_extent(preimage),
			AuthorizationExtent { transactions: 1, bytes: 2002 }
		);
		assert_noop!(
			TransactionStorage::<Test>::store(RawOrigin::None.into(), vec![1; 2000]),
			Error::<Test>::NotAuthorized,
		);
		assert_ok!(TransactionStorage::<Test>::store(RawOrigin::None.into(), data.clone()));
		assert_eq!(
			TransactionStorage::<Test>::unused_preimage_authorization_extent(preimage),
			AuthorizationExtent { transactions: 0, bytes: 2 }
		);
		run_to_block(3, || None);
		assert_noop!(
			TransactionStorage::<Test>::renew(
				RawOrigin::None.into(),
				1, // block
				0, // transaction
			),
			Error::<Test>::NotAuthorized,
		);
		assert_ok!(TransactionStorage::<Test>::authorize_preimage(
			RawOrigin::Root.into(),
			preimage,
			2000
		));
		assert_ok!(TransactionStorage::<Test>::renew(
			RawOrigin::None.into(),
			1, // block
			0, // transaction
		));
		assert_eq!(
			TransactionStorage::<Test>::unused_preimage_authorization_extent(preimage),
			AuthorizationExtent { transactions: 0, bytes: 2 }
		);
	});
}

#[test]
fn checks_proof() {
	new_test_ext().execute_with(|| {
		run_to_block(1, || None);
		let caller = 1;
		assert_ok!(TransactionStorage::<Test>::authorize_account(
			RawOrigin::Root.into(),
			caller,
			1,
			MAX_DATA_SIZE.into()
		));
		assert_ok!(TransactionStorage::<Test>::store(
			RawOrigin::Signed(caller).into(),
			vec![0u8; MAX_DATA_SIZE as usize]
		));
		run_to_block(10, || None);
		let parent_hash = <frame_system::Pallet<Test>>::parent_hash();
		let proof =
			build_proof(parent_hash.as_ref(), vec![vec![0u8; MAX_DATA_SIZE as usize]]).unwrap();
		assert_noop!(
			TransactionStorage::<Test>::check_proof(RuntimeOrigin::none(), proof,),
			Error::<Test>::UnexpectedProof,
		);
		run_to_block(11, || None);
		let parent_hash = <frame_system::Pallet<Test>>::parent_hash();

		let invalid_proof = build_proof(parent_hash.as_ref(), vec![vec![0u8; 1000]]).unwrap();
		assert_noop!(
			TransactionStorage::<Test>::check_proof(RuntimeOrigin::none(), invalid_proof,),
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
		let caller = 1;
		assert_ok!(TransactionStorage::<Test>::authorize_account(
			RawOrigin::Root.into(),
			caller,
			4,
			4009
		));
		assert_ok!(TransactionStorage::<Test>::store(
			RawOrigin::Signed(caller).into(),
			vec![0u8; 2000]
		));
		let info = BlockTransactions::<Test>::get().last().unwrap().clone();
		run_to_block(6, || None);
		assert_ok!(TransactionStorage::<Test>::renew(
			RawOrigin::Signed(caller).into(),
			1, // block
			0, // transaction
		));
		assert_eq!(
			TransactionStorage::<Test>::unused_account_authorization_extent(caller),
			AuthorizationExtent { transactions: 2, bytes: 9 },
		);
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
			TransactionStorage::<Test>::unused_account_authorization_extent(who),
			AuthorizationExtent { transactions: 1, bytes: 2000 },
		);
		run_to_block(10, || None);
		assert_eq!(
			TransactionStorage::<Test>::unused_account_authorization_extent(who),
			AuthorizationExtent { transactions: 1, bytes: 2000 },
		);
		run_to_block(11, || None);
		assert_eq!(
			TransactionStorage::<Test>::unused_account_authorization_extent(who),
			AuthorizationExtent { transactions: 0, bytes: 0 },
		);
	});
}

#[test]
fn handles_surge_by_pushing_expiration() {
	new_test_ext().execute_with(|| {
		run_to_block(1, || None);

		// type MaxBlockAuthorizationExpiries = ConstU32<10>;
		// type StoragePeriod = ConstU64<10>;

		// Expect first 10 to be "normal", next 10 to be pushed 1 block, etc.
		for ii in 0..30 {
			assert_ok!(TransactionStorage::<Test>::authorize_account(
				RawOrigin::Root.into(),
				ii,
				1,
				2000
			));
			if ii < 10 {
				System::assert_last_event(RuntimeEvent::TransactionStorage(
					crate::Event::AccountUploadAuthorized {
						who: ii,
						transactions: 1,
						bytes: 2000,
						expiry: 11,
					},
				));
			} else if ii < 20 {
				System::assert_last_event(RuntimeEvent::TransactionStorage(
					crate::Event::AccountUploadAuthorized {
						who: ii,
						transactions: 1,
						bytes: 2000,
						expiry: 12,
					},
				));
			} else {
				System::assert_last_event(RuntimeEvent::TransactionStorage(
					crate::Event::AccountUploadAuthorized {
						who: ii,
						transactions: 1,
						bytes: 2000,
						expiry: 13,
					},
				));
			}
		}

		// Another burst.
		run_to_block(5, || None);
		for ii in 30..50 {
			assert_ok!(TransactionStorage::<Test>::authorize_account(
				RawOrigin::Root.into(),
				ii,
				1,
				2000
			));
			if ii < 40 {
				System::assert_last_event(RuntimeEvent::TransactionStorage(
					crate::Event::AccountUploadAuthorized {
						who: ii,
						transactions: 1,
						bytes: 2000,
						expiry: 15,
					},
				));
			} else {
				System::assert_last_event(RuntimeEvent::TransactionStorage(
					crate::Event::AccountUploadAuthorized {
						who: ii,
						transactions: 1,
						bytes: 2000,
						expiry: 16,
					},
				));
			}
		}

		run_to_block(11, || None);
		for ii in 0..50 {
			if ii < 10 {
				// should have expired
				assert_eq!(
					TransactionStorage::<Test>::unused_account_authorization_extent(ii),
					AuthorizationExtent { transactions: 0, bytes: 0 },
				);
			} else {
				// still there
				assert_eq!(
					TransactionStorage::<Test>::unused_account_authorization_extent(ii),
					AuthorizationExtent { transactions: 1, bytes: 2000 },
				);
			}
		}

		run_to_block(12, || None);
		for ii in 0..50 {
			if ii < 20 {
				// expired
				assert_eq!(
					TransactionStorage::<Test>::unused_account_authorization_extent(ii),
					AuthorizationExtent { transactions: 0, bytes: 0 },
				);
			} else {
				// still there
				assert_eq!(
					TransactionStorage::<Test>::unused_account_authorization_extent(ii),
					AuthorizationExtent { transactions: 1, bytes: 2000 },
				);
			}
		}

		run_to_block(13, || None);
		for ii in 0..50 {
			if ii < 30 {
				// expired
				assert_eq!(
					TransactionStorage::<Test>::unused_account_authorization_extent(ii),
					AuthorizationExtent { transactions: 0, bytes: 0 },
				);
			} else {
				// still there
				assert_eq!(
					TransactionStorage::<Test>::unused_account_authorization_extent(ii),
					AuthorizationExtent { transactions: 1, bytes: 2000 },
				);
			}
		}

		run_to_block(15, || None);
		for ii in 0..50 {
			if ii < 40 {
				// expired
				assert_eq!(
					TransactionStorage::<Test>::unused_account_authorization_extent(ii),
					AuthorizationExtent { transactions: 0, bytes: 0 },
				);
			} else {
				// still there
				assert_eq!(
					TransactionStorage::<Test>::unused_account_authorization_extent(ii),
					AuthorizationExtent { transactions: 1, bytes: 2000 },
				);
			}
		}

		run_to_block(16, || None);
		for ii in 0..50 {
			// all expired
			assert_eq!(
				TransactionStorage::<Test>::unused_account_authorization_extent(ii),
				AuthorizationExtent { transactions: 0, bytes: 0 },
			);
		}
	});
}
