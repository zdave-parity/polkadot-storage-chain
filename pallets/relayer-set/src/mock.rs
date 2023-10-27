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

//! Test environment for relayer set pallet.

#![cfg(test)]

use crate as pallet_relayer_set;
use frame_support::{
	parameter_types,
	traits::{ConstU16, ConstU32, ConstU64, OnFinalize, OnInitialize},
};
use frame_system::{pallet_prelude::BlockNumberFor, EnsureRoot};
use sp_core::H256;
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
	BuildStorage,
};

pub type AccountId = u64;
type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test
	{
		System: frame_system,
		RelayerSet: pallet_relayer_set,
	}
);

impl frame_system::Config for Test {
	type BaseCallFilter = frame_support::traits::Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type Nonce = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<AccountId>;
	type Block = Block;
	type RuntimeEvent = RuntimeEvent;
	type BlockHashCount = ConstU64<250>;
	type DbWeight = ();
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = ();
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = ConstU16<42>;
	type OnSetCode = ();
	type MaxConsumers = ConstU32<16>;
}

parameter_types! {
	pub const BridgeTxFailCooldownBlocks: BlockNumberFor<Test> = 2;
}

impl pallet_relayer_set::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = ();
	type AddRemoveOrigin = EnsureRoot<AccountId>;
	type BridgeTxFailCooldownBlocks = BridgeTxFailCooldownBlocks;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
	let t = RuntimeGenesisConfig {
		system: Default::default(),
		relayer_set: RelayerSetConfig { initial_relayers: vec![1, 2, 3] },
	}
	.build_storage()
	.unwrap();
	t.into()
}

pub fn next_block() {
	System::on_finalize(System::block_number());
	System::set_block_number(System::block_number() + 1);
	System::on_initialize(System::block_number());
}
