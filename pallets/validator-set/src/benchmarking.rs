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

#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_benchmarking::v1::{account, benchmarks, BenchmarkError};
use frame_support::traits::EnsureOrigin;

const SEED: u32 = 0;

benchmarks! {
	add_validator {
		let origin =
			T::AddRemoveOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;
		let validator: T::ValidatorId = account("validator", 0, SEED);
	}: _<T::RuntimeOrigin>(origin, validator)

	remove_validator {
		let origin =
			T::AddRemoveOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;
		let validator: T::ValidatorId = account("validator", 0, SEED);
	}: _<T::RuntimeOrigin>(origin, validator)

	impl_benchmark_test_suite!(
		ValidatorSet,
		crate::mock::new_test_ext(),
		crate::mock::Test,
	);
}
