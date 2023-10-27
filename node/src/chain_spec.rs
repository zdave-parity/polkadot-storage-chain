use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use polkadot_bulletin_chain_runtime::{
	opaque::SessionKeys, AccountId, BabeConfig, BridgePolkadotGrandpaConfig,
	BridgePolkadotMessagesConfig, BridgePolkadotParachainsConfig, RelayerSetConfig,
	RuntimeGenesisConfig, SessionConfig, Signature, SudoConfig, SystemConfig, ValidatorSetConfig,
	BABE_GENESIS_EPOCH_CONFIG, WASM_BINARY,
};
use sc_service::ChainType;
use sp_consensus_babe::AuthorityId as BabeId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_core::{sr25519, Pair, Public};
use sp_runtime::traits::{IdentifyAccount, Verify};

const PROTOCOL_ID: &str = "dot-bulletin";

// The URL for the telemetry server.
// const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec<RuntimeGenesisConfig>;

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{}", seed), None)
		.expect("static values are valid; qed")
		.public()
}

type AccountPublic = <Signature as Verify>::Signer;

/// Generate an account ID from seed.
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Generate authority keys from a seed.
pub fn authority_keys_from_seed(s: &str) -> (AccountId, BabeId, GrandpaId, ImOnlineId) {
	(
		get_account_id_from_seed::<sr25519::Public>(s),
		get_from_seed::<BabeId>(s),
		get_from_seed::<GrandpaId>(s),
		get_from_seed::<ImOnlineId>(s),
	)
}

fn session_keys(babe: BabeId, grandpa: GrandpaId, im_online: ImOnlineId) -> SessionKeys {
	SessionKeys { babe, grandpa, im_online }
}

pub fn development_config() -> Result<ChainSpec, String> {
	let wasm_binary = WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?;

	Ok(ChainSpec::from_genesis(
		// Name
		"Development",
		// ID
		"dev",
		ChainType::Development,
		move || {
			testnet_genesis(
				wasm_binary,
				// Initial PoA authorities
				vec![authority_keys_from_seed("Alice")],
				// Sudo account
				get_account_id_from_seed::<sr25519::Public>("Alice"),
				true,
			)
		},
		// Bootnodes
		vec![],
		// Telemetry
		None,
		// Protocol ID
		Some(PROTOCOL_ID),
		None,
		// Properties
		None,
		// Extensions
		None,
	))
}

pub fn local_testnet_config() -> Result<ChainSpec, String> {
	let wasm_binary = WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?;

	Ok(ChainSpec::from_genesis(
		// Name
		"Local Testnet",
		// ID
		"local_testnet",
		ChainType::Local,
		move || {
			testnet_genesis(
				wasm_binary,
				// Initial PoA authorities
				vec![authority_keys_from_seed("Alice"), authority_keys_from_seed("Bob")],
				// Sudo account
				get_account_id_from_seed::<sr25519::Public>("Alice"),
				true,
			)
		},
		// Bootnodes
		vec![],
		// Telemetry
		None,
		// Protocol ID
		Some(PROTOCOL_ID),
		// Properties
		None,
		None,
		// Extensions
		None,
	))
}

/// Configure initial storage state for FRAME modules.
fn testnet_genesis(
	wasm_binary: &[u8],
	initial_authorities: Vec<(AccountId, BabeId, GrandpaId, ImOnlineId)>,
	root_key: AccountId,
	_enable_println: bool,
) -> RuntimeGenesisConfig {
	RuntimeGenesisConfig {
		system: SystemConfig {
			// Add Wasm runtime to storage.
			code: wasm_binary.to_vec(),
			..Default::default()
		},
		validator_set: ValidatorSetConfig {
			initial_validators: initial_authorities
				.iter()
				.map(|x| x.0.clone())
				.collect::<Vec<_>>()
				.try_into()
				.expect("Too many initial authorities"),
		},
		session: SessionConfig {
			keys: initial_authorities
				.iter()
				.map(|x| {
					(x.0.clone(), x.0.clone(), session_keys(x.1.clone(), x.2.clone(), x.3.clone()))
				})
				.collect(),
		},
		babe: BabeConfig { epoch_config: Some(BABE_GENESIS_EPOCH_CONFIG), ..Default::default() },
		grandpa: Default::default(),
		im_online: Default::default(),
		sudo: SudoConfig {
			// Assign network admin rights.
			key: Some(root_key.clone()),
		},
		relayer_set: RelayerSetConfig {
			// For simplicity just make the initial relayer set match the initial validator set. In
			// practice even if the same entities control the validators and the relayers they
			// would want to use separate keys for the relayers.
			initial_relayers: initial_authorities.iter().map(|x| x.0.clone()).collect::<Vec<_>>(),
		},
		bridge_polkadot_grandpa: BridgePolkadotGrandpaConfig {
			owner: Some(root_key.clone()),
			..Default::default()
		},
		bridge_polkadot_parachains: BridgePolkadotParachainsConfig {
			owner: Some(root_key.clone()),
			..Default::default()
		},
		bridge_polkadot_messages: BridgePolkadotMessagesConfig {
			owner: Some(root_key),
			..Default::default()
		},
	}
}
