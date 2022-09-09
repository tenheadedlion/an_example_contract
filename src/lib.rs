#![cfg_attr(not(feature = "std"), no_std)]
// use ink_lang as ink;
use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod agency {

    use super::pink;
    use ink_env;
    use ink_env::debug_println;

    use ink_prelude::format;
    use ink_prelude::vec;
    use ink_prelude::{
        string::{String, ToString},
        vec::Vec,
    };
    use ink_storage::traits::{PackedLayout, SpreadAllocate, SpreadLayout};
    use ink_storage::Mapping;
    use pink::PinkEnvironment;
    use scale::{Decode, Encode};

    //use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey};
    //use rsa::pkcs8::EncodePrivateKey;
    //use rsa::pkcs8::LineEnding;

    use aes_gcm::aead::{Aead, NewAead};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    pub const IV_BYTES: usize = 12;
    pub type IV = [u8; IV_BYTES];

    pub const AES_KEY_BYTES: usize = 32;
    pub type AESKey = [u8; AES_KEY_BYTES];

    fn next_random() -> [u8; 32] {
        [1; 32]
    }

    #[derive(
        Encode, Decode, Debug, PartialEq, Eq, Clone, SpreadLayout, PackedLayout, SpreadAllocate,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct SecretHandle {
        key: AESKey,
        iv: IV,
    }

    impl SecretHandle {
        pub fn new() -> Self {
            Self {
                key: next_random(),
                iv: next_random()[..IV_BYTES]
                    .try_into()
                    .expect("should not fail with valid length; qed."),
            }
        }

        pub fn encrypt(&self, _offset_bytes: u64, plaintext: Vec<u8>) -> Result<Vec<u8>> {
            // if offset_bytes % (BLOCK_BYTES as u64) != 0 {
            //     panic!(
            //         "Offset must be in multiples of block length of {} bytes",
            //         BLOCK_BYTES
            //     );
            // }

            let key = Key::from_slice(&self.key);
            let cipher = Aes256Gcm::new(key);
            // TODO: increase IV by offset / BLOCK_LEN
            let nonce = Nonce::from_slice(&self.iv); // 96-bits; unique per message

            let ciphertext = cipher
                .encrypt(nonce, plaintext.as_ref())
                .map_err(|_| Error::CannotEncrypt)?;
            Ok(ciphertext)
        }

        pub fn decrypt(&self, _offset_bytes: u64, ciphertext: Vec<u8>) -> Result<Vec<u8>> {
            // if offset_bytes % (BLOCK_BYTES as u64) != 0 {
            //     panic!(
            //         "Offset must be in multiples of block length of {} bytes",
            //         BLOCK_BYTES
            //     );
            // }

            let key = Key::from_slice(&self.key);
            let cipher = Aes256Gcm::new(key);
            // TODO: increase IV by offset / BLOCK_LEN
            let nonce = Nonce::from_slice(&self.iv); // 96-bits; unique per message

            let plaintext = cipher
                .decrypt(nonce, ciphertext.as_ref())
                .map_err(|_| Error::CannotDecrypt)?;
            Ok(plaintext)
        }
    }

    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Agency {
        name: String,
        admin: AccountId,
        registered_agents: Mapping<AccountId, Record>,
    }

    #[derive(
        Encode, Decode, Debug, PartialEq, Eq, Clone, SpreadLayout, PackedLayout, SpreadAllocate,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Record {
        name: String,
        secret_handle: SecretHandle,
    }

    #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        PermissionDenial,
        NoSuchTarget,
        KeyProblem,
        LinkExists,
        CannotDecrypt,
        CannotEncrypt,
    }

    pub type Result<T> = core::result::Result<T, Error>;
    const KEYBITS: usize = 2048;

    impl Agency {
        #[ink(constructor)]
        pub fn new() -> Self {
            let admin = Self::env().caller();
            ink_lang::utils::initialize_contract(|this: &mut Self| {
                this.admin = admin;
                this.registered_agents.insert(
                    admin,
                    &Record {
                        name: "admin".to_string(),
                        secret_handle: SecretHandle::new(),
                    },
                );
            })
        }

        /// Enrolls a new agent;
        ///
        /// Admin permission is require
        #[ink(message)]
        pub fn enroll(&mut self, agent_id: AccountId, agent_name: String) -> Result<()> {
            let caller = Self::env().caller();
            if caller != self.admin {
                return Err(Error::PermissionDenial);
            }
            // create a rsa key pair for encryption/decryption
            /*
            let mut rng = rand::thread_rng();
            let private_key = RsaPrivateKey::new(&mut rng, KEYBITS).map_err(|_| Error::KeyProblem)?;
            let public_key = RsaPublicKey::from(&private_key);

            let private_key = private_key.to_pkcs8_pem(LineEnding::CRLF);
            */
            self.registered_agents.insert(
                agent_id,
                &Record {
                    name: agent_name,
                    secret_handle: SecretHandle::new()
                },
            );
            Ok(())
        }

        /// Get the name of a colleague;
        ///
        /// The caller must be a member of the agency
        #[ink(message)]
        pub fn name_of(&self, agent_id: AccountId) -> Result<String> {
            let caller = Self::env().caller();
            if !self.registered_agents.contains(caller) {
                return Err(Error::PermissionDenial);
            }
            if !self.registered_agents.contains(agent_id) {
                return Err(Error::NoSuchTarget);
            }

            Ok(self.registered_agents.get(agent_id).unwrap().name)
        }

        #[ink(message)]
        pub fn who_is_the_admin(&self) -> AccountId {
            self.admin
        }
    }
}
