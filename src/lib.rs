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
    use pink::http_get;
    use pink::PinkEnvironment;
    use scale::{Decode, Encode};

    //use base64::{decode, encode};
    //use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey};
    //use rsa::pkcs8::EncodePrivateKey;
    //use rsa::pkcs8::LineEnding;

    use aes_gcm::aead::{Aead, NewAead};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    pub const IV_BYTES: usize = 12;
    pub type IV = [u8; IV_BYTES];

    pub const AES_KEY_BYTES: usize = 32;
    pub type AESKey = [u8; AES_KEY_BYTES];
    pub type SecretCode = [u8; AES_KEY_BYTES];

    fn next_random() -> [u8; 32] {
        [1; 32]
    }

    fn next_secret() -> [u8; 32] {
        [1; 32]
    }

    #[derive(
        Encode, Decode, Debug, PartialEq, Eq, Clone, SpreadLayout, PackedLayout, SpreadAllocate,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct SecretHandle {
        key: AESKey,
        iv: IV,
        secret_code: SecretCode,
    }

    impl SecretHandle {
        pub fn new() -> Self {
            Self {
                key: next_random(),
                iv: next_random()[..IV_BYTES]
                    .try_into()
                    .expect("should not fail with valid length; qed."),
                secret_code: next_secret(),
            }
        }

        #[allow(dead_code)]
        pub fn encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>> {
            let key = Key::from_slice(&self.key);
            let cipher = Aes256Gcm::new(key);
            let nonce = Nonce::from_slice(&self.iv); // 96-bits; unique per message

            let ciphertext = cipher
                .encrypt(nonce, plaintext.as_ref())
                .map_err(|_| Error::CannotEncrypt)?;
            Ok(ciphertext)
        }

        pub fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>> {
            let key = Key::from_slice(&self.key);
            let cipher = Aes256Gcm::new(key);
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
        report: Report,
    }

    #[derive(
        Encode,
        Decode,
        Debug,
        PartialEq,
        Eq,
        Clone,
        SpreadLayout,
        PackedLayout,
        SpreadAllocate,
        Default,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Report {
        url: String,
        archive: Vec<String>,
    }

    #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        PermissionDenied,
        NoSuchTarget,
        NoSuchAgent,
        KeyProblem,
        LinkExists,
        CannotDecrypt,
        CannotEncrypt,
        RequestFailed,
        WrongFormat,
        DataTransform,
        FalseReport,
    }

    pub type Result<T> = core::result::Result<T, Error>;

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
                        report: Report::default(),
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
                return Err(Error::PermissionDenied);
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
                    secret_handle: SecretHandle::new(),
                    report: Report::default(),
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
                return Err(Error::PermissionDenied);
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

        /// Agent gets his/her access key;
        /// Permission required;
        #[ink(message)]
        pub fn get_iv(&self, agent_id: AccountId) -> Result<Vec<u8>> {
            let caller = Self::env().caller();
            if !self.registered_agents.contains(caller) {
                return Err(Error::PermissionDenied);
            }
            if !self.registered_agents.contains(agent_id) {
                return Err(Error::NoSuchTarget);
            }

            Ok(self
                .registered_agents
                .get(agent_id)
                .unwrap()
                .secret_handle
                .iv
                .to_vec())
        }

        // todo: write a general getter
        // todo: write a permission verifier to reduce the boilerplate
        // todo: are we sure we should allow the admin to change agent records?

        /// Agent gets his/her key;
        /// Permission required;
        #[ink(message)]
        pub fn get_key(&self, agent_id: AccountId) -> Result<Vec<u8>> {
            let caller = Self::env().caller();
            if caller != self.admin || !self.registered_agents.contains(agent_id) {
                return Err(Error::NoSuchTarget);
            }

            Ok(self
                .registered_agents
                .get(agent_id)
                .unwrap()
                .secret_handle
                .key
                .to_vec())
        }

        /// Agent updates his/her report URL;
        /// Permission required;
        #[ink(message)]
        pub fn update_report_url(&mut self, url: String) -> Result<()> {
            let caller = Self::env().caller();
            if !self.registered_agents.contains(caller) {
                return Err(Error::NoSuchTarget);
            }
            let mut record = self
                .registered_agents
                .get(caller)
                .map(Ok)
                .unwrap_or(Err(Error::NoSuchAgent))?;
            record.report.url = url;
            self.registered_agents.insert(caller, &record);
            Ok(())
        }
        /// Get information from a specific agent;
        /// Permission required;
        #[ink(message)]
        // todo: is returing vector of Stri;ng Ok?
        pub fn get_report_from(&self, agent_id: AccountId) -> Result<Vec<String>> {
            let caller = Self::env().caller();
            if !self.registered_agents.contains(caller) {
                return Err(Error::NoSuchTarget);
            }
            let record = self
                .registered_agents
                .get(agent_id)
                .map(Ok)
                .unwrap_or(Err(Error::NoSuchAgent))?;
            Ok(record.report.archive)
        }

        /// Fetch report from a specific agent;
        /// Admin Permission required;
        #[ink(message)]
        pub fn fetch_report(&mut self, agent_id: AccountId) -> Result<()> {
            let caller = Self::env().caller();
            if caller != self.admin {
                return Err(Error::PermissionDenied);
            }
            // todo: make the get method easy to write
            let mut record = self
                .registered_agents
                .get(caller)
                .map(Ok)
                .unwrap_or(Err(Error::NoSuchAgent))?;
            let info = Self::fetch_and_verify(&record.report.url, &record.secret_handle)?;
            record
                .report
                .archive
                .push(String::from_utf8_lossy(&info).to_string());
            self.registered_agents.insert(agent_id, &record);
            Ok(())
        }

        #[ink(message)]
        pub fn attest(&self, url: String) -> Result<Vec<u8>> {
            let caller = Self::env().caller();
            let record = self
                .registered_agents
                .get(caller)
                .map(Ok)
                .unwrap_or(Err(Error::NoSuchAgent))?;
            Self::fetch_and_verify(&url, &record.secret_handle)
        }

        pub fn fetch_and_verify(url: &str, secret_handle: &SecretHandle) -> Result<Vec<u8>> {
            let resposne = http_get!(url);
            if resposne.status_code != 200 {
                return Err(Error::RequestFailed);
            }
            let body = resposne.body;
            let (secret_code, info) = Self::parse_report(&body)?;
            // decrypt the secret_code
            let secret_code = secret_handle.decrypt(secret_code)?;
            if secret_code != secret_handle.secret_code {
                return Err(Error::FalseReport);
            }
            Ok(info)
        }

        /// Parse the report source to retrieve secret_code and information;
        /// Reports must follow this format: `<secret_code>\r\n<content>`;
        /// to generate a report, echo $report | base64 -w 0
        /// for now the report protocol is too simple to be realistic,
        ///     it is merely used for demostration purposes;
        pub fn parse_report(src: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
            let src = &base64::decode(src).map_err(|_| Error::DataTransform)?;
            let mut i = 0;
            while !(src[i] == b'\r' && src[i + 1] == b'\n') {
                i += 1;
            }
            let secret = &src[..i];
            let info = &src[i + 2..];
            Ok((secret.to_vec(), info.to_vec()))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_lang as ink;

        fn default_accounts() -> ink_env::test::DefaultAccounts<PinkEnvironment> {
            ink_env::test::default_accounts::<Environment>()
        }

        #[ink::test]
        fn test_secret_hanle() {
            let plaintext = "hello world";
            let handle = SecretHandle::new();
            let encrypted = handle.encrypt(plaintext.as_bytes().to_vec()).unwrap();
            let decrypted = handle.decrypt(encrypted).unwrap();
            assert_eq!(plaintext.as_bytes(), &decrypted[..]);
        }

        #[ink::test]
        fn test_parse_report() {
            let (secret, info) = Agency::parse_report(b"c2VjcmV0DQppbmZvcm1hdGlvbgo=").unwrap();
            assert_eq!(&secret[..], "secret".as_bytes());
            assert_eq!(&info[..], "information\n".as_bytes());

            let handle = SecretHandle::new();
            let secret_enc = handle.encrypt("secret".as_bytes().to_vec()).unwrap();
            let report = [secret_enc, b"\r\ninformation".to_vec()].concat();
            let report = base64::encode(report);
            dbg!(&report);
            let (secret, info) = Agency::parse_report(report.as_bytes()).unwrap();
            let secret = handle.decrypt(secret).unwrap();
            assert_eq!(&secret[..], "secret".as_bytes());
            assert_eq!(&info[..], "information".as_bytes());
        }

        #[ink::test]
        fn test_fetch_and_verify() {
            let mut agency = Agency::new();
            let accounts = default_accounts();
            _ = agency.enroll(accounts.alice, "Alice".to_string());
            _ = agency.update_report_url("https://pastebin.com/raw/J8rMvMFd".to_string());

            let handle = SecretHandle::new();
            let info =
                Agency::fetch_and_verify("https://pastebin.com/raw/J8rMvMFd", &handle).unwrap();
            assert_eq!("information".as_bytes(), &info[..]);
        }
    }
}
