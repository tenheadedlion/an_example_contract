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
    }

    #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        PermissionDenial,
        NoSuchTarget
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl Agency {
        #[ink(constructor)]
        pub fn new() -> Self {
            let admin = Self::env().caller();
            ink_lang::utils::initialize_contract(|this: &mut Self| {
                this.admin = admin;
                this.registered_agents.insert(admin, &Record {
                    name: "admin".to_string()
                });
            })
        }

        /// Enrolls a new agent
        ///
        /// Admin permission is require
        #[ink(message)]
        pub fn enroll(&mut self, agent_id: AccountId, agent_name: String) -> Result<()> {
            let caller = Self::env().caller();
            if caller != self.admin {
                return Err(Error::PermissionDenial);
            }
            self.registered_agents
                .insert(agent_id, &Record { name: agent_name });
            Ok(())
        }

        /// Get the name of a colleague
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
        pub fn who_is_admin(&self) -> AccountId {
            self.admin
        }
    }
    
    
}
