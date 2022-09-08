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

    #[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
    #[derive(SpreadLayout, PackedLayout, SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Record {
        name: String,
    }

    #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        NoPermission,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl Agency {
        #[ink(constructor)]
        pub fn new() -> Self {
            let admin = Self::env().caller();
            ink_lang::utils::initialize_contract(|this: &mut Self| {
                this.admin = admin;
            })
        }

        #[ink(message)]
        pub fn enroll(&mut self, agent_id: AccountId, agent_name: String) -> Result<()> {
            let caller = Self::env().caller();
            if caller != self.admin {
                return Err(Error::NoPermission);
            }
            self.registered_agents
                .insert(agent_id, &Record { name: agent_name });
            Ok(())
        }

        #[ink(message)]
        pub fn seal_name(&mut self, name: String) {
            self.name = name;
        }
    }
}
