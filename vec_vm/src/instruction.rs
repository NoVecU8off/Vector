// use std::mem::size_of;
// use std::result::Result;
// use vec_crypto::crypto::ADS;
// use vec_errors::errors::*;

// pub type ProgramResult = Result<(), VMError>;
// const U64_BYTES: usize = 8;

// #[repr(C)]
// #[derive(Debug, PartialEq, Eq, Clone)]
// pub struct AccountMeta {
//     /// An account's public key.
//     pub address: ADS,
//     /// True if an `Instruction` requires a `Transaction` signature matching `pubkey`.
//     pub is_signer: bool,
//     /// True if the account data or metadata may be mutated during program execution.
//     pub is_writable: bool,
// }

// /// Instructions supported by the token program.
// pub struct Instruction {
//     pub program_id: ADS,
//     pub accounts: Vec<AccountMeta>,
//     pub data: Vec<u8>,
// }

// #[repr(C)]
// #[derive(Clone, Debug, PartialEq)]
// pub enum TokenInstruction {
//     /// Initializes a new account to hold tokens.  If this account is associated
//     /// with the native mint then the token balance of the initialized account
//     /// will be equal to the amount of SOL in the account. If this account is
//     /// associated with another mint, that mint must be initialized before this
//     /// command can succeed.
//     ///
//     /// The `InitializeAccount` instruction requires no signers and MUST be
//     /// included within the same Transaction as the system program's
//     /// `CreateAccount` instruction that creates the account being initialized.
//     /// Otherwise another party can acquire ownership of the uninitialized
//     /// account.
//     ///
//     /// Accounts expected by this instruction:
//     ///
//     ///   0. `[writable]`  The account to initialize.
//     ///   1. `[]` The mint this account will be associated with.
//     ///   2. `[]` The new account's owner/multisignature.
//     ///   3. `[]` Rent sysvar
//     InitializeAccount,
//     /// Transfers tokens from one account to another either directly or via a
//     /// delegate.  If this account is associated with the native mint then equal
//     /// amounts of SOL and Tokens will be transferred to the destination
//     /// account.
//     ///
//     /// Accounts expected by this instruction:
//     ///
//     ///   * Single owner/delegate
//     ///   0. `[writable]` The source account.
//     ///   1. `[writable]` The destination account.
//     ///   2. `[signer]` The source account's owner/delegate.
//     ///
//     ///   * Multisignature owner/delegate
//     ///   0. `[writable]` The source account.
//     ///   1. `[writable]` The destination account.
//     ///   2. `[]` The source account's multisignature owner/delegate.
//     ///   3. ..3+M `[signer]` M signer accounts.
//     Transfer {
//         /// The amount of tokens to transfer.
//         amount: u64,
//     },
//     /// Close an account by transferring all its SOL to the destination account.
//     /// Non-native accounts may only be closed if its token amount is zero.
//     ///
//     /// Accounts expected by this instruction:
//     ///
//     ///   * Single owner
//     ///   0. `[writable]` The account to close.
//     ///   1. `[writable]` The destination account.
//     ///   2. `[signer]` The account's owner.
//     ///
//     ///   * Multisignature owner
//     ///   0. `[writable]` The account to close.
//     ///   1. `[writable]` The destination account.
//     ///   2. `[]` The account's multisignature owner.
//     ///   3. ..3+M `[signer]` M signer accounts.
//     CloseAccount,
//     /// Freeze an Initialized account using the Mint's freeze_authority (if
//     /// set).
//     ///
//     /// Accounts expected by this instruction:
//     ///
//     ///   * Single owner
//     ///   0. `[writable]` The account to freeze.
//     ///   1. `[]` The token mint.
//     ///   2. `[signer]` The mint freeze authority.
//     ///
//     ///   * Multisignature owner
//     ///   0. `[writable]` The account to freeze.
//     ///   1. `[]` The token mint.
//     ///   2. `[]` The mint's multisignature freeze authority.
//     ///   3. ..3+M `[signer]` M signer accounts.
//     FreezeAccount,
//     /// Like InitializeAccount, but the owner pubkey is passed via instruction data
//     /// rather than the accounts list. This variant may be preferable when using
//     /// Cross Program Invocation from an instruction that does not need the owner's
//     /// `AccountInfo` otherwise.
//     ///
//     /// Accounts expected by this instruction:
//     ///
//     ///   0. `[writable]`  The account to initialize.
//     ///   1. `[]` The mint this account will be associated with.
//     ///   3. `[]` Rent sysvar
//     InitializeAccount2 {
//         /// The new account's owner/multisignature.
//         owner: ADS,
//     },
// }
// impl<'a> TokenInstruction {
//     /// Unpacks a byte buffer into a [TokenInstruction](enum.TokenInstruction.html).
//     pub fn unpack(input: &'a [u8]) -> Result<Self, VMError> {
//         use VMError::InvalidInstruction;

//         let (&tag, rest) = input.split_first().ok_or(InvalidInstruction)?;
//         Ok(match tag {
//             0 => Self::InitializeAccount,
//             1 => {
//                 let amount = rest
//                     .get(..8)
//                     .and_then(|slice| slice.try_into().ok())
//                     .map(u64::from_le_bytes)
//                     .ok_or(InvalidInstruction)?;
//                 Self::Transfer { amount }
//             }
//             2 => Self::CloseAccount,
//             3 => Self::FreezeAccount,
//             4 => {
//                 let (owner, _rest) = Self::unpack_pubkey(rest)?;
//                 Self::InitializeAccount2 { owner }
//             }
//             _ => return Err(VMError::InvalidInstruction),
//         })
//     }

//     /// Packs a [TokenInstruction](enum.TokenInstruction.html) into a byte buffer.
//     pub fn pack(&self) -> Vec<u8> {
//         let mut buf = Vec::with_capacity(size_of::<Self>());
//         match self {
//             Self::InitializeAccount => buf.push(0),
//             &Self::Transfer { amount } => {
//                 buf.push(1);
//                 buf.extend_from_slice(&amount.to_le_bytes());
//             }
//             Self::CloseAccount => buf.push(2),
//             Self::FreezeAccount => buf.push(3),
//             &Self::InitializeAccount2 { owner } => {
//                 buf.push(4);
//                 buf.extend_from_slice(owner.as_ref());
//             }
//         };
//         buf
//     }

//     fn unpack_pubkey(input: &[u8]) -> Result<(ADS, &[u8]), VMError> {
//         if input.len() >= 64 {
//             let (key, rest) = input.split_at(64);
//             let addr: ADS = key.try_into().unwrap();
//             Ok((addr, rest))
//         } else {
//             Err(VMError::InvalidInstruction)
//         }
//     }

//     fn unpack_pubkey_option(input: &[u8]) -> Result<(Option<ADS>, &[u8]), VMError> {
//         match input.split_first() {
//             Option::Some((&0, rest)) => Ok((Option::None, rest)),
//             Option::Some((&1, rest)) if rest.len() >= 64 => {
//                 let (key, rest) = rest.split_at(64);
//                 let addr: ADS = key.try_into().unwrap();
//                 Ok((Option::Some(addr), rest))
//             }
//             _ => Err(VMError::InvalidInstruction),
//         }
//     }

//     fn pack_pubkey_option(value: &Option<ADS>, buf: &mut Vec<u8>) {
//         match *value {
//             Option::Some(ref key) => {
//                 buf.push(1);
//                 buf.extend_from_slice(key);
//             }
//             Option::None => buf.push(0),
//         }
//     }

//     fn unpack_u64(input: &[u8]) -> Result<(u64, &[u8]), VMError> {
//         let value = input
//             .get(..U64_BYTES)
//             .and_then(|slice| slice.try_into().ok())
//             .map(u64::from_le_bytes)
//             .ok_or(VMError::InvalidInstruction)?;
//         Ok((value, &input[U64_BYTES..]))
//     }

//     fn unpack_amount_decimals(input: &[u8]) -> Result<(u64, u8, &[u8]), VMError> {
//         let (amount, rest) = Self::unpack_u64(input)?;
//         let (&decimals, rest) = rest.split_first().ok_or(VMError::InvalidInstruction)?;
//         Ok((amount, decimals, rest))
//     }
// }

// /// Specifies the authority type for SetAuthority instructions
// #[repr(u8)]
// #[derive(Clone, Debug, PartialEq)]
// pub enum AuthorityType {
//     /// Authority to mint new tokens
//     MintTokens,
//     /// Authority to freeze any account associated with the Mint
//     FreezeAccount,
//     /// Owner of a given token account
//     AccountOwner,
//     /// Authority to close a token account
//     CloseAccount,
// }

// impl AuthorityType {
//     fn into(&self) -> u8 {
//         match self {
//             AuthorityType::MintTokens => 0,
//             AuthorityType::FreezeAccount => 1,
//             AuthorityType::AccountOwner => 2,
//             AuthorityType::CloseAccount => 3,
//         }
//     }

//     fn from(index: u8) -> Result<Self, VMError> {
//         match index {
//             0 => Ok(AuthorityType::MintTokens),
//             1 => Ok(AuthorityType::FreezeAccount),
//             2 => Ok(AuthorityType::AccountOwner),
//             3 => Ok(AuthorityType::CloseAccount),
//             _ => Err(VMError::InvalidInstruction),
//         }
//     }
// }

// /// Creates a `InitializeAccount` instruction.
// pub fn initialize_account(
//     token_program_id: &ADS,
//     account_pubkey: &ADS,
//     mint_pubkey: &ADS,
//     owner_pubkey: &ADS,
// ) -> Result<Instruction, VMError> {
//     let data = TokenInstruction::InitializeAccount.pack();

//     let accounts = vec![
//         AccountMeta::new(*account_pubkey, false),
//         AccountMeta::new_readonly(*mint_pubkey, false),
//         AccountMeta::new_readonly(*owner_pubkey, false),
//     ];

//     Ok(Instruction {
//         program_id: *token_program_id,
//         accounts,
//         data,
//     })
// }

// /// Creates a `InitializeAccount2` instruction.
// pub fn initialize_account2(
//     token_program_id: &ADS,
//     account_pubkey: &ADS,
//     mint_pubkey: &ADS,
//     owner_pubkey: &ADS,
// ) -> Result<Instruction, VMError> {
//     let data = TokenInstruction::InitializeAccount2 {
//         owner: *owner_pubkey,
//     }
//     .pack();

//     let accounts = vec![
//         AccountMeta::new(*account_pubkey, false),
//         AccountMeta::new_readonly(*mint_pubkey, false),
//     ];

//     Ok(Instruction {
//         program_id: *token_program_id,
//         accounts,
//         data,
//     })
// }

// /// Creates a `Transfer` instruction.
// pub fn transfer(
//     token_program_id: &ADS,
//     source_pubkey: &ADS,
//     destination_pubkey: &ADS,
//     authority_pubkey: &ADS,
//     signer_pubkeys: &[&ADS],
//     amount: u64,
// ) -> Result<Instruction, VMError> {
//     let data = TokenInstruction::Transfer { amount }.pack();

//     let mut accounts = Vec::with_capacity(3 + signer_pubkeys.len());
//     accounts.push(AccountMeta::new(*source_pubkey, false));
//     accounts.push(AccountMeta::new(*destination_pubkey, false));
//     accounts.push(AccountMeta::new_readonly(
//         *authority_pubkey,
//         signer_pubkeys.is_empty(),
//     ));
//     for signer_pubkey in signer_pubkeys.iter() {
//         accounts.push(AccountMeta::new_readonly(**signer_pubkey, true));
//     }

//     Ok(Instruction {
//         program_id: *token_program_id,
//         accounts,
//         data,
//     })
// }

// impl AccountMeta {
//     pub fn new(address: ADS, is_signer: bool) -> Self {
//         Self {
//             address,
//             is_signer,
//             is_writable: true,
//         }
//     }

//     pub fn new_readonly(address: ADS, is_signer: bool) -> Self {
//         Self {
//             address,
//             is_signer,
//             is_writable: false,
//         }
//     }
// }

// /// Creates a `CloseAccount` instruction.
// pub fn close_account(
//     token_program_id: &ADS,
//     account_pubkey: &ADS,
//     destination_pubkey: &ADS,
//     owner_pubkey: &ADS,
//     signer_pubkeys: &[&ADS],
// ) -> Result<Instruction, VMError> {
//     let data = TokenInstruction::CloseAccount.pack();

//     let mut accounts = Vec::with_capacity(3 + signer_pubkeys.len());
//     accounts.push(AccountMeta::new(*account_pubkey, false));
//     accounts.push(AccountMeta::new(*destination_pubkey, false));
//     accounts.push(AccountMeta::new_readonly(
//         *owner_pubkey,
//         signer_pubkeys.is_empty(),
//     ));
//     for signer_pubkey in signer_pubkeys.iter() {
//         accounts.push(AccountMeta::new_readonly(**signer_pubkey, true));
//     }

//     Ok(Instruction {
//         program_id: *token_program_id,
//         accounts,
//         data,
//     })
// }

// /// Creates a `FreezeAccount` instruction.
// pub fn freeze_account(
//     token_program_id: &ADS,
//     account_pubkey: &ADS,
//     mint_pubkey: &ADS,
//     owner_pubkey: &ADS,
//     signer_pubkeys: &[&ADS],
// ) -> Result<Instruction, VMError> {
//     let data = TokenInstruction::FreezeAccount.pack();

//     let mut accounts = Vec::with_capacity(3 + signer_pubkeys.len());
//     accounts.push(AccountMeta::new(*account_pubkey, false));
//     accounts.push(AccountMeta::new_readonly(*mint_pubkey, false));
//     accounts.push(AccountMeta::new_readonly(
//         *owner_pubkey,
//         signer_pubkeys.is_empty(),
//     ));
//     for signer_pubkey in signer_pubkeys.iter() {
//         accounts.push(AccountMeta::new_readonly(**signer_pubkey, true));
//     }

//     Ok(Instruction {
//         program_id: *token_program_id,
//         accounts,
//         data,
//     })
// }
