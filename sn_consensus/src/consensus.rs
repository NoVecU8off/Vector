use sn_proto::messages::{Block, Header};
use sn_node::node::*;

// Структура данных для голоса
struct Vote {
    validator_id: u64,
    block_id: u64,
    signature: String,
}

fn verify_block(block: &Block, poh_sequence: &[PoHEntry]) -> bool {
    // 1. Check if the block has a valid signature
    let public_key = &block.msg_public_key;
    let signature = &block.msg_signature;
    let header = &block.msg_header;

    if !verify_signature(&header, &public_key, &signature) {
        return false;
    }

    // 2. Check if the PoH sequence is valid
    let poh_hash = get_poh_hash(poh_sequence);
    if header.msg_root_hash != poh_hash {
        return false;
    }

    // 3. Check if transactions are valid
    for transaction in &block.msg_transactions {
        if !verify_transaction(transaction) {
            return false;
        }
    }

    true
}

async fn send_vote(vote: &Vote, validators: &[Validator]) {
    let vote_message = VoteMessage {
        validator_id: vote.validator_id,
        block_id: vote.block_id,
        signature: vote.signature.clone(),
    };

    for validator in validators {
        let client = match make_node_client(&validator.addr).await {
            Ok(c) => c,
            Err(e) => {
                error!(validator.logger, "Failed to create node client: {:?}", e);
                continue;
            }
        };

        let request = Request::new(vote_message.clone());
        if let Err(e) = client.cast_vote(request).await {
            error!(validator.logger, "Failed to send vote: {:?}", e);
        }
    }
}


fn process_vote(vote: &Vote, tower: &mut Tower) {
    // Check if the vote is valid
    if !verify_vote(vote) {
        return;
    }

    // Update the tower with the new vote
    tower.update_lock(vote);
}


struct Tower {
    locks: HashMap<u64, u64>, // блок ID => уровень замка
}

impl Tower {
    fn update_lock(&mut self, vote: &Vote) {
        let validator_id = vote.validator_id;
        let block_id = vote.block_id;

        if let Some(current_lock) = self.locks.get_mut(&validator_id) {
            if *current_lock < block_id {
                *current_lock = block_id;
            }
        } else {
            self.locks.insert(validator_id, block_id);
        }
    }
}
