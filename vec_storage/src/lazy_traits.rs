use lazy_static::lazy_static;
use std::sync::Arc;

use crate::block_db::*;
use crate::image_db::*;
use crate::ip_db::*;
use crate::output_db::*;

lazy_static! {
    pub static ref BLOCK_STORER: Arc<BlockDB> = {
        let block_db = sled::open("C:/Vector/blocks_db").unwrap();
        let index_db = sled::open("C:/Vector/index_db").unwrap();
        Arc::new(BlockDB::new(block_db, index_db))
    };
    pub static ref IMAGE_STORER: Arc<ImageDB> = {
        let image_db = sled::open("C:/Vector/image_db").unwrap();
        Arc::new(ImageDB::new(image_db))
    };
    pub static ref OUTPUT_STORER: Arc<OutputDB> = {
        let output_db = sled::open("C:/Vector/output_db").unwrap();
        Arc::new(OutputDB::new(output_db))
    };
    pub static ref IP_STORER: Arc<IPDB> = {
        let ip_db = sled::open("C:/Vector/ip_db").unwrap();
        Arc::new(IPDB::new(ip_db))
    };
}
