use std::path::Path;

use hex::decode;
use nockvm::mem::NockStack;
use nockvm::noun::{Noun, Slots, D, T};
use nockvm_macros::tas;
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use tracing::{debug, error, info, warn};

use crate::nockapp::driver::{make_driver, IODriverFn};
use crate::nockapp::NockAppError;
use crate::noun::slab::{NockJammer, NounSlab};
use crate::utils::make_tas;
use crate::utils::scry::ScryResult;
use crate::{JammedNoun, NounExt};

#[derive(Debug)]
pub enum IndexerError {
    RocksDB(rocksdb::Error),
    Hex(hex::FromHexError),
    InvalidData(String),
}

impl From<rocksdb::Error> for IndexerError {
    fn from(err: rocksdb::Error) -> Self {
        IndexerError::RocksDB(err)
    }
}

impl From<hex::FromHexError> for IndexerError {
    fn from(err: hex::FromHexError) -> Self {
        IndexerError::Hex(err)
    }
}

#[derive(Debug)]
pub struct Page {
    digest: Noun,           // block-id
   // pow: Noun,              // unit proof
    parent: Noun,           // block-id
    tx_ids: Noun,           // z-set tx-id
    coinbase: Noun,         // coinbase-split
    timestamp: Noun,        // @
    epoch_counter: Noun,    // @ud
    target: Noun,           // bignum:bn
    accumulated_work: Noun, // bignum:bn
    height: Noun,           // @ud (direct atom)
                            // msg: Noun,           // page-msg (optional)
}

impl Page {
    pub fn from_noun(noun: Noun) -> Result<Self, NockAppError> {
        if !noun.is_cell() {
            debug!("indexer:  page noun was not cell: {:?}", noun);
            return Err(NockAppError::OtherError);
        } else {
            debug!("indexer:  page noun is cell: {:?}", noun);
        }

        // For debugging intermittent issues
        debug!("indexer:  raw page noun: {:?}", noun);

        let fields = [
            (1, "digest"),
           // (2, "pow"),
            (3, "parent"),
            (4, "tx_ids"),
            (5, "coinbase"),
            (6, "timestamp"),
            (7, "epoch_counter"),
            (8, "target"),
            (9, "accumulated_work"),
            (10, "height"),
        ];

        let mut extracted = Vec::with_capacity(fields.len());
        for &(idx, name) in &fields {
            let slot = (1u64 << (idx + 1)) - 2;
            let value = noun
                .slot(slot)
                .map_err(|e| {
                    error!("Failed to access slot {} for {}: {:?}", slot, name, e);
                    NockAppError::OtherError
                })?
                .clone();
            extracted.push(value);
        }

        let page = Page {
            digest: extracted[0].clone(),
            //pow: extracted[1].clone(),
            parent: extracted[1].clone(),
            tx_ids: extracted[2].clone(),
            coinbase: extracted[3].clone(),
            timestamp: extracted[4].clone(),
            epoch_counter: extracted[5].clone(),
            target: extracted[6].clone(),
            accumulated_work: extracted[7].clone(),
            height: extracted[8].clone(),
        };

        page.validate()?;
        Ok(page)
    }

    pub fn validate(&self) -> Result<(), NockAppError> {
        // Validate expected atom/cell types
        if !self.digest.is_cell() {
            error!("indexer:  invalid digest: not cell {:?}", self.digest);
            return Err(NockAppError::OtherError);
        }
        // if !self.pow.is_cell() && !self.pow.is_atom() {
        //     debug!("indexer:  invalid pow: not cell or atom {:?}", self.pow);
        //     return Err(NockAppError::OtherError);
        // }
        if !self.parent.is_cell() {
            error!("indexer:  invalid parent: not cell {:?}", self.parent);
            return Err(NockAppError::OtherError);
        }
        if !self.tx_ids.is_cell() && !self.tx_ids.is_atom() {
            error!(
                "indexer:  invalid tx-ids: not cell or atom {:?}",
                self.tx_ids
            );
            return Err(NockAppError::OtherError);
        }
        if !self.coinbase.is_cell() {
            error!("indexer:  invalid coinbase: not cell {:?}", self.coinbase);
            return Err(NockAppError::OtherError);
        }
        if !self.timestamp.is_atom() {
            error!("indexer:  invalid timestamp: not atom {:?}", self.timestamp);
            return Err(NockAppError::OtherError);
        }
        if !self.epoch_counter.is_atom() {
            error!(
                "indexer:  invalid epoch_counter: not atom {:?}",
                self.epoch_counter
            );
            return Err(NockAppError::OtherError);
        }
        if !self.height.is_atom() {
            error!("indexer:  invalid height: not atom {:?}", self.height);
            return Err(NockAppError::OtherError);
        }
        // todo: Add range checks for height, epoch_counter
        if let Ok(h) = self.height.as_direct() {
            if h.data() == 0 {
                error!("indexer:  invalid height: zero {:?}", self.height);
                return Err(NockAppError::OtherError);
            }
        }
        Ok(())
    }

    pub fn get_field(&self, field: &str) -> Result<&Noun, NockAppError> {
        match field {
            "digest" => Ok(&self.digest),
            //"pow" => Ok(&self.pow),
            "parent" => Ok(&self.parent),
            "tx-ids" => Ok(&self.tx_ids),
            "coinbase" => Ok(&self.coinbase),
            "timestamp" => Ok(&self.timestamp),
            "epoch_counter" => Ok(&self.epoch_counter),
            "target" => Ok(&self.target),
            "accumulated_work" => Ok(&self.accumulated_work),
            "height" => Ok(&self.height),
            //"msg" => Ok(&self.msg),
            _ => {
                debug!("Unknown field: {}", field);
                Err(NockAppError::OtherError)
            }
        }
    }

    pub fn get_second_value(&self, field: &str) -> Result<Noun, NockAppError> {
        let field_noun = self.get_field(field)?;
        field_noun.slot(3).map_err(|e| {
            debug!("Failed to get second value of {}: {:?}", field, e);
            NockAppError::OtherError
        })
    }
    pub fn format_as_ud(&self, field: &str) -> String {
        match self.get_field(field) {
            Ok(noun) => match noun.atom() {
                Some(atom) => {
                    if let Ok(value) = atom.as_direct() {
                        value.data().to_string()
                    } else {
                        debug!("large atom: {:?}", atom);
                        // Large atom (e.g., timestamp)
                        atom.as_ubig(&mut NockStack::new(8 << 10 << 10, 64)).to_string() // e.g., 360777252496
                    }
                }
                None => format!("invalid (not atom): {:?}", noun),
            },
            Err(e) => format!("error: {:?}", e),
        }
    }

    // DB methods

fn noun_to_bytes(&self, noun: &Noun) -> Result<Vec<u8>, IndexerError> {
        let jammed = noun.jam_self(&mut NockStack::new(8 << 10 << 10, 64));
        Ok(<JammedNoun as AsRef<[u8]>>::as_ref(&jammed).to_vec())
    }

    // Serialize Page to bytes (for pages CF)
    fn to_bytes(&self) -> Result<Vec<u8>, IndexerError> {
        let fields = [
            ("digest", &self.digest),
            ("parent", &self.parent),
            ("tx_ids", &self.tx_ids),
            ("coinbase", &self.coinbase),
            ("timestamp", &self.timestamp),
            ("epoch_counter", &self.epoch_counter),
            ("target", &self.target),
            ("accumulated_work", &self.accumulated_work),
            ("height", &self.height),
        ];

        let mut bytes = Vec::new();
        for (_name, noun) in fields.iter() {
            let jammed_bytes = self.noun_to_bytes(noun)?;
            bytes.extend_from_slice(&(jammed_bytes.len() as u32).to_le_bytes()); // Prefix with length
            bytes.extend_from_slice(&jammed_bytes);
        }
        Ok(bytes)
    }

    // Deserialize Page from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Option<Self>, IndexerError> {
        let mut offset = 0;
        let mut nouns = Vec::new();

        // Read 9 fields (digest, parent, tx_ids, coinbase, timestamp, epoch_counter, target, accumulated_work, height)
        for _ in 0..9 {
            if offset + 4 > bytes.len() {
                warn!("Incomplete data while reading length");
                return Err(IndexerError::InvalidData("Incomplete data".to_string()));
            }
            let len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if offset + len > bytes.len() {
                warn!("Invalid length field");
                return Err(IndexerError::InvalidData("Invalid length".to_string()));
            }
            let jammed = JammedNoun::new(bytes[offset..offset + len].to_vec().into());
            nouns.push(jammed.cue_self(&mut NockStack::new(8 << 10 << 10, 64)).map_err(|e| IndexerError::InvalidData(format!("Cue failed: {:?}", e)))?);
            offset += len;
        }

        if nouns.len() != 9 {
            return Err(IndexerError::InvalidData("Wrong number of fields".to_string()));
        }

        Ok(Some(Page {
            digest: nouns[0],
            //pow: nouns[1],
            parent: nouns[1],
            tx_ids: nouns[2],
            coinbase: nouns[3],
            timestamp: nouns[4],
            epoch_counter: nouns[5],
            target: nouns[6],
            accumulated_work: nouns[7],
            height: nouns[8],
        }))
    } 
        // Insert Page into RocksDB
    pub fn insert_to_db(&self, db: &DB) -> Result<(), IndexerError> {
        let cf_pages = db.cf_handle("pages").unwrap();
        let cf_height = db.cf_handle("height_to_digest").unwrap();

        let digest_bytes = self.noun_to_bytes(&self.digest)?;
        // Check for duplicate
        if db.get_cf(&cf_pages, &digest_bytes)?.is_some() {
            info!("indexer:  skipping duplicate block: {:?}", self.digest);
            return Ok(());
        }

        let mut batch = WriteBatch::default();
        let height_str = self.format_as_ud("height");

        // Store full page in pages CF
        batch.put_cf(&cf_pages, &digest_bytes, self.to_bytes()?);
        // Map height to digest in height_to_digest CF
        batch.put_cf(&cf_height, height_str.as_bytes(), &digest_bytes);

        db.write(batch)?;
        Ok(())
    }

// Query by height
    pub fn query_by_height(db: &DB, height: u64) -> Result<Option<Self>, IndexerError> {
        let cf_height = db.cf_handle("height_to_digest").unwrap();
        let cf_pages = db.cf_handle("pages").unwrap();

        let height_key = height.to_string();
        if let Some(digest_bytes) = db.get_cf(&cf_height, height_key.as_bytes())? {
            if let Some(page_bytes) = db.get_cf(&cf_pages, &digest_bytes)? {
                return Self::from_bytes(&page_bytes);
            }
        }
        Ok(None)
    }

    // Query by digest
    pub fn query_by_digest(db: &DB, digest: &str) -> Result<Option<Self>, IndexerError> {
        let cf_pages = db.cf_handle("pages").unwrap();
        let digest_bytes = if digest.starts_with("0x_") {
            decode(&digest[3..])?
        } else {
            digest.as_bytes().to_vec()
        };
        if let Some(page_bytes) = db.get_cf(&cf_pages, &digest_bytes)? {
            return Self::from_bytes(&page_bytes);
        }
        Ok(None)
    }
}

async fn log_page_fields(page: &Page) {
    let fields = [
        ("digest", 2),
        //("pow", 6),
        ("parent", 14),
        ("tx-ids", 30),
        ("coinbase", 62),
        ("timestamp", 126),
        ("epoch_counter", 254),
        ("target", 510),
        ("accumulated_work", 1022),
        ("height", 2046),
    ];

    for (name, slot) in fields.iter() {
        match *name {
            "height" | "epoch_counter" | "timestamp" => {
                info!(
                    "Field {} (slot {}): {}",
                    name,
                    slot,
                    page.format_as_ud(name)
                );
            }
            _ => match page.get_field(name) {
                Ok(field) => {
                    debug!("Field {} (slot {}): {:?}", name, slot, field);
                    if name == &"digest" || name == &"pow" {
                        match page.get_second_value(name) {
                            Ok(second) => debug!("Second value of {}: {:?}", name, second),
                            Err(e) => debug!("Failed to get second value of {}: {:?}", name, e),
                        }
                    }
                }
                Err(e) => debug!("Field {} (slot {}): {:?}", name, slot, e),
            },
        }
    }
}

// Initialize RocksDB with column families
fn init_db(path: &str) -> Result<DB, rocksdb::Error> {
    let mut cf_opts = Options::default();
    cf_opts.create_if_missing(true);

    let cf_names = vec![
        ColumnFamilyDescriptor::new("pages", cf_opts.clone()),
        ColumnFamilyDescriptor::new("height_to_digest", cf_opts),
    ];

    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);

    DB::open_cf_descriptors(&db_opts, Path::new(path), cf_names)
}

pub fn make_indexer_driver(enable_indexer: bool) -> IODriverFn {
    make_driver(move |handle| async move {
        if !enable_indexer {
            return Ok(());
        }
        info!("Starting indexer driver");

        // Initialize RocksDB
        let db_path = ".data.nockchain/indexer";
        let db = init_db(db_path).expect("Failed to initialize RocksDB");

        loop {
            match handle.next_effect().await {
                Ok(effect) => {
                    let Ok(effect_cell) = unsafe { effect.root() }.as_cell() else {
                        continue;
                    };
                    if unsafe { effect_cell.head().raw_equals(&D(tas!(b"gossip"))) } {
                        // Check if it's a heard-block gossip
                        let gossip_cell = effect_cell.tail().as_cell()?;
                        let data_cell = gossip_cell.tail(); // Skip version
                        if let Ok(data_cell) = data_cell.as_cell() {
                            if data_cell.head().eq_bytes(b"heard-block") {
                                debug!("indexer:  heard-block gossip received");

                                let mut slab = NounSlab::<NockJammer>::new();
                                let tag = make_tas(&mut slab, "heaviest-block").as_noun();
                                let path = T(&mut slab, &[tag, D(0)]);
                                slab.set_root(path);

                                info!("indexing block");
                                match handle.peek(slab).await {
                                    Ok(Some(result)) => {
                                        debug!("indexer:  got peek result");
                                        let root_noun = unsafe { result.root() };
                                        debug!("indexer:  extracted root noun: {:?}", root_noun);

                                        match ScryResult::from(root_noun) {
                                            ScryResult::Some(page_noun) => {
                                                debug!(
                                                    "indexer:  valid scry result: {:?}",
                                                    page_noun
                                                );
                                                match Page::from_noun(page_noun.clone()) {
                                                    Ok(page) => {
                                                        debug!("indexer:  parsed page: {:?}", page);
                                                        match page.validate() {
                                                            Ok(_) => {
                                                                debug!("indexer:  page validation succeeded")
                                                            }
                                                            Err(e) => debug!(
                                                        "indexer:  page validation failed: {:?}",
                                                        e
                                                    ),
                                                        }
                                                        log_page_fields(&page).await;
                                                        if let Err(e) = page.insert_to_db(&db) {
                                                            error!(
                                                                "failed to insert page to DB: {:?}",
                                                                e
                                                            );
                                                            continue;
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!(
                                                            "indexer:  failed to parse page: {:?}",
                                                            e
                                                        );
                                                        continue;
                                                    }
                                                }
                                            }
                                            ScryResult::BadPath => {
                                                debug!("indexer:  invalid scry path")
                                            }
                                            ScryResult::Nothing => {
                                                debug!("indexer:  no block data")
                                            }
                                            ScryResult::Invalid => {
                                                debug!(
                                                    "indexer:  invalid scry result: {:?}",
                                                    root_noun
                                                )
                                            }
                                        }
                                    }
                                    Ok(None) => debug!("indexer:  peek returned no result"),
                                    Err(e) => error!("indexer:  peek failed: {:?}", e),
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Error in indexer driver: {:?}", e);
                    continue;
                }
            }
        }
    })
}
