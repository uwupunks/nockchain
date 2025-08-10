use nockvm::noun::{Noun, Slots, D, T};
use nockvm_macros::tas;
use tracing::{debug, error, info};

use crate::nockapp::driver::{make_driver, IODriverFn};
use crate::nockapp::NockAppError;
use crate::noun::slab::{NockJammer, NounSlab};
use crate::utils::make_tas;
use crate::utils::scry::ScryResult;
use crate::NounExt;

#[derive(Debug)]
pub struct Page {
    digest: Noun,           // block-id
    pow: Noun,              // unit proof
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
            (2, "pow"),
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
                    debug!("Failed to access slot {} for {}: {:?}", slot, name, e);
                    NockAppError::OtherError
                })?
                .clone();
            extracted.push(value);
        }

        let page = Page {
            digest: extracted[0].clone(),
            pow: extracted[1].clone(),
            parent: extracted[2].clone(),
            tx_ids: extracted[3].clone(),
            coinbase: extracted[4].clone(),
            timestamp: extracted[5].clone(),
            epoch_counter: extracted[6].clone(),
            target: extracted[7].clone(),
            accumulated_work: extracted[8].clone(),
            height: extracted[9].clone(),
        };

        page.validate()?;
        Ok(page)
    }

    pub fn validate(&self) -> Result<(), NockAppError> {
        // Validate expected atom/cell types
        if !self.digest.is_cell() {
            debug!("indexer:  invalid digest: not cell {:?}", self.digest);
            return Err(NockAppError::OtherError);
        }
        if !self.pow.is_cell() && !self.pow.is_atom() {
            debug!("indexer:  invalid pow: not cell or atom {:?}", self.pow);
            return Err(NockAppError::OtherError);
        }
        if !self.parent.is_cell() {
            debug!("indexer:  invalid parent: not cell {:?}", self.parent);
            return Err(NockAppError::OtherError);
        }
        if !self.tx_ids.is_cell() && !self.tx_ids.is_atom() {
            debug!(
                "indexer:  invalid tx-ids: not cell or atom {:?}",
                self.tx_ids
            );
            return Err(NockAppError::OtherError);
        }
        if !self.coinbase.is_cell() {
            debug!("indexer:  invalid coinbase: not cell {:?}", self.coinbase);
            return Err(NockAppError::OtherError);
        }
        if !self.timestamp.is_atom() {
            debug!("indexer:  invalid timestamp: not atom {:?}", self.timestamp);
            return Err(NockAppError::OtherError);
        }
        if !self.epoch_counter.is_atom() {
            debug!(
                "indexer:  invalid epoch-counter: not atom {:?}",
                self.epoch_counter
            );
            return Err(NockAppError::OtherError);
        }
        if !self.height.is_atom() {
            debug!("indexer:  invalid height: not atom {:?}", self.height);
            return Err(NockAppError::OtherError);
        }
        // Optional: Add range checks for height, epoch_counter
        if let Ok(h) = self.height.as_direct() {
            if h.data() == 0 {
                debug!("indexer:  invalid height: zero {:?}", self.height);
                return Err(NockAppError::OtherError);
            }
        }
        Ok(())
    }

    pub fn get_field(&self, field: &str) -> Result<&Noun, NockAppError> {
        match field {
            "digest" => Ok(&self.digest),
            "pow" => Ok(&self.pow),
            "parent" => Ok(&self.parent),
            "tx-ids" => Ok(&self.tx_ids),
            "coinbase" => Ok(&self.coinbase),
            "timestamp" => Ok(&self.timestamp),
            "epoch-counter" => Ok(&self.epoch_counter),
            "target" => Ok(&self.target),
            "accumulated-work" => Ok(&self.accumulated_work),
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
                        format!("large atom: {:?}", atom)
                    }
                }
                None => format!("invalid (not atom): {:?}", noun),
            },
            Err(e) => format!("error: {:?}", e),
        }
    }
}

async fn log_page_fields(page: &Page) {
    let fields = [
        ("digest", 2),
        ("pow", 6),
        ("parent", 14),
        ("tx-ids", 30),
        ("coinbase", 62),
        ("timestamp", 126),
        ("epoch-counter", 254),
        ("target", 510),
        ("accumulated-work", 1022),
        ("height", 2046),
    ];

    for (name, slot) in fields.iter() {
        match *name {
            "height" | "epoch-counter" | "timestamp" => {
                debug!(
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
pub fn make_indexer_driver(enable_indexer: bool) -> IODriverFn {
    make_driver(move |handle| async move {
        if !enable_indexer {
            return Ok(());
        }
        info!("Starting indexer driver");

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
                                            ScryResult::Nothing => debug!("indexer:  no block data"),
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
