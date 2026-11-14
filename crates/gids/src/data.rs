use apdu_app::CommandView;
use heapless::{Vec, VecView};
use iso7816::Status;

use crate::{
    acl, store, tlv, Client, Gids, Result, EF_ATR, FDB_DO_EF, FID_CURRENT_DF, FID_CURRENT_EF,
    FID_EF_ATR, FID_EF_DIR,
};

const TAG_KEY_USAGE_TEMPLATE: u8 = 0x70;
const TAG_GLOBAL_PIN_STATUS: &[u8] = &[0x7F, 0x71];
const TAG_LOCAL_PIN_STATUS: &[u8] = &[0x7F, 0x72];
const TAG_LOCAL_PUK_STATUS: &[u8] = &[0x7F, 0x73];
const TAG_CARD_CAPABILITY_DESCRIPTION: &[u8] = &[0x7F, 0x62];
const TAG_APPLICATION_CAPABILITY_DESCRIPTION: &[u8] = &[0x7F, 0x63];
const MAX_OBJECTS: usize = 32;

fn is_constructed(tag: &[u8]) -> bool {
    tag.first().is_some_and(|first| first & 0x20 != 0)
}

fn well_formed_constructed(value: &[u8]) -> bool {
    let mut data = value;
    let mut count = 0;
    while !data.is_empty() {
        let Some((_, _, rest)) = tlv::take_tlv(data) else {
            return false;
        };
        data = rest;
        count += 1;
    }
    count >= 2
}

struct DataObject<'a> {
    tag: &'a [u8],
    value: &'a [u8],
    encoded: &'a [u8],
}

fn split_objects(mut data: &[u8]) -> Result<Vec<DataObject<'_>, MAX_OBJECTS>> {
    let mut objects = Vec::new();
    while !data.is_empty() {
        let (tag, rest) = tlv::take_tag(data).ok_or(Status::IncorrectDataParameter)?;
        let (len, value) = tlv::take_len(rest).ok_or(Status::NcInconsistentWithTlv)?;
        if value.len() < len {
            return Err(Status::NcInconsistentWithTlv);
        }
        let header_len = data.len() - value.len();
        let (encoded, rest) = data.split_at(header_len + len);
        let value = &value[..len];
        if is_constructed(tag) && !value.is_empty() && !well_formed_constructed(value) {
            return Err(Status::IncorrectDataParameter);
        }
        objects
            .push(DataObject {
                tag,
                value,
                encoded,
            })
            .map_err(|_| Status::NotEnoughMemory)?;
        data = rest;
    }
    if objects.is_empty() {
        return Err(Status::IncorrectDataParameter);
    }
    Ok(objects)
}

enum TagList<'a> {
    All,
    Tags,
    Single(&'a [u8]),
}

fn parse_tag_list(data: &[u8]) -> Result<TagList<'_>> {
    let (tag, value, rest) = tlv::take_tlv(data).ok_or(Status::IncorrectDataParameter)?;
    if tag != [0x5C] || !rest.is_empty() {
        return Err(Status::IncorrectDataParameter);
    }
    match value {
        [] => Ok(TagList::All),
        [0x5C] => Ok(TagList::Tags),
        tag if tlv::take_tag(tag).is_some_and(|(_, rest)| rest.is_empty()) => {
            Ok(TagList::Single(tag))
        }
        _ => Err(Status::IncorrectDataParameter),
    }
}

#[derive(Default)]
struct Search {
    found: bool,
    denied: bool,
}

impl<T: Client> Gids<T> {
    pub(crate) fn get_data(&mut self, apdu: CommandView<'_>, reply: &mut VecView<u8>) -> Result {
        let fid = u16::from_be_bytes([apdu.p1, apdu.p2]);
        match fid {
            FID_EF_ATR => {
                Self::expect_all(apdu.data())?;
                tlv::extend(reply, EF_ATR)
            }
            FID_EF_DIR => {
                Self::expect_all(apdu.data())?;
                Self::application_template(reply)
            }
            FID_CURRENT_DF => {
                if matches!(apdu.data().first(), Some(&TAG_KEY_USAGE_TEMPLATE | &0xA3)) {
                    return self.get_public_key(apdu.data(), reply);
                }
                let list = parse_tag_list(apdu.data())?;
                if let TagList::Single(tag) = list {
                    if matches!(
                        tag,
                        TAG_GLOBAL_PIN_STATUS | TAG_LOCAL_PIN_STATUS | TAG_LOCAL_PUK_STATUS
                    ) {
                        return self.pin_status(tag, reply);
                    }
                    if matches!(
                        tag,
                        TAG_CARD_CAPABILITY_DESCRIPTION | TAG_APPLICATION_CAPABILITY_DESCRIPTION
                    ) {
                        return tlv::push_tlv(reply, tag, &[]);
                    }
                }
                self.get_from_application(list, reply)
            }
            fid => {
                let fid = if fid == FID_CURRENT_EF {
                    self.selected_ef.ok_or(Status::NotFound)?
                } else {
                    fid
                };
                let list = parse_tag_list(apdu.data())?;
                let record = store::load_ef(&mut self.trussed, fid)?.ok_or(Status::NotFound)?;
                if record.descriptor() != Some(FDB_DO_EF) {
                    return Err(Status::CommandIncompatibleFileStructure);
                }
                self.check_ef_access(&record, acl::OP_DO_GET)?;
                let mut search = Search::default();
                self.collect(&store::do_prefix(fid), &list, &mut search, reply)?;
                if !search.found {
                    return Err(Status::KeyReferenceNotFound);
                }
                self.selected_ef = Some(fid);
                Ok(())
            }
        }
    }

    fn expect_all(data: &[u8]) -> Result {
        match parse_tag_list(data)? {
            TagList::All => Ok(()),
            _ => Err(Status::IncorrectDataParameter),
        }
    }

    fn get_from_application(&mut self, list: TagList<'_>, reply: &mut VecView<u8>) -> Result {
        let state = self.state()?;
        let security = self.effective_security()?;
        let enforce = state.is_operational() || state.is_terminated();
        let mut search = Search::default();
        let mut current = None;
        let mut accessible = false;
        let mut denied = false;
        let start = reply.len();
        let mut tags: Vec<u8, 1024> = Vec::new();
        let mut result = Ok(());
        store::for_each_do(&mut self.trussed, b"d", |trussed, fid, tag| {
            if current != Some(fid) {
                current = Some(fid);
                let record = store::load_ef(trussed, fid)?.filter(|record| record.is_operational());
                accessible = record.as_ref().is_some_and(|record| {
                    !enforce || acl::allowed(record.find(&[0x8C]), acl::OP_DO_GET, security)
                });
                denied = record.is_some() && !accessible;
            }
            if !accessible {
                if denied && !matches!(list, TagList::Single(wanted) if wanted != tag) {
                    search.denied = true;
                }
                return Ok(true);
            }
            if let Err(status) = Self::emit(trussed, fid, tag, &list, &mut search, reply, &mut tags)
            {
                result = Err(status);
                return Ok(false);
            }
            Ok(true)
        })?;
        result?;
        if let TagList::Tags = list {
            if search.found {
                tlv::push_tlv(reply, &[0x5C], &tags)?;
            }
        }
        if !search.found {
            reply.truncate(start);
            return Err(if search.denied {
                Status::SecurityStatusNotSatisfied
            } else {
                Status::KeyReferenceNotFound
            });
        }
        Ok(())
    }

    fn collect(
        &mut self,
        prefix: &[u8],
        list: &TagList<'_>,
        search: &mut Search,
        reply: &mut VecView<u8>,
    ) -> Result {
        let mut tags: Vec<u8, 1024> = Vec::new();
        let mut result = Ok(());
        store::for_each_do(&mut self.trussed, prefix, |trussed, fid, tag| {
            if let Err(status) = Self::emit(trussed, fid, tag, list, search, reply, &mut tags) {
                result = Err(status);
                return Ok(false);
            }
            Ok(true)
        })?;
        result?;
        if let TagList::Tags = list {
            if search.found {
                tlv::push_tlv(reply, &[0x5C], &tags)?;
            }
        }
        Ok(())
    }

    fn emit(
        trussed: &mut T,
        fid: u16,
        tag: &[u8],
        list: &TagList<'_>,
        search: &mut Search,
        reply: &mut VecView<u8>,
        tags: &mut Vec<u8, 1024>,
    ) -> Result {
        match list {
            TagList::Single(wanted) if *wanted != tag => Ok(()),
            TagList::Tags => {
                search.found = true;
                tags.extend_from_slice(tag)
                    .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)
            }
            _ => {
                search.found = true;
                store::read_into(trussed, store::do_path(fid, tag), reply)?;
                Ok(())
            }
        }
    }

    pub(crate) fn put_data(&mut self, apdu: CommandView<'_>) -> Result {
        let state = self.state()?;
        if state.is_terminated() {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        let target = u16::from_be_bytes([apdu.p1, apdu.p2]);
        let data = apdu.data();
        if target == FID_CURRENT_DF && data.first() == Some(&TAG_KEY_USAGE_TEMPLATE) {
            return self.put_key(data);
        }
        if matches!(target, FID_EF_ATR | FID_EF_DIR) {
            return Err(Status::SecurityStatusNotSatisfied);
        }
        let objects = split_objects(data)?;
        let explicit = match target {
            FID_CURRENT_EF => Some(self.selected_ef.ok_or(Status::NotFound)?),
            FID_CURRENT_DF => None,
            fid => Some(fid),
        };

        let mut checked: Vec<u16, MAX_OBJECTS> = Vec::new();
        let mut owners: Vec<u16, MAX_OBJECTS> = Vec::new();
        for object in &objects {
            let fid = match explicit {
                Some(fid) => fid,
                None => self.unique_do_owner(object.tag)?,
            };
            if !checked.contains(&fid) {
                let record = store::load_ef(&mut self.trussed, fid)?.ok_or(Status::NotFound)?;
                if record.descriptor() != Some(FDB_DO_EF) {
                    return Err(Status::CommandIncompatibleFileStructure);
                }
                self.check_ef_access(&record, acl::OP_DO_PUT)?;
                checked.push(fid).ok();
            }
            owners.push(fid).map_err(|_| Status::NotEnoughMemory)?;
        }

        for (object, fid) in objects.iter().zip(&owners) {
            let path = store::do_path(*fid, object.tag);
            if object.value.is_empty() && store::exists(&mut self.trussed, path.clone())? {
                store::remove(&mut self.trussed, path)?;
            } else {
                store::write(&mut self.trussed, path, object.encoded)?;
            }
        }
        if let Some(fid) = explicit {
            self.selected_ef = Some(fid);
        }
        Ok(())
    }

    fn unique_do_owner(&mut self, wanted: &[u8]) -> Result<u16> {
        let mut owner = None;
        let mut duplicate = false;
        store::for_each_do(&mut self.trussed, b"d", |_, fid, tag| {
            if tag == wanted {
                if owner.is_some() {
                    duplicate = true;
                    return Ok(false);
                }
                owner = Some(fid);
            }
            Ok(true)
        })?;
        if duplicate {
            return Err(Status::IncorrectDataParameter);
        }
        owner.ok_or(Status::KeyReferenceNotFound)
    }
}
