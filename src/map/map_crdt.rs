// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::metadata::{Address, Key, Owner, Perm, Value};
use crate::{Error, PublicKey, Result};
use crdts::{lseq::LSeq, CmRDT, MVReg, Map};
pub use crdts::{lseq::Op, Actor};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display},
    hash::Hash,
};

/// Since in most of the cases it will be appends operations, having a small
/// boundary will make the Identifiers' length to be shorter.
const LSEQ_BOUNDARY: u64 = 1;
/// Again, we are going to be dealing with append operations most of the time,
/// thus a large arity be benefitial to keep Identifiers' length short.
const LSEQ_TREE_BASE: u8 = 10; // arity of 1024 at root

/// Map data type as a CRDT
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd)]
pub struct MapCrdt<A, P>
where
    A: Actor,
    P: Perm + Hash + Clone,
{
    /// Address on the network of this piece of data
    address: Address,
    /// CRDT to store the actual data
    data: Map<u8, Map<u8, u8, A>, A>,
    /// This is the history of permissions matrix, with each entry representing a permissions matrix.
    permissions: LSeq<P, A>,
    /// This is the history of owners, with each entry representing an owner. Each single owner
    /// could represent an individual user, or a group of users, depending on the `PublicKey` type.
    owners: LSeq<Owner, A>,
}

impl<A, P> Display for MapCrdt<A, P>
where
    A: Actor,
    P: Perm + Hash + Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Map data entries list")
    }
}

impl<A, P> MapCrdt<A, P>
where
    A: Actor,
    P: Perm + Hash + Clone,
{
    /// Constructs a new 'SequenceCrdt'.
    pub fn new(actor: A, address: Address) -> Self {
        Self {
            address,
            data: Map::new(),
            permissions: LSeq::new_with_args(actor.clone(), LSEQ_TREE_BASE, LSEQ_BOUNDARY),
            owners: LSeq::new_with_args(actor, LSEQ_TREE_BASE, LSEQ_BOUNDARY),
        }
    }

    /// Returns the address.
    pub fn address(&self) -> &Address {
        &self.address
    }
}
