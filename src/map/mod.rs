// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod map_crdt;
mod metadata;

use crate::{Error, PublicKey, Result, XorName};
use map_crdt::{MapCrdt, Op};
pub use metadata::{
    Action, Address, Owner, Perm, Permissions, PrivPermissions, PrivUserPermissions,
    PubPermissions, PubUserPermissions, User, UserPermissions,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Formatter},
    hash::Hash,
};

// Type of data used for the 'Actor' in CRDT vector clocks
type ActorType = PublicKey;

/// Public Sequence.
pub type PublicMap = MapCrdt<ActorType, PubPermissions>;
/// Private Sequence.
pub type PrivateMap = MapCrdt<ActorType, PrivPermissions>;

impl Debug for PublicMap {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicMap {:?}", self.address().name())
    }
}

impl Debug for PrivateMap {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PrivateMap {:?}", self.address().name())
    }
}

/// Object storing a Sequence variant.
#[derive(Clone, Eq, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Data {
    /// Public Sequence Data.
    Public(PublicMap),
    /// Private Sequence Data.
    Private(PrivateMap),
}
