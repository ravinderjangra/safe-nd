// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{utils, Error, PublicKey, Result, XorName};
use multibase::Decodable;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Debug, hash::Hash};

/// A key in a Map.
pub type Key = Vec<u8>;

/// A value stored for any key in a Map.
pub type Value = Vec<u8>;

/// Set of Actions that can be performed on the Map.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Action {
    /// Permission to read entries.
    Read,
    /// Permission to insert new entries.
    Insert,
    /// Permission to update existing entries.
    Update,
    /// Permission to delete existing entries.
    Delete,
    /// Permission to modify permissions for other users.
    ManagePermissions,
}

/// Kind of a Map.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Kind {
    /// Public map.
    Public,
    /// Private map.
    Private,
}

impl Kind {
    /// Returns true if public.
    pub fn is_pub(self) -> bool {
        self == Kind::Public
    }

    /// Returns true if private.
    pub fn is_priv(self) -> bool {
        !self.is_pub()
    }
}

/// Address of a Map.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Address {
    /// Public map namespace.
    Public {
        /// Name.
        name: XorName,
        /// Tag.
        tag: u64,
    },
    /// Private map namespace.
    Private {
        /// Name.
        name: XorName,
        /// Tag.
        tag: u64,
    },
}

impl Address {
    /// Constructs a new `Address` given `kind`, `name`, and `tag`.
    pub fn from_kind(kind: Kind, name: XorName, tag: u64) -> Self {
        match kind {
            Kind::Public => Address::Public { name, tag },
            Kind::Private => Address::Private { name, tag },
        }
    }

    /// Returns the kind.
    pub fn kind(&self) -> Kind {
        match self {
            Address::Public { .. } => Kind::Public,
            Address::Private { .. } => Kind::Private,
        }
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        match self {
            Address::Public { ref name, .. } | Address::Private { ref name, .. } => name,
        }
    }

    /// Returns the tag.
    pub fn tag(&self) -> u64 {
        match self {
            Address::Public { tag, .. } | Address::Private { tag, .. } => *tag,
        }
    }

    /// Returns true if public.
    pub fn is_public(&self) -> bool {
        self.kind().is_pub()
    }

    /// Returns true if private.
    pub fn is_private(&self) -> bool {
        self.kind().is_priv()
    }

    /// Returns the `Address` serialised and encoded in z-base-32.
    pub fn encode_to_zbase32(&self) -> String {
        utils::encode(&self)
    }

    /// Creates from z-base-32 encoded string.
    pub fn decode_from_zbase32<I: Decodable>(encoded: I) -> Result<Self> {
        utils::decode(encoded)
    }
}

/// An owner could represent an individual user, or a group of users,
/// depending on the `public_key` type.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Owner {
    /// Public key.
    pub public_key: PublicKey,
    /// The current version of the data when this ownership change happened
    pub map_version: u64,
    /// The current index of the permissions when this ownership change happened
    pub permissions_index: u64,
}

/// Set of public permissions for a user.
#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PubUserPermissions {
    /// `Some(true)` if the user can read.
    /// `Some(false)` explicitly denies this permission (even if `Anyone` has required permissions).
    /// Use permissions for `Anyone` if `None`.
    read: Option<bool>,
    /// `Some(true)` if the user can read.
    /// `Some(false)` explicitly denies this permission (even if `Anyone` has required permissions).
    /// Use permissions for `Anyone` if `None`.
    insert: Option<bool>,
    /// `Some(true)` if the user can read.
    /// `Some(false)` explicitly denies this permission (even if `Anyone` has required permissions).
    /// Use permissions for `Anyone` if `None`.
    update: Option<bool>,
    /// `Some(true)` if the user can manage permissions.
    /// `Some(false)` explicitly denies this permission (even if `Anyone` has required permissions).
    /// Use permissions for `Anyone` if `None`.
    manage_permissions: Option<bool>,
}

impl PubUserPermissions {
    /// Constructs a new public permission set.
    pub fn new(
        read: impl Into<Option<bool>>,
        insert: impl Into<Option<bool>>,
        update: impl Into<Option<bool>>,
        manage_permissions: impl Into<Option<bool>>,
    ) -> Self {
        Self {
            read: read.into(),
            insert: insert.into(),
            update: update.into(),
            manage_permissions: manage_permissions.into(),
        }
    }

    /// Sets permissions.
    pub fn set_perms(
        &mut self,
        read: impl Into<Option<bool>>,
        insert: impl Into<Option<bool>>,
        update: impl Into<Option<bool>>,
        manage_permissions: impl Into<Option<bool>>,
    ) {
        self.read = read.into();
        self.insert = insert.into();
        self.update = update.into();
        self.manage_permissions = manage_permissions.into();
    }

    /// Returns `Some(true)` if `action` is allowed and `Some(false)` if it's not permitted.
    /// `None` means that default permissions should be applied.
    pub fn is_allowed(self, action: Action) -> Option<bool> {
        match action {
            Action::Read => Some(true), // It's public data, so it's always allowed to read it.
            Action::Insert => self.insert,
            Action::Update => self.update,
            Action::Delete => Some(false), // It's public data, so delete is never allowed.
            Action::ManagePermissions => self.manage_permissions,
        }
    }
}

/// Set of private permissions for a user.
#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PrivUserPermissions {
    /// `Some(true)` if the user can read.
    /// `Some(false)` explicitly denies this permission (even if `Anyone` has required permissions).
    /// Use permissions for `Anyone` if `None`.
    read: bool,
    /// `Some(true)` if the user can read.
    /// `Some(false)` explicitly denies this permission (even if `Anyone` has required permissions).
    /// Use permissions for `Anyone` if `None`.
    insert: bool,
    /// `Some(true)` if the user can read.
    /// `Some(false)` explicitly denies this permission (even if `Anyone` has required permissions).
    /// Use permissions for `Anyone` if `None`.
    update: bool,
    /// `Some(true)` if the user can read.
    /// `Some(false)` explicitly denies this permission (even if `Anyone` has required permissions).
    /// Use permissions for `Anyone` if `None`.
    delete: bool,
    /// `Some(true)` if the user can manage permissions.
    /// `Some(false)` explicitly denies this permission (even if `Anyone` has required permissions).
    /// Use permissions for `Anyone` if `None`.
    manage_permissions: bool,
}

impl PrivUserPermissions {
    /// Constructs a new private permission set.
    pub fn new(
        read: bool,
        insert: bool,
        update: bool,
        delete: bool,
        manage_permissions: bool,
    ) -> Self {
        Self {
            read,
            insert,
            update,
            delete,
            manage_permissions,
        }
    }

    /// Sets permissions.
    pub fn set_perms(
        &mut self,
        read: bool,
        insert: bool,
        update: bool,
        delete: bool,
        manage_permissions: bool,
    ) {
        self.read = read;
        self.insert = insert;
        self.update = update;
        self.delete = delete;
        self.manage_permissions = manage_permissions;
    }

    /// Returns `true` if `action` is allowed.
    pub fn is_allowed(self, action: Action) -> bool {
        match action {
            Action::Read => self.read,
            Action::Insert => self.insert,
            Action::Update => self.update,
            Action::Delete => self.delete,
            Action::ManagePermissions => self.manage_permissions,
        }
    }
}
/// User that can access Map.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub enum User {
    /// Any user.
    Anyone,
    /// User identified by its public key.
    Key(PublicKey),
}

/// Published permissions.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PubPermissions {
    /// Map of users to their public permission set.
    pub permissions: BTreeMap<User, PubUserPermissions>,
    /// The current index of the data when this permission change happened.
    pub map_version: u64,
    /// The current index of the owners when this permission change happened.
    pub owners_index: u64,
}

impl PubPermissions {
    /// Returns `Some(true)` if `action` is allowed for the provided user and `Some(false)` if it's
    /// not permitted. `None` means that default permissions should be applied.
    fn is_action_allowed_by_user(&self, user: &User, action: Action) -> Option<bool> {
        self.permissions
            .get(user)
            .and_then(|perms| perms.is_allowed(action))
    }
}

/// Private permissions.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PrivPermissions {
    /// Map of users to their private permission set.
    pub permissions: BTreeMap<PublicKey, PrivUserPermissions>,
    /// The current index of the data when this permission change happened.
    pub map_version: u64,
    /// The current index of the owners when this permission change happened.
    pub owners_index: u64,
}

pub trait Perm {
    /// Returns true if `action` is allowed for the provided user.
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> Result<()>;
    /// Gets the permissions for a user if applicable.
    fn user_permissions(&self, user: User) -> Option<UserPermissions>;
    /// Gets the last entry index.
    fn map_version(&self) -> u64;
    /// Gets the last owner index.
    fn owners_index(&self) -> u64;
}

impl Perm for PubPermissions {
    /// Returns `Ok(())` if `action` is allowed for the provided user and `Err(AccessDenied)` if
    /// this action is not permitted.
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> Result<()> {
        match self
            .is_action_allowed_by_user(&User::Key(requester), action)
            .or_else(|| self.is_action_allowed_by_user(&User::Anyone, action))
        {
            Some(true) => Ok(()),
            Some(false) => Err(Error::AccessDenied),
            None => Err(Error::AccessDenied),
        }
    }

    /// Gets the permissions for a user if applicable.
    fn user_permissions(&self, user: User) -> Option<UserPermissions> {
        self.permissions
            .get(&user)
            .map(|p| UserPermissions::Pub(*p))
    }

    /// Returns the version.
    fn map_version(&self) -> u64 {
        self.map_version
    }

    /// Returns the last owners index.
    fn owners_index(&self) -> u64 {
        self.owners_index
    }
}

impl Perm for PrivPermissions {
    /// Returns `Ok(())` if `action` is allowed for the provided user and `Err(AccessDenied)` if
    /// this action is not permitted.
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> Result<()> {
        match self.permissions.get(&requester) {
            Some(perms) => {
                if perms.is_allowed(action) {
                    Ok(())
                } else {
                    Err(Error::AccessDenied)
                }
            }
            None => Err(Error::AccessDenied),
        }
    }

    /// Gets the permissions for a user if applicable.
    fn user_permissions(&self, user: User) -> Option<UserPermissions> {
        match user {
            User::Anyone => None,
            User::Key(key) => self
                .permissions
                .get(&key)
                .map(|p| UserPermissions::Priv(*p)),
        }
    }

    /// Returns the version.
    fn map_version(&self) -> u64 {
        self.map_version
    }

    /// Returns the last owners index.
    fn owners_index(&self) -> u64 {
        self.owners_index
    }
}

/// Wrapper type for permissions, which can be public or private.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub enum Permissions {
    /// Public permissions.
    Pub(PubPermissions),
    /// Private permissions.
    Priv(PrivPermissions),
}

impl From<PrivPermissions> for Permissions {
    fn from(permissions: PrivPermissions) -> Self {
        Permissions::Priv(permissions)
    }
}

impl From<PubPermissions> for Permissions {
    fn from(permissions: PubPermissions) -> Self {
        Permissions::Pub(permissions)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub enum UserPermissions {
    /// Public permissions set.
    Pub(PubUserPermissions),
    /// Private permissions set.
    Priv(PrivUserPermissions),
}

impl From<PrivUserPermissions> for UserPermissions {
    fn from(permission_set: PrivUserPermissions) -> Self {
        UserPermissions::Priv(permission_set)
    }
}

impl From<PubUserPermissions> for UserPermissions {
    fn from(permission_set: PubUserPermissions) -> Self {
        UserPermissions::Pub(permission_set)
    }
}
