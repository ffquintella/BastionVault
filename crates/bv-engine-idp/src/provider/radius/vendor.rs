//! Per-vendor attribute templates: which vendor-specific attributes an
//! Access-Accept carries for each environment role. Data, validated when it
//! is written; FortiGate's `Fortinet-Group-Name` is the first named kind.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::packet::{vendor_specific, MAX_VSA_VALUE_LEN};
use crate::posix::model::PosixError;

pub const FORTINET_VENDOR_ID: u32 = 12356;
pub const CISCO_VENDOR_ID: u32 = 9;
/// The generic kind: any vendor id and sub-attribute type, string value.
pub const GENERIC_VSA: &str = "vsa";
pub const MAX_ATTRIBUTES_PER_ROLE: usize = 8;

/// A named attribute this provider encodes (FreeRADIUS dictionary numbers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownAttribute {
    pub name: &'static str,
    pub vendor_id: u32,
    pub vendor_type: u8,
}

pub const KNOWN_ATTRIBUTES: &[KnownAttribute] = &[
    KnownAttribute { name: "fortinet-group-name", vendor_id: FORTINET_VENDOR_ID, vendor_type: 1 },
    KnownAttribute { name: "fortinet-vdom-name", vendor_id: FORTINET_VENDOR_ID, vendor_type: 3 },
    KnownAttribute { name: "fortinet-access-profile", vendor_id: FORTINET_VENDOR_ID, vendor_type: 6 },
    KnownAttribute { name: "cisco-avpair", vendor_id: CISCO_VENDOR_ID, vendor_type: 1 },
];

/// One attribute as stored: resolved to numbers at write time, so a later
/// change to [`KNOWN_ATTRIBUTES`] cannot change what an Accept carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VendorAttribute {
    /// A [`KNOWN_ATTRIBUTES`] name or [`GENERIC_VSA`].
    pub attribute: String,
    pub vendor_id: u32,
    pub vendor_type: u8,
    pub value: String,
}

impl VendorAttribute {
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("attribute".into(), self.attribute.clone().into());
        m.insert("vendor_id".into(), self.vendor_id.into());
        m.insert("vendor_type".into(), self.vendor_type.into());
        m.insert("value".into(), self.value.clone().into());
        Value::Object(m)
    }

    /// The encoded Vendor-Specific value.
    pub fn encode(&self) -> Result<Vec<u8>, PosixError> {
        vendor_specific(self.vendor_id, self.vendor_type, self.value.as_bytes())
            .map_err(|_| PosixError::Invalid(format!("attribute `{}` cannot be encoded", self.attribute)))
    }

    fn validate(&self) -> Result<(), PosixError> {
        let bad = |why: &str| PosixError::Invalid(format!("attribute `{}`: {why}", self.attribute));
        if self.vendor_id == 0 || self.vendor_id > 0x00FF_FFFF {
            return Err(bad("vendor_id must lie within [1, 16777215]"));
        }
        if self.vendor_type == 0 {
            return Err(bad("vendor_type must lie within [1, 255]"));
        }
        if self.value.is_empty() || self.value.len() > MAX_VSA_VALUE_LEN {
            return Err(bad(&format!("value must be 1-{MAX_VSA_VALUE_LEN} bytes")));
        }
        if self.value.chars().any(char::is_control) {
            return Err(bad("value must not contain control characters"));
        }
        match KNOWN_ATTRIBUTES.iter().find(|k| k.name == self.attribute) {
            Some(k) if k.vendor_id == self.vendor_id && k.vendor_type == self.vendor_type => Ok(()),
            Some(_) => Err(bad("vendor numbers do not match the named attribute")),
            None if self.attribute == GENERIC_VSA => Ok(()),
            None => Err(bad("unknown attribute kind")),
        }
    }
}

fn number(m: &Map<String, Value>, key: &str, max: u64) -> Result<Option<u64>, PosixError> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => match v.as_u64() {
            Some(n) if (1..=max).contains(&n) => Ok(Some(n)),
            _ => Err(PosixError::Invalid(format!("{key} must be an integer within [1, {max}]"))),
        },
    }
}

/// Parse one template from `{"attribute": ..., "value": ...}` (a named
/// kind) or `{"attribute": "vsa", "vendor_id": ..., "vendor_type": ...,
/// "value": ...}`.
pub fn parse_attribute(v: &Value) -> Result<VendorAttribute, PosixError> {
    let Value::Object(m) = v else {
        return Err(PosixError::Invalid("each attribute must be an object".into()));
    };
    if let Some(k) = m.keys().find(|k| !["attribute", "vendor_id", "vendor_type", "value"].contains(&k.as_str())) {
        return Err(PosixError::Invalid(format!("unknown attribute field `{k}`")));
    }
    let text = |key: &str| match m.get(key) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(PosixError::Invalid(format!("attribute field `{key}` must be a string"))),
    };
    let attribute = text("attribute")?;
    let value = text("value")?;
    let vendor_id = number(m, "vendor_id", 0x00FF_FFFF)?;
    let vendor_type = number(m, "vendor_type", 255)?;
    let resolved = if attribute == GENERIC_VSA {
        let (Some(id), Some(ty)) = (vendor_id, vendor_type) else {
            return Err(PosixError::Invalid("a `vsa` attribute needs vendor_id and vendor_type".into()));
        };
        VendorAttribute { attribute, vendor_id: id as u32, vendor_type: ty as u8, value }
    } else {
        let known = KNOWN_ATTRIBUTES
            .iter()
            .find(|k| k.name == attribute)
            .ok_or_else(|| PosixError::Invalid(format!("unknown attribute kind `{attribute}`")))?;
        if vendor_id.is_some() || vendor_type.is_some() {
            return Err(PosixError::Invalid(format!("`{attribute}` takes no vendor_id or vendor_type")));
        }
        VendorAttribute { attribute, vendor_id: known.vendor_id, vendor_type: known.vendor_type, value }
    };
    resolved.validate()?;
    Ok(resolved)
}

/// Validate a role's attribute list: at least one, at most
/// [`MAX_ATTRIBUTES_PER_ROLE`], each valid.
pub fn validate_role_attributes(role: &str, attrs: &[VendorAttribute]) -> Result<(), PosixError> {
    if attrs.is_empty() || attrs.len() > MAX_ATTRIBUTES_PER_ROLE {
        return Err(PosixError::Invalid(format!("role `{role}`: 1-{MAX_ATTRIBUTES_PER_ROLE} attributes")));
    }
    attrs.iter().try_for_each(VendorAttribute::validate)
}
