use std::{collections::HashMap, mem, sync::Arc, time::Duration};

use better_default::Default;
use derive_more::{Deref, DerefMut};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{
    validation::{create_hmac, verify_cidr_role_secret_id_subset, SecretIdStorageEntry},
    AppRoleBackend, AppRoleBackendInner, HMAC_INPUT_LEN_MAX, SECRET_ID_LOCAL_PREFIX, SECRET_ID_PREFIX,
};
use crate::kernel_api::VaultCtx;
use bv_auth_ferrogate::{machine_id as ferrogate_machine_id, MachineEntry};

use crate::{
    context::Context,
    errors::RvError,
    logical::{field::FieldTrait, Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::{Storage, StorageEntry},
    utils::{
        self, deserialize_duration,
        policy::sanitize_policies,
        serialize_duration,
        sock_addr::SockAddrMarshaler,
        token_util::{token_fields, TokenParams},
    },
};

#[derive(Debug, Clone, Default, Serialize, Deserialize, Deref, DerefMut)]
pub struct RoleEntry {
    // Name of the role. This field is not persisted on disk. After the role is read out of disk,
    // the sanitized version of name is set in this field for subsequent use of role name
    // elsewhere.
    pub name: String,

    // UUID that uniquely represents this role. This serves as a credential to perform login using
    // this role.
    pub role_id: String,

    // UUID that serves as the HMAC key for the hashing the 'secret_id's of the role
    pub hmac_key: String,

    // Policies that are to be required by the token to access this role. Deprecated.
    pub policies: Vec<String>,

    // lower_case_role_name enforces the lower casing of role names for all the
    #[default(true)]
    pub lower_case_role_name: bool,

    // A constraint, if set, requires 'secret_id' credential to be presented during login
    pub bind_secret_id: bool,

    // Number of times the secret_id generated against this role can be used to perform login
    // operation
    pub secret_id_num_uses: i64,

    // SecretIDPrefix is the storage prefix for persisting secret IDs. This differs based on
    // whether the secret IDs are cluster local or not.
    pub secret_id_prefix: String,

    // Deprecated: A constraint, if set, specifies the CIDR blocks from which logins should be
    // allowed, please use secret_id_bound_cidrs instead.
    #[serde(rename = "bound_cidr_list", default)]
    pub bound_cidr_list_old: String,

    // Deprecated: A constraint, if set, specifies the CIDR blocks from which logins should be
    // allowed, please use secret_id_bound_cidrs instead.
    #[serde(rename = "bound_cidr_list_list", skip_serializing_if = "Vec::is_empty", default)]
    pub bound_cidr_list: Vec<String>,

    // A constraint, if set, specifies the CIDR blocks from which logins should be allowed
    pub secret_id_bound_cidrs: Vec<String>,

    // A constraint requiring the login to present a FerroGate machine token
    // bound to one of these machines. Machine binding is mandatory: a role with
    // no bound machines cannot authenticate. Each binding may scope the machine
    // to a set of environments (wildcards allowed; empty = all environments).
    #[serde(default)]
    pub bound_machines: Vec<MachineBinding>,

    // Duration (less than the backend mount's max TTL) after which a secret_id generated against
    // the role will expire
    #[serde(serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    pub secret_id_ttl: Duration,
    #[serde(serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    // Period, if set, indicates that the token generated using this role should never expire. The
    // token should be renewed within the duration specified by this value. The renewal duration
    // will be fixed if the value is not modified on the role. If the `Period` in the role is
    // modified, a token will pick up the new value during its next renewal. Deprecated.
    pub period: Duration,
    #[serde(flatten)]
    #[deref]
    #[deref_mut]
    pub token_params: TokenParams,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoleIdEntry {
    pub name: String,
}

// MachineBinding ties an AppRole to a FerroGate-attested machine. The login
// must present a live FerroGate machine token whose SPIFFE ID resolves to one
// of the role's bound machines. Each binding may restrict the machine to a set
// of environments.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MachineBinding {
    // Stable, path-safe handle for the SPIFFE ID (blake3 hex). Matches the
    // FerroGate admin routes and GUI machine `id`.
    pub machine_id: String,

    // The machine's SPIFFE ID, stored for display/audit.
    #[serde(default)]
    pub spiffe_id: String,

    // Environment glob patterns this machine may access for this role (empty =
    // all environments). Wildcards are allowed (e.g. "prod-*").
    #[serde(default)]
    pub environments: Vec<String>,
}

impl RoleEntry {
    pub fn validate_role_constraints(&self) -> Result<(), RvError> {
        if self.bind_secret_id
            || !self.bound_cidr_list.is_empty()
            || !self.secret_id_bound_cidrs.is_empty()
            || !self.token_bound_cidrs.is_empty()
            || !self.bound_machines.is_empty()
        {
            return Ok(());
        }

        Err(RvError::ErrResponse("at least one constraint should be enabled on the role".to_string()))
    }
}

impl AppRoleBackend {
    // role_path creates all the paths that are used to register and manage a role.
    //
    // role/ - For listing all the registered roles
    pub fn role_path(&self) -> Path {
        let approle_backend_ref = self.inner.clone();

        let mut path = new_path!({
            pattern: r"role/?",
            operations: [
                {op: Operation::List, handler: approle_backend_ref.list_role}
            ],
            help: "Lists all the roles registered with the backend."
        });

        path.fields.extend(token_fields());

        path
    }

    // role/<role_name> - For registering a role
    pub fn role_name_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();
        let approle_backend_ref3 = self.inner.clone();

        let mut path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "bind_secret_id": {
                    field_type: FieldType::Bool,
                    default: true,
                    description: "Impose secret_id to be presented when logging in using this role. Defaults to 'true'."
                },
                "bound_cidr_list": {
                    field_type: FieldType::CommaStringSlice,
                    required: false,
                    description: r#"Use "secret_id_bound_cidrs" instead."#
                },
                "secret_id_bound_cidrs": {
                    field_type: FieldType::CommaStringSlice,
                    required: false,
                    description: r#"Comma separated string or list of CIDR blocks.
                    If set, specifies the blocks of IP addresses which can perform the login operation."#
                },
                "secret_id_num_uses": {
                    field_type: FieldType::Int,
                    required: false,
                    description: r#"Number of times a SecretID can access the role, after which the SecretID
        will expire. Defaults to 0 meaning that the the secret_id is of unlimited use."#
                },
                "secret_id_ttl": {
                    field_type: FieldType::DurationSecond,
                    required: false,
                    description: r#"Duration in seconds after which the issued SecretID should expire. Defaults to 0, meaning no expiration."#
                },
                "policies": {
                    field_type: FieldType::CommaStringSlice,
                    required: false,
                    description: "Use token_policies instead. If this and token_policies are both speicified, only token_policies will be used."
                },
                "period": {
                    field_type: FieldType::DurationSecond,
                    default: 0,
                    description: "Use token_period instead. If this and token_period are both speicified, only token_period will be used."
                },
                "role_id": {
                    field_type: FieldType::Str,
                    description: "Identifier of the role. Defaults to a UUID."
                },
                "local_secret_ids": {
                    field_type: FieldType::Bool,
                    default: false,
                    description: "If set, the secret IDs generated using this role will be cluster local. This can only be set during role creation and once set, it can't be reset later."
                }
            },
            operations: [
                {op: Operation::Read, handler: approle_backend_ref1.read_role},
                {op: Operation::Write, handler: approle_backend_ref2.write_role},
                {op: Operation::Delete, handler: approle_backend_ref3.delete_role}
            ],
            help: r#"
A role can represent a service, a machine or anything that can be IDed.
The set of policies on the role defines access to the role, meaning, any
Vault token with a policy set that is a superset of the policies on the
role registered here will have access to the role. If a SecretID is desired
to be generated against only this specific role, it can be done via
'role/<role_name>/secret-id' and 'role/<role_name>/custom-secret-id' endpoints.
The properties of the SecretID created against the role and the properties
of the token issued with the SecretID generated against the role, can be
configured using the fields of this endpoint.
                "#
        });

        path.fields.extend(token_fields());

        path
    }

    // role/<role_name>/policies - For updating the param
    pub fn role_policies_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();
        let approle_backend_ref3 = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/policies$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "policies": {
                    field_type: FieldType::CommaStringSlice,
                    required: false,
                    description: "Use token_policies instead. If this and token_policies are both speicified, only token_policies will be used."
                },
                "token_policies": {
                    field_type: FieldType::CommaStringSlice,
                    required: true,
                    description: "Comma-separated list of policies"
                }
            },
            operations: [
                {op: Operation::Read, handler: approle_backend_ref1.read_role_policies},
                {op: Operation::Write, handler: approle_backend_ref2.write_role_policies},
                {op: Operation::Delete, handler: approle_backend_ref3.delete_role_policies}
            ],
            help: r#"
A comma-delimited set of Vault policies that defines access to the role.
All the Vault tokens with policies that encompass the policy set
defined on the role, can access the role.
                "#
        });

        path
    }

    // role/<role_name>/local-secret-ids - For reading the param
    pub fn role_local_secret_ids_path(&self) -> Path {
        let approle_backend_ref = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/local-secret-ids$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                }
            },
            operations: [
                {op: Operation::Read, handler: approle_backend_ref.read_role_local_secret_ids}
            ],
            help: r#"If set, the secret IDs generated using this role will be cluster local.
This can only be set during role creation and once set, it can't be reset later.
                "#
        });

        path
    }

    // role/<role_name>/bound-cidr-list - For updating the param
    pub fn role_bound_cidr_list_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();
        let approle_backend_ref3 = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/bound-cidr-list$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "bound_cidr_list": {
                    field_type: FieldType::CommaStringSlice,
                    description: r#"Comma separated string or list of CIDR blocks.
        If set, specifies the blocks of IP addresses which can perform the login operation."#
                }
            },
            operations: [
                {op: Operation::Read, handler: approle_backend_ref1.read_role_bound_cidr_list},
                {op: Operation::Write, handler: approle_backend_ref2.write_role_bound_cidr_list},
                {op: Operation::Delete, handler: approle_backend_ref3.delete_role_bound_cidr_list}
            ],
            help: r#"
During login, the IP address of the client will be checked to see if it
belongs to the CIDR blocks specified. If CIDR blocks were set and if the
IP is not encompassed by it, login fails
                "#
        });

        path
    }

    // role/<role_name>/secret-id-bound-cidrs - For updating the param
    pub fn role_secret_id_bound_cidrs_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();
        let approle_backend_ref3 = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/secret-id-bound-cidrs$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "secret_id_bound_cidrs": {
                    field_type: FieldType::CommaStringSlice,
                    description: r#"Comma separated string or list of CIDR blocks.
        If set, specifies the blocks of IP addresses which can perform the login operation."#
                }
            },
            operations: [
                {op: Operation::Read, handler: approle_backend_ref1.read_role_secret_id_bound_cidrs},
                {op: Operation::Write, handler: approle_backend_ref2.write_role_secret_id_bound_cidrs},
                {op: Operation::Delete, handler: approle_backend_ref3.delete_role_secret_id_bound_cidrs}
            ],
            help: r#"
During login, the IP address of the client will be checked to see if it
belongs to the CIDR blocks specified. If CIDR blocks were set and if the
IP is not encompassed by it, login fails
                "#
        });

        path
    }

    // role/<role_name>/token-bound-cidrs - For updating the param
    pub fn role_token_bound_cidrs_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();
        let approle_backend_ref3 = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/token-bound-cidrs$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "token_bound_cidrs": {
                    field_type: FieldType::CommaStringSlice,
                    description: r#"Comma separated string or list of CIDR blocks. If set, specifies the blocks of IP addresses which can use the returned token. Should be a subset of the token CIDR blocks listed on the role, if any."#
                }
            },
            operations: [
                {op: Operation::Read, handler: approle_backend_ref1.read_role_token_bound_cidrs},
                {op: Operation::Write, handler: approle_backend_ref2.write_role_token_bound_cidrs},
                {op: Operation::Delete, handler: approle_backend_ref3.delete_role_token_bound_cidrs}
            ],
            help: r#"
During use of the returned token, the IP address of the client will be checked to see if it
belongs to the CIDR blocks specified. If CIDR blocks were set and if the
IP is not encompassed by it, token use fails
                "#
        });

        path
    }

    // role/<role_name>/bind-secret-id - For updating the param
    pub fn role_bind_secret_id_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();
        let approle_backend_ref3 = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/bind-secret-id$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "bind_secret_id": {
                    field_type: FieldType::Bool,
                    default: true,
                    description: "Impose secret_id to be presented when logging in using this role. Defaults to 'true'."
                }
            },
            operations: [
                {op: Operation::Read, handler: approle_backend_ref1.read_role_bind_secret_id},
                {op: Operation::Write, handler: approle_backend_ref2.write_role_bind_secret_id},
                {op: Operation::Delete, handler: approle_backend_ref3.delete_role_bind_secret_id}
            ],
            help: r#"
By setting this to 'true', during login the field 'secret_id' becomes a mandatory argument.
The value of 'secret_id' can be retrieved using 'role/<role_name>/secret-id' endpoint.
                "#
        });

        path
    }

    // role/<role_name>/secret-id-num-users - For updating the param
    pub fn role_secret_id_num_uses_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();
        let approle_backend_ref3 = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/secret-id-num-uses$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "secret_id_num_uses": {
                    field_type: FieldType::Int,
                    default: 0,
                    description: "Number of times a secret ID can access the role, after which the SecretID will expire. Defaults to 0 meaning that the secret ID is of unlimited use."
                }
            },
            operations: [
                {op: Operation::Read, handler: approle_backend_ref1.read_role_secret_id_num_uses},
                {op: Operation::Write, handler: approle_backend_ref2.write_role_secret_id_num_uses},
                {op: Operation::Delete, handler: approle_backend_ref3.delete_role_secret_id_num_uses}
            ],
            help: r#"
If a SecretID is generated/assigned against a role using the
'role/<role_name>/secret-id' or 'role/<role_name>/custom-secret-id' endpoint,
then the number of times this SecretID can be used is defined by this option.
However, this option may be overriden by the request's 'num_uses' field.
                "#
        });

        path
    }

    // role/<role_name>/secret-id-ttl - For updating the param
    pub fn role_secret_id_ttl_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();
        let approle_backend_ref3 = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/secret-id-ttl$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "secret_id_ttl": {
                    field_type: FieldType::Int,
                    default: 0,
                    description: "Duration in seconds after which the issued secret ID should expire. Defaults to 0, meaning no expiration."
                }
            },
            operations: [
                {op: Operation::Read, handler: approle_backend_ref1.read_role_secret_id_ttl},
                {op: Operation::Write, handler: approle_backend_ref2.write_role_secret_id_ttl},
                {op: Operation::Delete, handler: approle_backend_ref3.delete_role_secret_id_ttl}
            ],
            help: r#"
If a SecretID is generated/assigned against a role using the
'role/<role_name>/secret-id' or 'role/<role_name>/custom-secret-id' endpoint,
then the lifetime of this SecretID is defined by this option.
However, this option may be overridden by the request's 'ttl' field.
                "#
        });

        path
    }

    // role/<role_name>/period - For updating the param
    pub fn role_period_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();
        let approle_backend_ref3 = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/period$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "period": {
                    field_type: FieldType::DurationSecond,
                    default: 0,
                    description: "Use token_period instead. If this and token_period are both speicified, only token_period will be used."
                },
                "token_period": {
                    field_type: FieldType::DurationSecond,
                    description: "If set, tokens created via this role will have no max lifetime; instead, their renewal period will be fixed to this value."
                }
            },
            operations: [
                {op: Operation::Read, handler: approle_backend_ref1.read_role_period},
                {op: Operation::Write, handler: approle_backend_ref2.write_role_period},
                {op: Operation::Delete, handler: approle_backend_ref3.delete_role_period}
            ],
            help: r#"
If set,  indicates that the token generated using this role
should never expire. The token should be renewed within the
duration specified by this value. The renewal duration will
be fixed. If the Period in the role is modified, the token
will pick up the new value during its next renewal.
                "#
        });

        path
    }

    // role/<role_name>/token-num-uses - For updating the param
    pub fn role_token_num_uses_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();
        let approle_backend_ref3 = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/token-num-uses$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "token_num_uses": {
                    field_type: FieldType::Int,
                    default: 0,
                    description: "The maximum number of times a token may be used, a value of zero means unlimited"
                }
            },
            operations: [
                {op: Operation::Read, handler: approle_backend_ref1.read_role_token_num_uses},
                {op: Operation::Write, handler: approle_backend_ref2.write_role_token_num_uses},
                {op: Operation::Delete, handler: approle_backend_ref3.delete_role_token_num_uses}
            ],
            help: "By default, this will be set to zero, indicating that the issued"
        });

        path
    }

    // role/<role_name>/token-ttl - For updating the param
    pub fn role_token_ttl_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();
        let approle_backend_ref3 = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/token-ttl$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "token_ttl": {
                    field_type: FieldType::DurationSecond,
                    description: "The initial ttl of the token to generate"
                }
            },
            operations: [
                {op: Operation::Read, handler: approle_backend_ref1.read_role_token_ttl},
                {op: Operation::Write, handler: approle_backend_ref2.write_role_token_ttl},
                {op: Operation::Delete, handler: approle_backend_ref3.delete_role_token_ttl}
            ],
            help: r#"
If SecretIDs are generated against the role, using 'role/<role_name>/secret-id' or the
'role/<role_name>/custom-secret-id' endpoints, and if those SecretIDs are used
to perform the login operation, then the value of 'token-ttl' defines the
lifetime of the token issued, before which the token needs to be renewed.
                "#
        });

        path
    }

    // role/<role_name>/token-max-ttl - For updating the param
    pub fn role_token_max_ttl_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();
        let approle_backend_ref3 = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/token-max-ttl$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "token_max_ttl": {
                    field_type: FieldType::DurationSecond,
                    description: "The maximum lifetime of the generated token"
                }
            },
            operations: [
                {op: Operation::Read, handler: approle_backend_ref1.read_role_token_max_ttl},
                {op: Operation::Write, handler: approle_backend_ref2.write_role_token_max_ttl},
                {op: Operation::Delete, handler: approle_backend_ref3.delete_role_token_max_ttl}
            ],
            help: r#"
If SecretIDs are generated against the role using 'role/<role_name>/secret-id'
or the 'role/<role_name>/custom-secret-id' endpoints, and if those SecretIDs
are used to perform the login operation, then the value of 'token-max-ttl'
defines the maximum lifetime of the tokens issued, after which the tokens
cannot be renewed. A reauthentication is required after this duration.
This value will be capped by the backend mount's maximum TTL value.
                "#
        });

        path
    }

    // role/<role_name>/role-id - For updating the param
    pub fn role_role_id_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/role-id$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "role_id": {
                    field_type: FieldType::Str,
                    description: "Identifier of the role. Defaults to a UUID."
                }
            },
            operations: [
                {op: Operation::Read, handler: approle_backend_ref1.read_role_role_id},
                {op: Operation::Write, handler: approle_backend_ref2.write_role_role_id}
            ],
            help: r#"
If login is performed from an role, then its 'role_id' should be presented
as a credential during the login. This 'role_id' can be retrieved using
this endpoint."#
        });

        path
    }

    // role/<role_name>/secret-id - For issuing a secret_id against a role, also to list the secret_id_accessors
    pub fn role_secret_id_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/secret-id/?$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "metadata": {
                    field_type: FieldType::Str,
                    description: r#"Metadata to be tied to the SecretID. This should be a JSON
        formatted string containing the metadata in key value pairs."#
                },
                "cidr_list": {
                    field_type: FieldType::CommaStringSlice,
                    description: r#"Comma separated string or list of CIDR blocks enforcing secret IDs to be used from
specific set of IP addresses. If 'bound_cidr_list' is set on the role, then the
list of CIDR blocks listed here should be a subset of the CIDR blocks listed on
the role."#
                },
                "token_bound_cidrs": {
                    field_type: FieldType::CommaStringSlice,
                    description: r#"List of CIDR blocks. If set, specifies the blocks of IP addresses which can use the returned token. Should be a subset of the token CIDR blocks listed on the role, if any."#
                },
                "num_uses": {
                    field_type: FieldType::Int,
                    description: r#"Number of times this SecretID can be used, after which the SecretID expires.
        Overrides secret_id_num_uses role option when supplied. May not be higher than role's secret_id_num_uses."#
                },
                "ttl": {
                    field_type: FieldType::DurationSecond,
                    description: r#"Duration in seconds after which this SecretID expires.
        Overrides secret_id_ttl role option when supplied. May not be longer than role's secret_id_ttl."#
                },
                "environments": {
                    field_type: FieldType::CommaStringSlice,
                    description: r#"Comma separated string or list of environment glob patterns this
        SecretID may access (matched against the `env` request parameter on KV v2 reads/writes).
        Empty means the SecretID is not environment scoped and may access all environments.
        Wildcards are allowed (e.g. "prod-*")."#
                }
            },
            operations: [
                {op: Operation::List, handler: approle_backend_ref1.list_role_secret_id},
                {op: Operation::Write, handler: approle_backend_ref2.write_role_secret_id}
            ],
            help: r#"
The SecretID generated using this endpoint will be scoped to access
just this role and none else. The properties of this SecretID will be
based on the options set on the role. It will expire after a period
defined by the 'ttl' field or 'secret_id_ttl' option on the role,
and/or the backend mount's maximum TTL value."#
        });

        path
    }

    // role/<role_name>/secret-id/lookup - For reading the properties of a secret_id
    pub fn role_secret_id_lookup_path(&self) -> Path {
        let approle_backend_ref = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/secret-id/lookup/?$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "secret_id": {
                    field_type: FieldType::Str,
                    description: "SecretID attached to the role."
                }
            },
            operations: [
                {op: Operation::Write, handler: approle_backend_ref.write_role_secret_id_lookup}
            ],
            help: "This endpoint is used to read the properties of a secret_id associated to a role."
        });

        path
    }

    // role/<role_name>/secret-id/destroy - For deleting a secret_id
    pub fn role_secret_id_destroy_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/secret-id/destroy/?$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "secret_id": {
                    field_type: FieldType::Str,
                    description: "SecretID attached to the role."
                }
            },
            operations: [
                {op: Operation::Write, handler: approle_backend_ref1.write_role_secret_id_destory},
                {op: Operation::Delete, handler: approle_backend_ref2.delete_role_secret_id_destory}
            ],
            help: "This endpoint is used to delete the properties of a secret_id associated to a role."
        });

        path
    }

    // role/<role_name>/secret-id-accessor/lookup - For reading secret_id using accessor
    pub fn role_secret_id_accessor_lookup_path(&self) -> Path {
        let approle_backend_ref = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/secret-id-accessor/lookup/?$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "secret_id_accessor": {
                    field_type: FieldType::Str,
                    description: "Accessor of the SecretID"
                }
            },
            operations: [
                {op: Operation::Write, handler: approle_backend_ref.write_role_secret_id_accessor_lookup}
            ],
            help: r#"
This is particularly useful to lookup the non-expiring 'secret_id's.
The list operation on the 'role/<role_name>/secret-id' endpoint will return
the 'secret_id_accessor's. This endpoint can be used to read the properties
of the secret. If the 'secret_id_num_uses' field in the response is 0, it
represents a non-expiring 'secret_id'."#
        });

        path
    }

    // role/<role_name>/secret-id-accessor/destroy - For deleting secret_id using accessor
    pub fn role_secret_id_accessor_destroy_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/secret-id-accessor/destroy/?$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "secret_id_accessor": {
                    field_type: FieldType::Str,
                    description: "Accessor of the SecretID"
                }
            },
            operations: [
                {op: Operation::Write, handler: approle_backend_ref1.write_role_secret_id_accessor_destory},
                {op: Operation::Delete, handler: approle_backend_ref2.delete_role_secret_id_accessor_destory}
            ],
            help: r#"
This is particularly useful to clean-up the non-expiring 'secret_id's.
The list operation on the 'role/<role_name>/secret-id' endpoint will return
the 'secret_id_accessor's. This endpoint can be used to read the properties
of the secret. If the 'secret_id_num_uses' field in the response is 0, it
represents a non-expiring 'secret_id'."#
        });

        path
    }

    // role/<role_name>/custom-secret-id - For assigning a custom SecretID against a role
    pub fn role_custom_secret_id_path(&self) -> Path {
        let approle_backend_ref = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/custom-secret-id$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "secret_id": {
                    field_type: FieldType::Str,
                    description: "SecretID to be attached to the role."
                },
                "metadata": {
                    field_type: FieldType::Str,
                    description: r#"Metadata to be tied to the SecretID. This should be a JSON
        formatted string containing the metadata in key value pairs."#
                },
                "cidr_list": {
                    field_type: FieldType::CommaStringSlice,
                    description: r#"Comma separated string or list of CIDR blocks enforcing secret IDs to be used from
specific set of IP addresses. If 'bound_cidr_list' is set on the role, then the
list of CIDR blocks listed here should be a subset of the CIDR blocks listed on
the role."#
                },
                "token_bound_cidrs": {
                    field_type: FieldType::CommaStringSlice,
                    description: r#"List of CIDR blocks. If set, specifies the blocks of IP addresses which can use the returned token. Should be a subset of the token CIDR blocks listed on the role, if any."#
                },
                "num_uses": {
                    field_type: FieldType::Int,
                    description: r#"Number of times this SecretID can be used, after which the SecretID expires.
        Overrides secret_id_num_uses role option when supplied. May not be higher than role's secret_id_num_uses."#
                },
                "ttl": {
                    field_type: FieldType::DurationSecond,
                    description: r#"Duration in seconds after which this SecretID expires.
        Overrides secret_id_ttl role option when supplied. May not be longer than role's secret_id_ttl."#
                },
                "environments": {
                    field_type: FieldType::CommaStringSlice,
                    description: r#"Comma separated string or list of environment glob patterns this
        SecretID may access. Empty means all environments. Wildcards are allowed (e.g. "prod-*")."#
                }
            },
            operations: [
                {op: Operation::Write, handler: approle_backend_ref.write_role_custom_secret_id}
            ],
            help: r#"
This option is not recommended unless there is a specific need
to do so. This will assign a client supplied SecretID to be used to access
the role. This SecretID will behave similarly to the SecretIDs generated by
the backend. The properties of this SecretID will be based on the options
set on the role. It will expire after a period defined by the 'ttl' field
or 'secret_id_ttl' option on the role, and/or the backend mount's maximum TTL value."#
        });

        path
    }

    // role/<role_name>/machine - For listing and adding machine bindings
    pub fn role_machine_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/machine/?$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "machine_id": {
                    field_type: FieldType::Str,
                    description: "FerroGate machine id (blake3 hex). Either machine_id or spiffe_id is required."
                },
                "spiffe_id": {
                    field_type: FieldType::Str,
                    description: "FerroGate machine SPIFFE ID. When given, machine_id is derived from it."
                },
                "environments": {
                    field_type: FieldType::CommaStringSlice,
                    description: r#"Comma separated string or list of environment glob patterns this machine
        may access for this role (empty = all environments). Wildcards are allowed (e.g. "prod-*")."#
                }
            },
            operations: [
                {op: Operation::List, handler: approle_backend_ref1.list_role_machines},
                {op: Operation::Write, handler: approle_backend_ref2.write_role_machine}
            ],
            help: r#"
AppRole logins are required to present a FerroGate machine token bound to one of
the machines listed here. Several machines may be bound to a role, and each
binding may restrict the machine to a set of environments."#
        });

        path
    }

    // role/<role_name>/machine/<machine_id> - For reading and deleting a machine binding
    pub fn role_machine_id_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();

        let path = new_path!({
            pattern: r"role/(?P<role_name>\w[\w-]+\w)/machine/(?P<machine_id>\w+)$",
            fields: {
                "role_name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Name of the role."
                },
                "machine_id": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "FerroGate machine id (blake3 hex)."
                }
            },
            operations: [
                {op: Operation::Read, handler: approle_backend_ref1.read_role_machine},
                {op: Operation::Delete, handler: approle_backend_ref2.delete_role_machine}
            ],
            help: "Read or remove a single machine binding on the role."
        });

        path
    }

    pub fn role_paths(&self) -> Vec<Path> {
        let paths: Vec<Path> = vec![
            self.role_path(),
            self.role_name_path(),
            self.role_policies_path(),
            self.role_local_secret_ids_path(),
            self.role_bound_cidr_list_path(),
            self.role_secret_id_bound_cidrs_path(),
            self.role_token_bound_cidrs_path(),
            self.role_bind_secret_id_path(),
            self.role_secret_id_num_uses_path(),
            self.role_secret_id_ttl_path(),
            self.role_period_path(),
            self.role_token_num_uses_path(),
            self.role_token_ttl_path(),
            self.role_token_max_ttl_path(),
            self.role_role_id_path(),
            self.role_secret_id_path(),
            self.role_secret_id_lookup_path(),
            self.role_secret_id_destroy_path(),
            self.role_secret_id_accessor_lookup_path(),
            self.role_secret_id_accessor_destroy_path(),
            self.role_custom_secret_id_path(),
            self.role_machine_path(),
            self.role_machine_id_path(),
        ];
        paths
    }
}

#[allow(clippy::assigning_clones)]
#[maybe_async::maybe_async]
impl AppRoleBackendInner {
    pub async fn get_role_id(&self, req: &mut Request, role_id: &str) -> Result<Option<RoleIdEntry>, RvError> {
        if role_id.is_empty() {
            return Err(RvError::ErrResponse("missing role_id".to_string()));
        }

        let salt = self.salt.load();
        if salt.is_none() {
            return Err(RvError::ErrResponse("salt not found".to_string()));
        }

        let salt_id = salt.as_ref().unwrap().salt_id(role_id)?;
        let storage_entry = req.storage_get(format!("role_id/{salt_id}").as_str()).await?;
        if storage_entry.is_none() {
            return Ok(None);
        }

        let entry = storage_entry.unwrap();
        let role_id_entry: RoleIdEntry = serde_json::from_slice(entry.value.as_slice())?;

        Ok(Some(role_id_entry))
    }

    pub async fn set_role_id(
        &self,
        req: &mut Request,
        role_id: &str,
        role_id_entry: &RoleIdEntry,
    ) -> Result<(), RvError> {
        let Some(salt) = self.salt.load_full() else {
            return Err(RvError::ErrResponse("salt not found".to_string()));
        };

        let salt_id = salt.salt_id(role_id)?;

        let entry = StorageEntry::new(format!("role_id/{salt_id}").as_str(), role_id_entry)?;

        req.storage_put(&entry).await
    }

    pub async fn delete_role_id(&self, req: &mut Request, role_id: &str) -> Result<(), RvError> {
        if role_id.is_empty() {
            return Err(RvError::ErrResponse("missing role_id".to_string()));
        }

        let Some(salt) = self.salt.load_full() else {
            return Err(RvError::ErrResponse("salt not found".to_string()));
        };

        let salt_id = salt.salt_id(role_id)?;

        req.storage_delete(format!("role_id/{salt_id}").as_str()).await?;

        Ok(())
    }

    pub async fn get_role(&self, req: &mut Request, name: &str) -> Result<Option<RoleEntry>, RvError> {
        let key = format!("role/{}", name.to_lowercase());
        let storage_entry = req.storage_get(&key).await?;
        if storage_entry.is_none() {
            return Ok(None);
        }

        let entry = storage_entry.unwrap();
        let mut role_entry: RoleEntry = serde_json::from_slice(entry.value.as_slice())?;

        role_entry.name = name.to_string();
        if role_entry.lower_case_role_name {
            role_entry.name = name.to_lowercase();
        }

        if role_entry.secret_id_prefix.is_empty() {
            role_entry.secret_id_prefix = SECRET_ID_PREFIX.to_string();
        }

        if !role_entry.bound_cidr_list_old.is_empty() {
            role_entry.secret_id_bound_cidrs =
                role_entry.bound_cidr_list_old.split(',').map(|s| s.to_string()).collect();
            role_entry.bound_cidr_list_old.clear();
        }

        if !role_entry.bound_cidr_list.is_empty() {
            role_entry.secret_id_bound_cidrs.clone_from(&role_entry.bound_cidr_list);
            role_entry.bound_cidr_list.clear();
        }

        if role_entry.token_period.as_secs() == 0 && role_entry.period.as_secs() > 0 {
            role_entry.token_period = role_entry.period;
        }

        if role_entry.token_policies.is_empty() && !role_entry.policies.is_empty() {
            role_entry.token_policies = role_entry.policies.clone();
        }

        Ok(Some(role_entry))
    }

    pub async fn set_role(
        &self,
        req: &mut Request,
        name: &str,
        role_entry: &RoleEntry,
        previous_role_id: &str,
    ) -> Result<(), RvError> {
        if name.is_empty() {
            return Err(RvError::ErrResponse("missing role name".to_string()));
        }

        role_entry.validate_role_constraints()?;

        if let Some(role_id_entry) = self.get_role_id(req, &role_entry.role_id).await? {
            if role_id_entry.name.as_str() != name {
                return Err(RvError::ErrResponse("role_id already in use".to_string()));
            }
        }

        let mut create_role_id = true;

        if !previous_role_id.is_empty() {
            if previous_role_id != role_entry.role_id.as_str() {
                self.delete_role_id(req, previous_role_id).await?;
            } else {
                create_role_id = false;
            }
        }

        let entry = StorageEntry::new(format!("role/{}", name.to_lowercase()).as_str(), role_entry)?;

        req.storage_put(&entry).await?;

        if create_role_id {
            return self.set_role_id(req, &role_entry.role_id, &RoleIdEntry { name: name.to_string() }).await;
        }

        Ok(())
    }

    pub async fn list_role(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let roles = req.storage_list("role/").await?;
        Ok(Some(Response::list_response(&roles)))
    }

    pub async fn write_role(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let role_name_value = req.get_data("role_name")?;
        let role_name = role_name_value.as_str().ok_or(RvError::ErrRequestFieldInvalid)?;

        if role_name.len() > HMAC_INPUT_LEN_MAX {
            return Err(RvError::ErrResponse(
                format!("role_name is longer than maximum of {HMAC_INPUT_LEN_MAX} bytes").to_string(),
            ));
        }

        let mut role_entry = RoleEntry::default();
        let mut create = false;

        let lock_entry = self.role_locks.get_lock(role_name);
        let _locked = lock_entry.lock.write().await;

        let entry = self.get_role(req, role_name).await?;
        if entry.is_some() {
            role_entry = entry.unwrap();
        } else {
            role_entry.name = role_name.to_lowercase();
            role_entry.lower_case_role_name = true;
            role_entry.hmac_key = utils::generate_uuid();
            create = true;
        }

        let old_token_policies = role_entry.token_policies.clone();
        let old_token_period = role_entry.token_period;

        role_entry.parse_token_fields(req)?;

        if old_token_policies != role_entry.token_policies {
            role_entry.policies = role_entry.token_policies.clone();
        } else if let Ok(policies_value) = req.get_data("policies") {
            let policies = policies_value.as_comma_string_slice().ok_or(RvError::ErrRequestFieldInvalid)?;
            role_entry.policies.clone_from(&policies);
            role_entry.token_policies = policies;
        }

        if old_token_period != role_entry.token_period {
            role_entry.period = role_entry.token_period;
        } else if let Ok(period_value) = req.get_data("period") {
            let period = period_value.as_duration().ok_or(RvError::ErrRequestFieldInvalid)?;
            role_entry.period = period;
            role_entry.token_period = period;
        }

        if let Ok(local_secret_ids_value) = req.get_data("local_secret_ids") {
            let local_secret_ids = local_secret_ids_value.as_bool().ok_or(RvError::ErrRequestFieldInvalid)?;
            if local_secret_ids {
                if !create {
                    return Err(RvError::ErrResponse(
                        "local_secret_ids can only be modified during role creation".to_string(),
                    ));
                }
                role_entry.secret_id_prefix = SECRET_ID_LOCAL_PREFIX.to_string();
            }
        }

        let previous_role_id = role_entry.role_id.clone();

        if let Ok(role_id_value) = req.get_data("role_id") {
            role_entry.role_id = role_id_value.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        } else if create {
            role_entry.role_id = utils::generate_uuid();
        }

        if role_entry.role_id.is_empty() {
            return Err(RvError::ErrResponse("invalid role_id supplied, or failed to generate a role_id".to_string()));
        }

        if let Ok(bind_secret_id_value) = req.get_data("bind_secret_id") {
            role_entry.bind_secret_id = bind_secret_id_value.as_bool().ok_or(RvError::ErrRequestFieldInvalid)?;
        } else if create {
            role_entry.bind_secret_id =
                req.get_data_or_default("bind_secret_id")?.as_bool().ok_or(RvError::ErrRequestFieldInvalid)?;
        }

        if let Ok(bound_cidr_list_value) = req.get_data_or_next(&["secret_id_bound_cidrs", "bound_cidr_list"]) {
            role_entry.secret_id_bound_cidrs =
                bound_cidr_list_value.as_comma_string_slice().ok_or(RvError::ErrRequestFieldInvalid)?;
        }

        if !role_entry.secret_id_bound_cidrs.is_empty() {
            let cidrs: Vec<&str> = role_entry.secret_id_bound_cidrs.iter().map(AsRef::as_ref).collect();
            if !utils::cidr::validate_cidrs(&cidrs)? {
                return Err(RvError::ErrResponse("invalid CIDR blocks".to_string()));
            }
        }

        if let Ok(secret_id_num_uses_value) = req.get_data("secret_id_num_uses") {
            role_entry.secret_id_num_uses = secret_id_num_uses_value.as_int().ok_or(RvError::ErrRequestFieldInvalid)?;
        } else if create {
            role_entry.secret_id_num_uses =
                req.get_data_or_default("secret_id_num_uses")?.as_int().ok_or(RvError::ErrRequestFieldInvalid)?;
        }

        if role_entry.secret_id_num_uses < 0 {
            return Err(RvError::ErrResponse("secret_id_num_uses cannot be negative".to_string()));
        }

        if let Ok(secret_id_ttl_value) = req.get_data("secret_id_ttl") {
            role_entry.secret_id_ttl = secret_id_ttl_value.as_duration().ok_or(RvError::ErrRequestFieldInvalid)?;
        } else if create {
            role_entry.secret_id_ttl =
                req.get_data_or_default("secret_id_ttl")?.as_duration().ok_or(RvError::ErrRequestFieldInvalid)?;
        }

        self.set_role(req, &role_entry.name, &role_entry, &previous_role_id).await?;

        // Pre-provision the entity_id alias so this role shows up in
        // the GUI's user-picker (`/v2/identity/entity/aliases`) without
        // the role having to log in first. Same rationale as the
        // userpass user-create hook.
        if create {
            let _ = super::path_login::resolve_approle_entity_id(&self.core, &role_entry.name, "").await;
        }

        // Audit: lifecycle event for the role.
        record_approle_audit(
            &self.core,
            req,
            if create { "create" } else { "update" },
            &role_entry.name,
            &format!("policies={}", role_entry.policies.join(",")),
        )
        .await;

        Ok(None)
    }

    pub async fn read_role(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data_as_str("role_name")?;

        let lock_entry = self.role_locks.get_lock(&role_name);
        let locked = lock_entry.lock.read().await;

        if let Some(entry) = self.get_role(req, &role_name).await? {
            let mut data = serde_json::json!({
                "bind_secret_id": entry.bind_secret_id,
                "secret_id_bound_cidrs": entry.secret_id_bound_cidrs,
                "secret_id_num_uses": entry.secret_id_num_uses,
                "secret_id_ttl": entry.secret_id_ttl.as_secs(),
                "local_secret_ids": false,
            })
            .as_object()
            .unwrap()
            .clone();

            if entry.secret_id_prefix.as_str() == SECRET_ID_LOCAL_PREFIX {
                data["local_secret_ids"] = Value::from(true);
            }

            if !entry.bound_machines.is_empty() {
                data.insert("bound_machines".to_string(), serde_json::to_value(&entry.bound_machines)?);
            }

            if entry.period.as_secs() != 0 {
                data.insert("period".to_string(), Value::from(entry.period.as_secs()));
            }

            if !entry.policies.is_empty() {
                data.insert("policies".to_string(), Value::from(entry.policies.clone()));
            }

            entry.populate_token_data(&mut data);

            if entry.validate_role_constraints().is_err() {
                log::warn!(
                    "Role does not have any constraints set on it. Updates to this role will require a constraint to \
                     be set"
                );
            }

            let mut resp = Response::data_response(Some(data));

            // For sanity, verify that the index still exists. If the index is missing,
            // add one and return a warning so it can be reported.
            if self.get_role_id(req, &entry.role_id).await?.is_none() {
                // Switch to a write lock
                mem::drop(locked);
                let _locked = lock_entry.lock.write().await;

                // Check again if the index is missing
                if self.get_role_id(req, &entry.role_id).await?.is_none() {
                    // Create a new inde
                    self.set_role_id(req, &entry.role_id, &RoleIdEntry { name: entry.name.clone() }).await?;
                    resp.add_warning("Role identifier was missing an index back to role name");
                }
            }

            return Ok(Some(resp));
        }

        Ok(None)
    }

    pub async fn delete_role(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data_as_str("role_name")?;

        let lock_entry = self.role_locks.get_lock(&role_name);
        let _locked = lock_entry.lock.write().await;

        if let Some(entry) = self.get_role(req, &role_name).await? {
            let storage = req.storage.as_ref().unwrap();

            self.flush_role_secrets(Arc::as_ref(storage), &entry.name, &entry.hmac_key, &entry.secret_id_prefix)
                .await?;

            self.delete_role_id(req, &entry.role_id).await?;

            req.storage_delete(format!("role/{}", role_name.to_lowercase()).as_str()).await?;

            // Drop the entity alias so the role disappears from the
            // GUI user-picker immediately. Mirrors the delete-user
            // hook in userpass. Entity record itself stays so audit
            // history survives; only the (mount, name) lookup index
            // is removed.
            if let Some(identity) = self.core.identity() {
                let _ = identity.forget_alias("approle/", &entry.name).await;
            }

            record_approle_audit(&self.core, req, "delete", &entry.name, "").await;
        }

        Ok(None)
    }

    pub async fn read_config(&self, _backend: &dyn Backend, _req: &mut Request) -> Result<Option<Response>, RvError> {
        let require_machine =
            self.core.approle_require_machine().load(std::sync::atomic::Ordering::Relaxed);
        let data = json!({ "require_machine": require_machine });
        Ok(Some(Response::data_response(data.as_object().cloned())))
    }

    pub async fn write_config(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        if let Ok(v) = req.get_data("require_machine") {
            let required = v.as_bool().ok_or(RvError::ErrRequestFieldInvalid)?;
            self.core.set_approle_require_machine(required).await?;
        }
        Ok(None)
    }

    // Best-effort cross-mount read of a FerroGate machine record. Returns
    // `Ok(None)` when the ferrogate mount is not present at the expected path
    // (so callers can fall back to token-only trust) or the machine is unknown.
    pub async fn lookup_ferrogate_machine(&self, id: &str) -> Result<Option<MachineEntry>, RvError> {
        let Some(view) = self.core.router().matching_view("auth/ferrogate/")? else {
            return Ok(None);
        };
        match view.get(&format!("machine/{id}")).await? {
            Some(entry) => Ok(Some(serde_json::from_slice(entry.value.as_slice())?)),
            None => Ok(None),
        }
    }

    pub async fn list_role_machines(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data_as_str("role_name")?;

        let lock_entry = self.role_locks.get_lock(&role_name);
        let _locked = lock_entry.lock.read().await;

        let Some(role) = self.get_role(req, &role_name).await? else {
            return Err(RvError::ErrResponse(format!("role {role_name} does not exist")));
        };

        let data = json!({
            "machines": serde_json::to_value(&role.bound_machines)?,
            "keys": role.bound_machines.iter().map(|m| m.machine_id.clone()).collect::<Vec<String>>(),
        });

        Ok(Some(Response::data_response(data.as_object().cloned())))
    }

    pub async fn write_role_machine(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data_as_str("role_name")?;

        // Resolve the machine id from either an explicit machine_id or a spiffe_id.
        let spiffe_id = req.get_data("spiffe_id").ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
        let mut machine_id =
            req.get_data("machine_id").ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
        if machine_id.is_empty() && !spiffe_id.is_empty() {
            machine_id = ferrogate_machine_id(&spiffe_id);
        }
        if machine_id.is_empty() {
            return Err(RvError::ErrResponse("either machine_id or spiffe_id is required".to_string()));
        }

        let environments = req
            .get_data("environments")
            .ok()
            .and_then(|v| v.as_comma_string_slice())
            .unwrap_or_default();

        // Resolve spiffe_id for display: prefer the supplied value, else read it
        // back from the FerroGate machine record when available.
        let mut binding = MachineBinding { machine_id: machine_id.clone(), spiffe_id, environments };
        if binding.spiffe_id.is_empty() {
            if let Some(m) = self.lookup_ferrogate_machine(&machine_id).await? {
                binding.spiffe_id = m.spiffe_id;
            }
        }

        let lock_entry = self.role_locks.get_lock(&role_name);
        let _locked = lock_entry.lock.write().await;

        let Some(mut role) = self.get_role(req, &role_name).await? else {
            return Err(RvError::ErrResponse(format!("role {role_name} does not exist")));
        };

        // Replace an existing binding for the same machine, else append.
        if let Some(existing) = role.bound_machines.iter_mut().find(|m| m.machine_id == machine_id) {
            existing.spiffe_id = binding.spiffe_id.clone();
            existing.environments = binding.environments.clone();
        } else {
            role.bound_machines.push(binding);
        }

        let previous_role_id = role.role_id.clone();
        self.set_role(req, &role.name, &role, &previous_role_id).await?;

        record_approle_audit(&self.core, req, "bind-machine", &role.name, &format!("machine_id={machine_id}")).await;

        Ok(None)
    }

    pub async fn read_role_machine(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data_as_str("role_name")?;
        let machine_id = req.get_data_as_str("machine_id")?;

        let lock_entry = self.role_locks.get_lock(&role_name);
        let _locked = lock_entry.lock.read().await;

        let Some(role) = self.get_role(req, &role_name).await? else {
            return Err(RvError::ErrResponse(format!("role {role_name} does not exist")));
        };

        match role.bound_machines.iter().find(|m| m.machine_id == machine_id) {
            Some(binding) => {
                let data = serde_json::to_value(binding)?;
                Ok(Some(Response::data_response(data.as_object().cloned())))
            }
            None => Ok(None),
        }
    }

    pub async fn delete_role_machine(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data_as_str("role_name")?;
        let machine_id = req.get_data_as_str("machine_id")?;

        let lock_entry = self.role_locks.get_lock(&role_name);
        let _locked = lock_entry.lock.write().await;

        let Some(mut role) = self.get_role(req, &role_name).await? else {
            return Err(RvError::ErrResponse(format!("role {role_name} does not exist")));
        };

        let before = role.bound_machines.len();
        role.bound_machines.retain(|m| m.machine_id != machine_id);
        if role.bound_machines.len() != before {
            let previous_role_id = role.role_id.clone();
            self.set_role(req, &role.name, &role, &previous_role_id).await?;
            record_approle_audit(&self.core, req, "unbind-machine", &role.name, &format!("machine_id={machine_id}"))
                .await;
        }

        Ok(None)
    }

    pub async fn read_role_policies(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data_as_str("role_name")?;

        let lock_entry = self.role_locks.get_lock(&role_name);
        let _locked = lock_entry.lock.read().await;

        if let Some(role) = self.get_role(req, &role_name).await? {
            let mut data = serde_json::json!({
                "token_policies": role.token_policies,
            })
            .as_object()
            .unwrap()
            .clone();

            if !role.policies.is_empty() {
                data.insert("policies".to_string(), Value::from(role.policies));
            }

            Ok(Some(Response::data_response(Some(data))))
        } else {
            Ok(None)
        }
    }

    pub async fn write_role_policies(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data_as_str("role_name")?;

        let token_policies_value = req.get_data_or_next(&["token_policies", "policies"])?;
        let mut token_policies = token_policies_value.as_comma_string_slice().ok_or(RvError::ErrRequestFieldInvalid)?;

        let lock_entry = self.role_locks.get_lock(&role_name);
        let _locked = lock_entry.lock.write().await;

        if let Some(mut role) = self.get_role(req, &role_name).await? {
            sanitize_policies(&mut token_policies, false);
            role.policies.clone_from(&token_policies);
            role.token_policies = token_policies;
            self.set_role(req, &role_name, &role, "").await?;
        } else {
            return Err(RvError::ErrLogicalPathUnsupported);
        }

        Ok(None)
    }

    pub async fn delete_role_policies(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data_as_str("role_name")?;

        let lock_entry = self.role_locks.get_lock(&role_name);
        let _locked = lock_entry.lock.write().await;

        if let Some(mut role) = self.get_role(req, &role_name).await? {
            role.token_policies.clear();
            role.policies.clear();
            self.set_role(req, &role_name, &role, "").await?;
        } else {
            return Err(RvError::ErrLogicalPathUnsupported);
        }

        Ok(None)
    }

    pub async fn read_role_local_secret_ids(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.read_role_field(req, "local_secret_ids").await
    }

    pub async fn read_role_field(&self, req: &mut Request, field: &str) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data_as_str("role_name")?;

        let lock_entry = self.role_locks.get_lock(&role_name);
        let _locked = lock_entry.lock.read().await;

        if let Some(role) = self.get_role(req, &role_name).await? {
            let data = match field {
                "bound_cidr_list" => {
                    serde_json::json!({
                        "bound_cidr_list": role.bound_cidr_list,
                    })
                }
                "secret_id_bound_cidrs" => {
                    serde_json::json!({
                        "secret_id_bound_cidrs": role.secret_id_bound_cidrs,
                    })
                }
                "token_bound_cidrs" => {
                    serde_json::json!({
                        "token_bound_cidrs": role.token_bound_cidrs,
                    })
                }
                "bind_secret_id" => {
                    serde_json::json!({
                        "bind_secret_id": role.bind_secret_id,
                    })
                }
                "local_secret_ids" => {
                    serde_json::json!({
                        "local_secret_ids": role.secret_id_prefix.as_str() == SECRET_ID_LOCAL_PREFIX,
                    })
                }
                "secret_id_num_uses" => {
                    serde_json::json!({
                        "secret_id_num_uses": role.secret_id_num_uses,
                    })
                }
                "role_id" => {
                    serde_json::json!({
                        "role_id": role.role_id,
                    })
                }
                "secret_id_ttl" => {
                    serde_json::json!({
                        "secret_id_ttl": role.secret_id_ttl.as_secs(),
                    })
                }
                "token_period" | "period" => {
                    if role.period.as_secs() > 0 {
                        serde_json::json!({
                            "token_period": role.token_period.as_secs(),
                            "period": role.period.as_secs(),
                        })
                    } else {
                        serde_json::json!({
                            "token_period": role.token_period.as_secs(),
                        })
                    }
                }
                "token_num_uses" => {
                    serde_json::json!({
                        "token_num_uses": role.token_num_uses,
                    })
                }
                "token_ttl" => {
                    serde_json::json!({
                        "token_ttl": role.token_ttl.as_secs(),
                    })
                }
                "token_max_ttl" => {
                    serde_json::json!({
                        "token_max_ttl": role.token_max_ttl.as_secs(),
                    })
                }
                _ => {
                    return Err(RvError::ErrResponse("unrecognized field".to_string()));
                }
            };
            Ok(Some(Response::data_response(Some(data.as_object().unwrap().clone()))))
        } else {
            Ok(None)
        }
    }

    pub async fn update_role_field(&self, req: &mut Request, field: &str) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data_as_str("role_name")?;

        let field_value = match field {
            "token_period" | "period" => req.get_data_or_next(&["token_period", "period"])?,
            _ => req.get_data(field)?,
        };

        let mut cidr_list = Vec::new();

        match field {
            "bound_cidr_list" | "secret_id_bound_cidrs" | "token_bound_cidrs" => {
                cidr_list = field_value.as_comma_string_slice().ok_or(RvError::ErrRequestFieldInvalid)?;
                if cidr_list.is_empty() {
                    return Err(RvError::ErrResponse(format!("missing {field}").to_string()));
                }

                let cidrs: Vec<&str> = cidr_list.iter().map(AsRef::as_ref).collect();
                if !utils::cidr::validate_cidrs(&cidrs)? {
                    return Err(RvError::ErrResponse("failed to validate CIDR blocks".to_string()));
                }
            }
            _ => {}
        }

        let lock_entry = self.role_locks.get_lock(&role_name);
        let _locked = lock_entry.lock.write().await;

        let mut previous_role_id = "".to_string();

        if let Some(mut role) = self.get_role(req, &role_name).await? {
            match field {
                "bound_cidr_list" | "secret_id_bound_cidrs" => {
                    role.secret_id_bound_cidrs = cidr_list;
                }
                "token_bound_cidrs" => {
                    role.token_bound_cidrs = cidr_list
                        .iter()
                        .map(|s| SockAddrMarshaler::from_str(s))
                        .collect::<Result<Vec<SockAddrMarshaler>, _>>()?;
                }
                "bind_secret_id" => {
                    role.bind_secret_id = field_value.as_bool().ok_or(RvError::ErrLogicalOperationUnsupported)?;
                }
                "secret_id_num_uses" => {
                    role.secret_id_num_uses = field_value.as_int().ok_or(RvError::ErrLogicalOperationUnsupported)?;
                    if role.secret_id_num_uses < 0 {
                        return Err(RvError::ErrResponse("secret_id_num_uses cannot be negative".to_string()));
                    }
                }
                "role_id" => {
                    previous_role_id.clone_from(&role.role_id);
                    role.role_id = field_value.as_str().ok_or(RvError::ErrLogicalOperationUnsupported)?.to_string();
                    if role.role_id.as_str() == "" {
                        return Err(RvError::ErrResponse("missing role_id".to_string()));
                    }
                }
                "secret_id_ttl" => {
                    role.secret_id_ttl = field_value.as_duration().ok_or(RvError::ErrLogicalOperationUnsupported)?;
                }
                "token_period" | "period" => {
                    role.token_period = field_value.as_duration().ok_or(RvError::ErrLogicalOperationUnsupported)?;
                    role.period = role.token_period;
                }
                "token_num_uses" => {
                    role.token_num_uses = field_value.as_u64().ok_or(RvError::ErrLogicalOperationUnsupported)?;
                }
                "token_ttl" => {
                    role.token_ttl = field_value.as_duration().ok_or(RvError::ErrLogicalOperationUnsupported)?;
                    if role.token_max_ttl.as_secs() > 0 && role.token_ttl.as_secs() > role.token_max_ttl.as_secs() {
                        return Err(RvError::ErrResponse(
                            "token_ttl should not be greater than token_max_ttl".to_string(),
                        ));
                    }
                }
                "token_max_ttl" => {
                    role.token_max_ttl = field_value.as_duration().ok_or(RvError::ErrLogicalOperationUnsupported)?;
                    if role.token_max_ttl.as_secs() > 0 && role.token_ttl.as_secs() > role.token_max_ttl.as_secs() {
                        return Err(RvError::ErrResponse(
                            "token_max_ttl should not be greater than token_ttl".to_string(),
                        ));
                    }
                }
                _ => {
                    return Err(RvError::ErrResponse("unrecognized field".to_string()));
                }
            }

            self.set_role(req, &role_name, &role, &previous_role_id).await?;
        } else {
            return Err(RvError::ErrLogicalPathUnsupported);
        }

        Ok(None)
    }

    pub async fn delete_role_field(&self, req: &mut Request, field: &str) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data_as_str("role_name")?;

        let lock_entry = self.role_locks.get_lock(&role_name);
        let _locked = lock_entry.lock.write().await;

        if let Some(mut role) = self.get_role(req, &role_name).await? {
            match field {
                "bound_cidr_list" => {
                    role.bound_cidr_list.clear();
                }
                "secret_id_bound_cidrs" => {
                    role.secret_id_bound_cidrs.clear();
                }
                "token_bound_cidrs" => {
                    role.token_bound_cidrs.clear();
                }
                "bind_secret_id" => {
                    role.bind_secret_id = req
                        .get_field_default_or_zero("bind_secret_id")?
                        .as_bool()
                        .ok_or(RvError::ErrLogicalOperationUnsupported)?;
                }
                "secret_id_num_uses" => {
                    role.secret_id_num_uses = req
                        .get_field_default_or_zero("secret_id_num_uses")?
                        .as_int()
                        .ok_or(RvError::ErrLogicalOperationUnsupported)?;
                }
                "secret_id_ttl" => {
                    role.secret_id_ttl = req
                        .get_field_default_or_zero("secret_id_ttl")?
                        .as_duration()
                        .ok_or(RvError::ErrLogicalOperationUnsupported)?;
                }
                "token_period" | "period" => {
                    role.token_period = Duration::from_secs(0);
                    role.period = Duration::from_secs(0);
                }
                "token_num_uses" => {
                    role.token_num_uses = req
                        .get_field_default_or_zero("token_num_uses")?
                        .as_u64()
                        .ok_or(RvError::ErrLogicalOperationUnsupported)?;
                }
                "token_ttl" => {
                    role.token_ttl = req
                        .get_field_default_or_zero("token_ttl")?
                        .as_duration()
                        .ok_or(RvError::ErrLogicalOperationUnsupported)?;
                }
                "token_max_ttl" => {
                    role.token_max_ttl = req
                        .get_field_default_or_zero("token_max_ttl")?
                        .as_duration()
                        .ok_or(RvError::ErrLogicalOperationUnsupported)?;
                }
                _ => {
                    return Err(RvError::ErrResponse("unrecognized field".to_string()));
                }
            }

            self.set_role(req, &role_name, &role, "").await?;
        }

        Ok(None)
    }

    pub async fn read_role_bound_cidr_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.read_role_field(req, "bound_cidr_list").await
    }

    pub async fn write_role_bound_cidr_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.update_role_field(req, "bound_cidr_list").await
    }

    pub async fn delete_role_bound_cidr_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.delete_role_field(req, "bound_cidr_list").await
    }

    pub async fn read_role_secret_id_bound_cidrs(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.read_role_field(req, "secret_id_bound_cidrs").await
    }

    pub async fn write_role_secret_id_bound_cidrs(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.update_role_field(req, "secret_id_bound_cidrs").await
    }

    pub async fn delete_role_secret_id_bound_cidrs(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.delete_role_field(req, "secret_id_bound_cidrs").await
    }

    pub async fn read_role_token_bound_cidrs(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.read_role_field(req, "token_bound_cidrs").await
    }

    pub async fn write_role_token_bound_cidrs(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.update_role_field(req, "token_bound_cidrs").await
    }

    pub async fn delete_role_token_bound_cidrs(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.delete_role_field(req, "token_bound_cidrs").await
    }

    pub async fn read_role_bind_secret_id(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.read_role_field(req, "bind_secret_id").await
    }

    pub async fn write_role_bind_secret_id(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.update_role_field(req, "bind_secret_id").await
    }

    pub async fn delete_role_bind_secret_id(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.delete_role_field(req, "bind_secret_id").await
    }

    pub async fn read_role_secret_id_num_uses(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.read_role_field(req, "secret_id_num_uses").await
    }

    pub async fn write_role_secret_id_num_uses(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.update_role_field(req, "secret_id_num_uses").await
    }

    pub async fn delete_role_secret_id_num_uses(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.delete_role_field(req, "secret_id_num_uses").await
    }

    pub async fn read_role_secret_id_ttl(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.read_role_field(req, "secret_id_ttl").await
    }

    pub async fn write_role_secret_id_ttl(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.update_role_field(req, "secret_id_ttl").await
    }

    pub async fn delete_role_secret_id_ttl(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.delete_role_field(req, "secret_id_ttl").await
    }

    pub async fn read_role_period(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.read_role_field(req, "token_period").await
    }

    pub async fn write_role_period(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.update_role_field(req, "token_period").await
    }

    pub async fn delete_role_period(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.delete_role_field(req, "token_period").await
    }

    pub async fn read_role_token_num_uses(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.read_role_field(req, "token_num_uses").await
    }

    pub async fn write_role_token_num_uses(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.update_role_field(req, "token_num_uses").await
    }

    pub async fn delete_role_token_num_uses(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.delete_role_field(req, "token_num_uses").await
    }

    pub async fn read_role_token_ttl(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.read_role_field(req, "token_ttl").await
    }

    pub async fn write_role_token_ttl(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.update_role_field(req, "token_ttl").await
    }

    pub async fn delete_role_token_ttl(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.delete_role_field(req, "token_ttl").await
    }

    pub async fn read_role_token_max_ttl(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.read_role_field(req, "token_max_ttl").await
    }

    pub async fn write_role_token_max_ttl(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.update_role_field(req, "token_max_ttl").await
    }

    pub async fn delete_role_token_max_ttl(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.delete_role_field(req, "token_max_ttl").await
    }

    pub async fn read_role_role_id(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.read_role_field(req, "role_id").await
    }

    pub async fn write_role_role_id(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.update_role_field(req, "role_id").await
    }

    pub async fn list_role_secret_id(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data_as_str("role_name")?;

        let lock_entry = self.role_locks.get_lock(&role_name);
        let _locked = lock_entry.lock.read().await;

        if let Some(role) = self.get_role(req, &role_name).await? {
            let role_name_hmac = create_hmac(&role.hmac_key, &role.name)?;
            let key = format!("{}{}/", role.secret_id_prefix, role_name_hmac);
            let secret_id_hmacs = req.storage_list(&key).await?;

            let mut list_items: Vec<String> = Vec::with_capacity(secret_id_hmacs.len());
            for secret_id_hmac in secret_id_hmacs.iter() {
                let entry_index = format!("{}{}/{}", role.secret_id_prefix, role_name_hmac, secret_id_hmac);

                // secret_id locks are not indexed by secret_id itself.
                // This is because secret_id are not stored in plaintext
                // form anywhere in the backend, and hence accessing its
                // corresponding lock many times using secret_id is not
                // possible. Also, indexing it everywhere using secret_id_hmacs
                // makes listing operation easier.
                let lock_entry = self.secret_id_locks.get_lock(secret_id_hmac);
                let _locked = lock_entry.lock.read().await;
                let storage_entry = req.storage_get(&entry_index).await?;
                if storage_entry.is_none() {
                    return Err(RvError::ErrResponse(
                        "storage entry for SecretID is present but no content found at the index".to_string(),
                    ));
                }
                let entry = storage_entry.unwrap();
                let secret_id_entry: SecretIdStorageEntry = serde_json::from_slice(entry.value.as_slice())?;
                list_items.push(secret_id_entry.secret_id_accessor);
            }

            return Ok(Some(Response::list_response(&list_items)));
        }

        Err(RvError::ErrResponse(format!("role {role_name} does not exist")))
    }

    pub async fn update_role_secret_id_common(
        &self,
        req: &mut Request,
        secret_id: &str,
    ) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data_as_str("role_name")?;

        if secret_id.is_empty() {
            return Err(RvError::ErrResponse("missing secret_id".to_string()));
        }

        let lock_entry = self.role_locks.get_lock(&role_name);
        let _locked = lock_entry.lock.read().await;

        let role = self.get_role(req, &role_name).await?;
        if role.is_none() {
            return Err(RvError::ErrResponse(format!("role {role_name} does not exist")));
        }

        let role = role.unwrap();

        if !role.bind_secret_id {
            return Err(RvError::ErrResponse("bind_secret_id is not set on the role".to_string()));
        }

        let cidr_list_value = req.get_data_or_default("cidr_list")?;
        let cidr_list = cidr_list_value.as_comma_string_slice().ok_or(RvError::ErrRequestFieldInvalid)?;
        // Validate the list of CIDR blocks
        if !cidr_list.is_empty() {
            let cidrs: Vec<&str> = cidr_list.iter().map(AsRef::as_ref).collect();
            if !utils::cidr::validate_cidrs(&cidrs)? {
                return Err(RvError::ErrResponse("failed to validate CIDR blocks".to_string()));
            }
        }

        // Ensure that the CIDRs on the secret ID are a subset of that of role's
        verify_cidr_role_secret_id_subset(&cidr_list, &role.secret_id_bound_cidrs)?;

        let token_bound_cidrs_value = req.get_data_or_default("token_bound_cidrs")?;
        let token_bound_cidrs =
            token_bound_cidrs_value.as_comma_string_slice().ok_or(RvError::ErrRequestFieldInvalid)?;
        // Validate the list of CIDR blocks
        if !token_bound_cidrs.is_empty() {
            let cidrs: Vec<&str> = token_bound_cidrs.iter().map(AsRef::as_ref).collect();
            if !utils::cidr::validate_cidrs(&cidrs)? {
                return Err(RvError::ErrResponse("failed to validate CIDR blocks".to_string()));
            }
        }

        // Ensure that the token CIDRs on the secret ID are a subset of that of role's
        let role_token_bound_cidrs =
            role.token_bound_cidrs.iter().map(|s| s.sock_addr.to_string()).collect::<Vec<String>>();
        verify_cidr_role_secret_id_subset(&token_bound_cidrs, &role_token_bound_cidrs)?;

        // Check whether or not specified num_uses is defined, otherwise fallback to role's secret_id_num_uses
        let num_uses: i64;
        if let Ok(num_uses_value) = req.get_data("num_uses") {
            num_uses = num_uses_value.as_i64().ok_or(RvError::ErrRequestFieldInvalid)?;
            if num_uses < 0 {
                return Err(RvError::ErrResponse("num_uses cannot be negative".to_string()));
            }
            // If the specified num_uses is higher than the role's secret_id_num_uses, throw an error rather than implicitly overriding
            if role.secret_id_num_uses > 0 && (num_uses == 0 || num_uses > role.secret_id_num_uses) {
                return Err(RvError::ErrResponse(
                    "num_uses cannot be higher than the role's secret_id_num_uses".to_string(),
                ));
            }
        } else {
            num_uses = role.secret_id_num_uses;
        }

        // Check whether or not specified ttl is defined, otherwise fallback to role's secret_id_ttl
        let ttl: Duration;
        if let Ok(ttl_value) = req.get_data("ttl") {
            ttl = ttl_value.as_duration().ok_or(RvError::ErrRequestFieldInvalid)?;
            if (ttl.as_secs() == 0 && role.secret_id_ttl.as_secs() > 0)
                || (role.secret_id_ttl.as_secs() > 0 && ttl.as_secs() > role.secret_id_ttl.as_secs())
            {
                return Err(RvError::ErrResponse("ttl cannot be longer than the role's secret_id_ttl".to_string()));
            }
        } else {
            ttl = role.secret_id_ttl;
        }

        let mut secret_id_storage = SecretIdStorageEntry {
            secret_id_num_uses: num_uses,
            secret_id_ttl: ttl,
            cidr_list,
            token_cidr_list: token_bound_cidrs,
            ..Default::default()
        };

        if let Ok(metadata_value) = req.get_data("metadata") {
            secret_id_storage.metadata = metadata_value.as_map().ok_or(RvError::ErrRequestFieldInvalid)?;
        }

        if let Ok(environments_value) = req.get_data("environments") {
            secret_id_storage.environments =
                environments_value.as_comma_string_slice().ok_or(RvError::ErrRequestFieldInvalid)?;
        }

        let storage = Arc::as_ref(req.storage.as_ref().unwrap());
        self.register_secret_id_entry(
            storage,
            &role.name,
            secret_id,
            &role.hmac_key,
            &role.secret_id_prefix,
            &mut secret_id_storage,
        )
        .await?;

        let resp_data = json!({
            "secret_id": secret_id,
            "secret_id_accessor": secret_id_storage.secret_id_accessor,
            "secret_id_ttl": self.derive_secret_id_ttl(secret_id_storage.secret_id_ttl).as_secs(),
            "secret_id_num_uses": secret_id_storage.secret_id_num_uses,
            "environments": secret_id_storage.environments,
        });

        Ok(Some(Response::data_response(resp_data.as_object().cloned())))
    }

    pub async fn write_role_secret_id(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let secret_id = utils::generate_uuid();
        self.update_role_secret_id_common(req, &secret_id).await
    }

    pub async fn write_role_secret_id_lookup(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data_as_str("role_name")?;
        let secret_id = req.get_data_as_str("secret_id")?;

        let lock_entry = self.role_locks.get_lock(&role_name);
        let _locked = lock_entry.lock.read().await;

        let role = self.get_role(req, &role_name).await?;
        if role.is_none() {
            return Err(RvError::ErrResponse(format!("role {role_name} does not exist")));
        }

        let role = role.unwrap();

        let role_name_hmac = create_hmac(&role.hmac_key, &role.name)?;
        let secret_id_hmac = create_hmac(&role.hmac_key, &secret_id)?;

        let entry_index = format!("{}{}/{}", role.secret_id_prefix, role_name_hmac, secret_id_hmac);

        let lock_entry = self.secret_id_locks.get_lock(&secret_id_hmac);
        let _locked = lock_entry.lock.write().await;

        let storage = Arc::as_ref(req.storage.as_ref().unwrap());

        if let Some(secret_id_entry) =
            self.get_secret_id_storage_entry(storage, &role.secret_id_prefix, &role_name_hmac, &secret_id_hmac).await?
        {
            // If a secret ID entry does not have a corresponding accessor
            // entry, revoke the secret ID immediately
            let accessor_entry = self
                .get_secret_id_accessor_entry(storage, &secret_id_entry.secret_id_accessor, &role.secret_id_prefix)
                .await?;
            if accessor_entry.is_none() {
                req.storage_delete(&entry_index).await?;
                return Err(RvError::ErrResponse("invalid secret_id".to_string()));
            }

            let data = serde_json::to_value(&secret_id_entry)?;
            return Ok(Some(Response::data_response(Some(data.as_object().unwrap().clone()))));
        }

        Ok(None)
    }

    pub async fn write_role_secret_id_destory(
        &self,
        backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.delete_role_secret_id_destory(backend, req).await
    }

    pub async fn delete_role_secret_id_destory(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data_as_str("role_name")?;
        let secret_id = req.get_data_as_str("secret_id")?;

        let lock_entry = self.role_locks.get_lock(&role_name);
        let _locked = lock_entry.lock.read().await;

        let role = self.get_role(req, &role_name).await?;
        if role.is_none() {
            return Err(RvError::ErrResponse(format!("role {role_name} does not exist")));
        }

        let role = role.unwrap();

        let role_name_hmac = create_hmac(&role.hmac_key, &role.name)?;
        let secret_id_hmac = create_hmac(&role.hmac_key, &secret_id)?;

        let entry_index = format!("{}{}/{}", role.secret_id_prefix, role_name_hmac, secret_id_hmac);

        let lock_entry = self.secret_id_locks.get_lock(&secret_id_hmac);
        let _locked = lock_entry.lock.write().await;

        let storage = Arc::as_ref(req.storage.as_ref().unwrap());

        if let Some(secret_id_entry) =
            self.get_secret_id_storage_entry(storage, &role.secret_id_prefix, &role_name_hmac, &secret_id_hmac).await?
        {
            // Delete the accessor of the secret_id first
            self.delete_secret_id_accessor_entry(storage, &secret_id_entry.secret_id_accessor, &role.secret_id_prefix)
                .await?;

            // Delete the storage entry that corresponds to the secret_id
            storage.delete(&entry_index).await?;
        }

        Ok(None)
    }

    pub async fn write_role_secret_id_accessor_lookup(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data_as_str("role_name")?;
        let secret_id_accessor = req.get_data_as_str("secret_id_accessor")?;

        let lock_entry = self.role_locks.get_lock(&role_name);
        let _locked = lock_entry.lock.read().await;

        let role = self.get_role(req, &role_name).await?;
        if role.is_none() {
            return Err(RvError::ErrResponse(format!("role {role_name} does not exist")));
        }

        let role = role.unwrap();

        let storage = Arc::as_ref(req.storage.as_ref().unwrap());

        if let Some(accessor_entry) =
            self.get_secret_id_accessor_entry(storage, &secret_id_accessor, &role.secret_id_prefix).await?
        {
            let role_name_hmac = create_hmac(&role.hmac_key, &role.name)?;

            let lock_entry = self.secret_id_locks.get_lock(&accessor_entry.secret_id_hmac);
            let _locked = lock_entry.lock.read().await;

            if let Some(secret_id_entry) = self
                .get_secret_id_storage_entry(
                    storage,
                    &role.secret_id_prefix,
                    &role_name_hmac,
                    &accessor_entry.secret_id_hmac,
                )
                .await?
            {
                let data = serde_json::to_value(secret_id_entry)?;
                return Ok(Some(Response::data_response(Some(data.as_object().unwrap().clone()))));
            }
        } else {
            return Err(RvError::ErrResponseStatus(
                404,
                format!("failed to find accessor entry for secret_id_accessor: {secret_id_accessor}"),
            ));
        }

        Ok(None)
    }

    pub async fn write_role_secret_id_accessor_destory(
        &self,
        backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.delete_role_secret_id_accessor_destory(backend, req).await
    }

    pub async fn delete_role_secret_id_accessor_destory(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let role_name = req.get_data_as_str("role_name")?;
        let secret_id_accessor = req.get_data_as_str("secret_id_accessor")?;

        let lock_entry = self.role_locks.get_lock(&role_name);
        let _locked = lock_entry.lock.write().await;

        // secret_id is indexed based on HMACed role_name and HMACed secret_id.
        // Get the role details to fetch the role_id and accessor to get
        // the HMACed secret_id.

        let role = self.get_role(req, &role_name).await?;
        if role.is_none() {
            return Err(RvError::ErrResponse(format!("role {role_name} does not exist")));
        }

        let role = role.unwrap();

        let storage = Arc::as_ref(req.storage.as_ref().unwrap());

        if let Some(accessor_entry) =
            self.get_secret_id_accessor_entry(storage, &secret_id_accessor, &role.secret_id_prefix).await?
        {
            let role_name_hmac = create_hmac(&role.hmac_key, &role.name)?;

            let lock_entry = self.secret_id_locks.get_lock(&accessor_entry.secret_id_hmac);
            let _locked = lock_entry.lock.write().await;

            // Verify we have a valid secret_id storage entry
            if self
                .get_secret_id_storage_entry(
                    storage,
                    &role.secret_id_prefix,
                    &role_name_hmac,
                    &accessor_entry.secret_id_hmac,
                )
                .await?
                .is_none()
            {
                return Err(RvError::ErrResponseStatus(
                    403,
                    format!("invalid secret_id_accessor: {secret_id_accessor}"),
                ));
            }

            let entry_index = format!("{}{}/{}", role.secret_id_prefix, role_name_hmac, &accessor_entry.secret_id_hmac);

            let storage = Arc::as_ref(req.storage.as_ref().unwrap());

            // Delete the accessor of the secret_id first
            self.delete_secret_id_accessor_entry(storage, &secret_id_accessor, &role.secret_id_prefix).await?;

            storage.delete(&entry_index).await?;
        } else {
            return Err(RvError::ErrResponseStatus(
                404,
                format!("failed to find accessor entry for secret_id_accessor: {secret_id_accessor}"),
            ));
        }

        Ok(None)
    }

    pub async fn write_role_custom_secret_id(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.update_role_secret_id_common(req, req.get_data("secret_id")?.as_str().unwrap_or("")).await
    }
}

/// Best-effort append to the UserAuditStore (covers approle role
/// lifecycle too — same store, `mount="approle/"`). Silent on
/// subsystem absence.
async fn record_approle_audit(
    core: &dyn VaultCtx,
    req: &crate::logical::Request,
    op: &str,
    target: &str,
    details: &str,
) {
    use crate::kernel_api::identity::{caller_audit_actor, UserAuditRecord};

    let Some(identity) = core.identity() else {
        return;
    };
    let _ = identity
        .record_user_audit(UserAuditRecord {
            ts: String::new(),
            actor_entity_id: caller_audit_actor(req),
            op: op.to_string(),
            mount: "approle/".to_string(),
            target: target.to_string(),
            details: details.to_string(),
        })
        .await;
}

