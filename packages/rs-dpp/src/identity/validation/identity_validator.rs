use crate::dash_platform_protocol::JsonSchemas;
use crate::errors::consensus::basic::JsonSchemaError;
use crate::errors::consensus::ConsensusError;
use crate::schema::IdentitySchemaJsons;
use crate::validation::{byte_array_meta, ValidationResult};
use crate::DashPlatformProtocolInitError;
use jsonschema::{ErrorIterator, JSONSchema, KeywordDefinition, ValidationError};
use serde_json::json;
use serde_json::Value as JsonValue;
use thiserror::Error;

pub struct IdentityValidator {
    identity_schema_json: JsonValue,
    identity_schema: Option<JSONSchema>,
}

impl IdentityValidator {
    pub fn new() -> Result<Self, DashPlatformProtocolInitError> {
        let identity_schema_json = crate::schema::identity::identity_json()?;

        let mut identity_validator = Self {
            identity_schema_json,
            identity_schema: None,
        };

        // BYTE_ARRAY META SCHEMA

        let byte_array_meta = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://schema.dash.org/dpp-0-4-0/meta/byte-array",
            "description": "Byte array keyword meta schema",
            "type": "object",
            "properties": {
                "properties": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "object",
                        "properties": {
                            "byteArray": {
                                "type": "boolean",
                                "const": true
                            }
                        }
                    },
                    "dependentSchemas": {
                        "byteArray": {
                          "description": "should be used only with array type",
                          "properties": {
                            "type": {
                              "type": "string",
                              "const": "array"
                            }
                          },
                          "not": {
                            "properties": {
                              "items": {
                                "type": "array"
                              }
                            },
                            "required": ["items"]
                          }
                        },
                        "contentMediaType": {
                          "if": {
                            "properties": {
                              "contentMediaType": {
                                "const": "application/x.dash.dpp.identifier"
                              }
                            }
                          },
                          "then": {
                            "properties": {
                              "byteArray": {
                                "const": true
                              },
                              "minItems": {
                                "const": 32
                              },
                              "maxItems": {
                                "const": 32
                              }
                            },
                            "required": ["byteArray", "minItems", "maxItems"]
                          }
                        },
                    }
                }
            }
        });

        let byte_array_meta_schema = JSONSchema::compile(&byte_array_meta)?;
        let identity_schema = &identity_validator.identity_schema_json.clone();
        let res = byte_array_meta_schema.validate(&identity_schema);

        //let res = byte_array_meta::validate(&identity_schema);

        match res {
            Ok(_) => {}
            Err(mut errors) => {
                return Err(DashPlatformProtocolInitError::from(errors.nth(0).unwrap()));
            }
        }

        // BYTE_ARRAY META SCHEMA END

        let identity_schema = JSONSchema::options()
            .add_keyword(
                "byteArray",
                KeywordDefinition::Schema(json!({
                    "items": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 255,
                    },
                })),
            )
            .compile(&identity_validator.identity_schema_json)?;
        identity_validator.identity_schema = Some(identity_schema);

        Ok(identity_validator)
    }

    pub fn validate_identity(&self, identity_json: &serde_json::Value) -> ValidationResult {
        // Validator.validate(schema, identity_json, None) should be here
        let res = self
            .identity_schema
            .as_ref()
            .unwrap()
            .validate(&identity_json);
        let mut validation_result = ValidationResult::new(None);
        match res {
            Ok(_) => {}
            Err(validation_errors) => {
                let errors: Vec<ConsensusError> =
                    validation_errors.map(|e| ConsensusError::from(e)).collect();
                validation_result.add_errors(errors);
            }
        }
        validation_result
    }

    pub fn validate_public_keys() {}
}
