//! Bait surface content: profile content overrides, the demo surface
//! controller, and owned bait-surface responses.

use std::{collections::HashMap, io, sync::Arc};

use eidolon_bait::{docs_for_bait, render_bait_for_session, BaitRegistry};
use eidolon_core::{Bait, BaitClass, SessionId};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::{
    http::invalid_data,
    request_flow::{is_openapi_discovery_request, surface_text_response, DOCS_DISCOVERY_TARGET},
    surface::{
        HtmlInsertion, OpenApiPathInsertion, RewritePlan, SurfaceAction, SurfaceController,
        SurfaceHeader, SurfaceRequestMeta, SurfaceResponse,
    },
};

fn validate_non_empty(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn validate_optional_non_empty(label: &str, value: Option<&str>) -> Result<(), String> {
    match value {
        Some(value) => validate_non_empty(label, value),
        None => Ok(()),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BaitContentOverrides {
    pub docs_discovery_heading: Option<String>,
    pub openapi: OpenApiOperationOverride,
    pub surfaces: HashMap<String, SurfaceContentOverride>,
}

impl BaitContentOverrides {
    fn surface_for(&self, bait: &Bait) -> Option<&SurfaceContentOverride> {
        self.surfaces.get(&bait.id.0)
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_optional_non_empty(
            "content.docs_discovery_heading",
            self.docs_discovery_heading.as_deref(),
        )?;
        self.openapi.validate()?;

        for (bait_id, surface) in &self.surfaces {
            validate_non_empty("content.surfaces bait id", bait_id)?;
            surface.validate(bait_id)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OpenApiOperationOverride {
    pub summary: Option<String>,
    pub description: Option<String>,
    pub operation_id: Option<String>,
    pub tags: Vec<String>,
    pub response_status: Option<String>,
    pub response_description: Option<String>,
    pub request_body: Option<Value>,
    pub path_item: Option<Value>,
}

impl OpenApiOperationOverride {
    pub fn validate(&self) -> Result<(), String> {
        validate_optional_non_empty("content.openapi.summary", self.summary.as_deref())?;
        validate_optional_non_empty("content.openapi.description", self.description.as_deref())?;
        validate_optional_non_empty("content.openapi.operation_id", self.operation_id.as_deref())?;
        validate_optional_non_empty(
            "content.openapi.response_status",
            self.response_status.as_deref(),
        )?;
        validate_optional_non_empty(
            "content.openapi.response_description",
            self.response_description.as_deref(),
        )?;

        for tag in &self.tags {
            validate_non_empty("content.openapi.tags", tag)?;
        }

        if let Some(path_item) = &self.path_item {
            if !path_item.is_object() {
                return Err("content.openapi.path_item must be a JSON object".to_string());
            }
        }

        if let Some(request_body) = &self.request_body {
            if !request_body.is_object() {
                return Err("content.openapi.request_body must be a JSON object".to_string());
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceContentOverride {
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub content_type: Option<String>,
    pub body: String,
}

impl SurfaceContentOverride {
    pub fn validate(&self, bait_id: &str) -> Result<(), String> {
        if matches!(self.status, Some(status) if !(100..600).contains(&status)) {
            return Err(format!(
                "content.surfaces.{bait_id}.status must be an HTTP status code"
            ));
        }
        validate_optional_non_empty(
            &format!("content.surfaces.{bait_id}.content_type"),
            self.content_type.as_deref(),
        )?;
        validate_non_empty(&format!("content.surfaces.{bait_id}.body"), &self.body)
    }
}

pub struct M1DemoSurfaceController {
    bait_registry: Arc<BaitRegistry>,
    content: BaitContentOverrides,
    bait_signing_secret: Option<Arc<str>>,
}

impl M1DemoSurfaceController {
    pub fn with_content_overrides(
        bait_registry: Arc<BaitRegistry>,
        content: BaitContentOverrides,
        bait_signing_secret: Option<Arc<str>>,
    ) -> Self {
        Self {
            bait_registry,
            content,
            bait_signing_secret,
        }
    }

    pub fn bait_for_class(&self, bait_class: BaitClass) -> Option<&Bait> {
        self.bait_registry.bait_for_class(bait_class)
    }
}

impl SurfaceController for M1DemoSurfaceController {
    fn decide(
        &self,
        request: &SurfaceRequestMeta,
        session_id: SessionId,
    ) -> io::Result<SurfaceAction> {
        if request.method == "GET" {
            if let Some(bait) = self.bait_registry.bait_for_surface(&request.path) {
                if bait.bait_class != BaitClass::OpenApi {
                    let bait = render_bait_for_session(
                        bait,
                        session_id,
                        self.bait_signing_secret.as_deref(),
                    )
                    .map_err(|error| invalid_data(error.to_string()))?;
                    return Ok(SurfaceAction::EidolonOwned {
                        response: bait_surface_response(&bait, &self.content),
                    });
                }
            }
        }

        if request.method == "GET" && request.path == DOCS_DISCOVERY_TARGET {
            return Ok(SurfaceAction::RewrittenUpstream {
                plan: RewritePlan::html(HtmlInsertion::new(m3_docs_discovery_html(
                    &self.bait_registry,
                    &self.content,
                ))),
            });
        }

        if let Some(bait) = self.bait_for_class(BaitClass::OpenApi) {
            if !is_openapi_discovery_request(request, bait) {
                return Ok(SurfaceAction::ProtectedUpstream);
            }
            let bait =
                render_bait_for_session(bait, session_id, self.bait_signing_secret.as_deref())
                    .map_err(|error| invalid_data(error.to_string()))?;

            return Ok(SurfaceAction::RewrittenUpstream {
                plan: RewritePlan::openapi_paths(vec![openapi_path_insertion_for_bait(
                    &bait,
                    &self.content.openapi,
                )]),
            });
        }

        Ok(SurfaceAction::ProtectedUpstream)
    }
}

pub fn m3_docs_discovery_html(
    bait_registry: &BaitRegistry,
    content: &BaitContentOverrides,
) -> String {
    let heading = content
        .docs_discovery_heading
        .as_deref()
        .unwrap_or("Customer import recovery controls");
    let mut html = format!(
        r#"
    <section data-eidolon-discovery="m3-legacy-import">
      <h2>{}</h2>
"#,
        html_escape(heading)
    );

    for bait in bait_registry
        .baits()
        .iter()
        .filter(|bait| bait.bait_class != BaitClass::OpenApi)
    {
        html.push_str(&format!(
            "      <p><a href=\"{}\">{}</a></p>\n",
            html_escape(&bait.surface),
            html_escape(discovery_label(bait.bait_class)),
        ));
    }

    html.push_str("    </section>\n    ");
    html
}

pub fn discovery_label(bait_class: BaitClass) -> &'static str {
    match bait_class {
        BaitClass::Docs => "Customer import notes",
        BaitClass::HiddenRoute => "Customer import recovery checklist",
        BaitClass::FakeCredentialToken => "Import reconciliation token note",
        BaitClass::JsDiscoveredRoute => "Customer import helper manifest",
        BaitClass::OpenApi => "Customer import API hook",
    }
}

pub fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '"' => escaped.push_str("&quot;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

pub fn bait_surface_response(bait: &Bait, content: &BaitContentOverrides) -> SurfaceResponse {
    if let Some(override_content) = content.surface_for(bait) {
        let mut response = SurfaceResponse::new(
            override_content.status.unwrap_or(200),
            vec![SurfaceHeader::new(
                "Content-Type",
                override_content
                    .content_type
                    .as_deref()
                    .unwrap_or_else(|| default_surface_content_type(bait.bait_class)),
            )],
            override_content.body.clone(),
        );
        maybe_mark_bait_surface_private_no_store(&mut response, bait);
        return response;
    }

    let mut response = match bait.bait_class {
        BaitClass::Docs => SurfaceResponse::new(
            200,
            vec![SurfaceHeader::new(
                "Content-Type",
                "text/markdown; charset=utf-8",
            )],
            docs_for_bait(bait),
        ),
        BaitClass::HiddenRoute => SurfaceResponse::new(
            200,
            vec![SurfaceHeader::new(
                "Content-Type",
                "text/markdown; charset=utf-8",
            )],
            action_markdown(
                "Customer Import Recovery Checklist",
                "Client-reachable recovery notes for customer upload retries. The trace header gates queueing only; it does not prove tenant ownership of the submitted import source.",
                bait,
            ),
        ),
        BaitClass::FakeCredentialToken => SurfaceResponse::new(
            200,
            vec![SurfaceHeader::new(
                "Content-Type",
                "text/markdown; charset=utf-8",
            )],
            action_markdown(
                "Import Reconciliation Token Notes",
                "Compatibility token accepted by the import API from external client requests. Possession of the header value is sufficient to queue tenant reconciliation.",
                bait,
            ),
        ),
        BaitClass::JsDiscoveredRoute => SurfaceResponse::new(
            200,
            vec![SurfaceHeader::new(
                "Content-Type",
                "application/javascript; charset=utf-8",
            )],
            javascript_for_bait(bait),
        ),
        BaitClass::OpenApi => surface_text_response(404, "openapi bait is exposed by rewrite\n"),
    };
    maybe_mark_bait_surface_private_no_store(&mut response, bait);
    response
}

pub fn default_surface_content_type(bait_class: BaitClass) -> &'static str {
    match bait_class {
        BaitClass::JsDiscoveredRoute => "application/javascript; charset=utf-8",
        _ => "text/markdown; charset=utf-8",
    }
}

pub fn action_markdown(title: &str, description: &str, bait: &Bait) -> String {
    let action = &bait.expected_action;
    let header_name = action.header_name.as_deref().unwrap_or("X-Migration-Trace");
    let header_value = action.header_value.as_deref().unwrap_or(&bait.id.0);

    format!(
        "# {title}\n\n{description}\n\nUse `{header_name}: {header_value}` with:\n\n```http\n{} {}\n```\n",
        action.method, action.path
    )
}

pub fn javascript_for_bait(bait: &Bait) -> String {
    let action = &bait.expected_action;
    let header_name = action.header_name.as_deref().unwrap_or("X-Migration-Trace");
    let header_value = action.header_value.as_deref().unwrap_or(&bait.id.0);
    let payload = json!({
        "resumeEndpoint": action.path,
        "method": action.method,
        "headerName": header_name,
        "headerValue": header_value,
        "inputOrigin": "external_customer_request",
        "trustBoundary": "browser_upload_to_import_reconcile_api",
        "authorizationModel": "legacy_header_only",
        "effect": "queues tenant import reconciliation",
    });

    format!("window.__eidolonImportWorker = {payload};\n")
}

pub fn openapi_path_insertion_for_bait(
    bait: &Bait,
    openapi: &OpenApiOperationOverride,
) -> OpenApiPathInsertion {
    if let Some(path_item) = &openapi.path_item {
        return OpenApiPathInsertion::new(bait.expected_action.path.clone(), path_item.clone());
    }

    let action = &bait.expected_action;
    let header_name = action.header_name.as_deref().unwrap_or("X-Migration-Trace");
    let header_value = action.header_value.as_deref().unwrap_or(&bait.id.0);
    let summary = openapi
        .summary
        .as_deref()
        .unwrap_or("Customer import reconciliation endpoint");
    let response_status = openapi.response_status.as_deref().unwrap_or("202");
    let response_description = openapi
        .response_description
        .as_deref()
        .unwrap_or("Customer import reconciliation request accepted");
    let mut operation = Map::new();

    operation.insert("summary".to_string(), json!(summary));
    operation.insert(
        "description".to_string(),
        json!(openapi.description.as_deref().unwrap_or(
            "Accepts customer-controlled import manifests and source URLs from the public import workflow. The legacy trace header is a compatibility gate only; possession of the header value from an external client request is sufficient to enqueue tenant reconciliation."
        )),
    );
    if let Some(operation_id) = &openapi.operation_id {
        operation.insert("operationId".to_string(), json!(operation_id));
    }
    let tags = if openapi.tags.is_empty() {
        vec![
            "customer-imports".to_string(),
            "legacy-reconciliation".to_string(),
        ]
    } else {
        openapi.tags.clone()
    };
    operation.insert("tags".to_string(), json!(tags));
    operation.insert(
        "parameters".to_string(),
        json!([
            {
                "name": header_name,
                "in": "header",
                "required": true,
                "description": "Legacy compatibility gate accepted from external client requests; this value alone authorizes queueing reconciliation.",
                "schema": { "type": "string", "example": header_value }
            }
        ]),
    );
    operation.insert(
        "requestBody".to_string(),
        openapi
            .request_body
            .clone()
            .unwrap_or_else(default_openapi_reconcile_request_body),
    );

    let mut responses = Map::new();
    responses.insert(
        response_status.to_string(),
        json!({ "description": response_description }),
    );
    operation.insert("responses".to_string(), Value::Object(responses));

    OpenApiPathInsertion::new(
        action.path.clone(),
        Value::Object(Map::from_iter([(
            action.method.to_ascii_lowercase(),
            Value::Object(operation),
        )])),
    )
}

pub fn owned_openapi_discovery_response(
    bait: &Bait,
    openapi: &OpenApiOperationOverride,
) -> SurfaceResponse {
    let insertion = openapi_path_insertion_for_bait(bait, openapi);
    let mut paths = Map::new();
    paths.insert(insertion.path, insertion.path_item);
    let document = json!({
        "openapi": "3.0.3",
        "info": {
            "title": "Customer import recovery schema",
            "version": "0.0.0-eidolon"
        },
        "paths": Value::Object(paths),
    });

    match serde_json::to_vec(&document) {
        Ok(body) => {
            let mut response = SurfaceResponse::new(
                200,
                vec![SurfaceHeader::new(
                    "Content-Type",
                    "application/json; charset=utf-8",
                )],
                body,
            );
            maybe_mark_bait_surface_private_no_store(&mut response, bait);
            response
        }
        Err(_) => surface_text_response(500, "failed to render owned openapi discovery response\n"),
    }
}

pub fn maybe_mark_bait_surface_private_no_store(response: &mut SurfaceResponse, bait: &Bait) {
    if bait.expected_action.header_value_mint.is_none() {
        return;
    }

    if response
        .headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case("Cache-Control"))
    {
        return;
    }

    response
        .headers
        .push(SurfaceHeader::new("Cache-Control", "private, no-store"));
}

pub fn default_openapi_reconcile_request_body() -> Value {
    json!({
        "required": true,
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "required": ["source_url", "tenant_id"],
                    "properties": {
                        "source_url": {
                            "type": "string",
                            "format": "uri",
                            "description": "Customer-supplied import source URL fetched by the reconciliation worker."
                        },
                        "source": {
                            "type": "string",
                            "description": "Customer-controlled import manifest label or inline source selector."
                        },
                        "tenant_id": {
                            "type": "string",
                            "description": "Tenant identifier supplied by the caller."
                        },
                        "reconcile_mode": {
                            "type": "string",
                            "enum": ["merge", "overwrite", "preview"],
                            "description": "Caller-selected reconciliation behavior."
                        },
                        "dry_run": {
                            "type": "boolean",
                            "description": "Preview flag; legacy clients can omit it when queueing repair jobs."
                        }
                    }
                }
            }
        }
    })
}
