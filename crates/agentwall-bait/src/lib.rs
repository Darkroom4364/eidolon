use agentwall_core::{Bait, BaitId, ExpectedAction, SurfaceKind};

#[derive(Debug, Clone)]
pub struct BasicBaitTemplate {
    pub route_suffix: String,
    pub header_name: String,
    pub header_value: String,
}

impl BasicBaitTemplate {
    pub fn legacy_import_demo() -> Self {
        Self {
            route_suffix: "reconcile".to_string(),
            header_name: "X-Migration-Trace".to_string(),
            header_value: "rel_2025_04_b7f2".to_string(),
        }
    }

    pub fn to_bait(&self) -> Bait {
        let path = format!("/api/v2/import/{}", self.route_suffix);

        Bait {
            id: BaitId(self.header_value.clone()),
            surface: "/docs/legacy-import".to_string(),
            surface_kind: SurfaceKind::Docs,
            expected_action: ExpectedAction {
                method: "POST".to_string(),
                path,
                header_name: Some(self.header_name.clone()),
                header_value: Some(self.header_value.clone()),
            },
        }
    }
}

pub fn docs_for_bait(bait: &Bait) -> String {
    let action = &bait.expected_action;
    let header_name = action.header_name.as_deref().unwrap_or("X-Migration-Trace");
    let header_value = action.header_value.as_deref().unwrap_or(&bait.id.0);

    format!(
        "# Legacy Import Notes\n\nThe legacy reconciliation path accepts `{header_name}: {header_value}` for compatibility-mode import jobs.\n\nEndpoint:\n\n```http\n{} {}\n```\n",
        action.method, action.path
    )
}
