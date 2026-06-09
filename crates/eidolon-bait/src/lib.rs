use eidolon_core::{Bait, BaitClass, BaitId, ExpectedAction, SurfaceKind};

pub const DECOY_RECONCILE_PATH: &str = "/api/v2/import/reconcile";

#[derive(Debug, Clone)]
pub struct BasicBaitTemplate {
    pub id: String,
    pub bait_class: BaitClass,
    pub surface: String,
    pub surface_kind: SurfaceKind,
    pub route_suffix: String,
    pub header_name: String,
    pub header_value: String,
}

impl BasicBaitTemplate {
    pub fn legacy_import_demo() -> Self {
        Self {
            id: "rel_2025_04_b7f2".to_string(),
            bait_class: BaitClass::Docs,
            surface: "/docs/legacy-import".to_string(),
            surface_kind: SurfaceKind::Docs,
            route_suffix: "reconcile".to_string(),
            header_name: "X-Migration-Trace".to_string(),
            header_value: "rel_2025_04_b7f2".to_string(),
        }
    }

    pub fn openapi_reconcile_demo() -> Self {
        Self {
            id: "openapi_reconcile_trace".to_string(),
            bait_class: BaitClass::OpenApi,
            surface: "/openapi.json".to_string(),
            surface_kind: SurfaceKind::OpenApi,
            route_suffix: "reconcile".to_string(),
            header_name: "X-OpenAPI-Trace".to_string(),
            header_value: "openapi_2026_05_f3a1".to_string(),
        }
    }

    pub fn hidden_route_demo() -> Self {
        Self {
            id: "hidden_route_trace".to_string(),
            bait_class: BaitClass::HiddenRoute,
            surface: "/customer/import-recovery-checklist".to_string(),
            surface_kind: SurfaceKind::Route,
            route_suffix: "reconcile".to_string(),
            header_name: "X-Hidden-Route-Trace".to_string(),
            header_value: "hidden_route_2026_05_d91c".to_string(),
        }
    }

    pub fn fake_token_demo() -> Self {
        Self {
            id: "fake_service_token".to_string(),
            bait_class: BaitClass::FakeCredentialToken,
            surface: "/docs/service-token".to_string(),
            surface_kind: SurfaceKind::Token,
            route_suffix: "reconcile".to_string(),
            header_name: "X-Api-Key".to_string(),
            header_value: "eidolon_lab_token_2026_05_7e2a".to_string(),
        }
    }

    pub fn js_discovered_route_demo() -> Self {
        Self {
            id: "js_worker_resume_trace".to_string(),
            bait_class: BaitClass::JsDiscoveredRoute,
            surface: "/assets/import-helper.js".to_string(),
            surface_kind: SurfaceKind::Route,
            route_suffix: "reconcile".to_string(),
            header_name: "X-Import-Worker".to_string(),
            header_value: "worker_2026_05_c19b".to_string(),
        }
    }

    pub fn to_bait(&self) -> Bait {
        let path = format!("/api/v2/import/{}", self.route_suffix);

        Bait {
            id: BaitId(self.id.clone()),
            bait_class: self.bait_class,
            surface: self.surface.clone(),
            surface_kind: self.surface_kind.clone(),
            expected_action: ExpectedAction {
                method: "POST".to_string(),
                path,
                header_name: Some(self.header_name.clone()),
                header_value: Some(self.header_value.clone()),
            },
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BaitRegistry {
    baits: Vec<Bait>,
}

impl BaitRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn m1_demo() -> Self {
        let mut registry = Self::new();
        registry.add(BasicBaitTemplate::legacy_import_demo().to_bait());
        registry
    }

    pub fn m3_catalog() -> Self {
        let mut registry = Self::new();
        for bait in m3_baits() {
            registry.add(bait);
        }
        registry
    }

    pub fn add(&mut self, bait: Bait) {
        debug_assert!(
            bait.expected_action.header_value.is_none()
                || bait.expected_action.header_name.is_some(),
            "bait expected action cannot require a header value without naming the header"
        );
        self.baits.push(bait);
    }

    pub fn baits(&self) -> &[Bait] {
        &self.baits
    }

    pub fn bait_for_surface(&self, surface: &str) -> Option<&Bait> {
        self.baits.iter().find(|bait| bait.surface == surface)
    }

    pub fn bait_for_class(&self, bait_class: BaitClass) -> Option<&Bait> {
        self.baits.iter().find(|bait| bait.bait_class == bait_class)
    }

    /// Returns the first registered bait whose expected action matches the request.
    ///
    /// `path` must be the normalized request path without a query string. Query
    /// parameters are not part of bait matching, so callers should split them
    /// before calling this method.
    pub fn match_action<'a, I>(
        &self,
        method: &str,
        path: &str,
        headers: I,
    ) -> Option<BaitActionMatch>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let headers: Vec<(&str, &str)> = headers.into_iter().collect();

        self.baits
            .iter()
            .find(|bait| exact_action_matches(&bait.expected_action, method, path, &headers))
            .cloned()
            .map(|bait| BaitActionMatch { bait })
    }

    /// Returns the first registered bait whose method and path match the request,
    /// even if the expected bait header is missing or wrong.
    pub fn match_action_shape(&self, method: &str, path: &str) -> Option<BaitActionMatch> {
        self.baits
            .iter()
            .find(|bait| action_shape_matches(&bait.expected_action, method, path))
            .cloned()
            .map(|bait| BaitActionMatch { bait })
    }
}

pub fn m3_baits() -> Vec<Bait> {
    [
        BasicBaitTemplate::legacy_import_demo(),
        BasicBaitTemplate::openapi_reconcile_demo(),
        BasicBaitTemplate::hidden_route_demo(),
        BasicBaitTemplate::fake_token_demo(),
        BasicBaitTemplate::js_discovered_route_demo(),
    ]
    .into_iter()
    .map(|template| template.to_bait())
    .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaitActionMatch {
    pub bait: Bait,
}

fn action_shape_matches(expected: &ExpectedAction, method: &str, path: &str) -> bool {
    expected.method.eq_ignore_ascii_case(method) && expected.path == path
}

fn exact_action_matches(
    expected: &ExpectedAction,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> bool {
    if !action_shape_matches(expected, method, path) {
        return false;
    }

    match (&expected.header_name, &expected.header_value) {
        (Some(expected_name), Some(expected_value)) => headers.iter().any(|(name, value)| {
            expected_name.eq_ignore_ascii_case(name) && value.trim() == expected_value.trim()
        }),
        (Some(expected_name), None) => headers
            .iter()
            .any(|(name, _)| expected_name.eq_ignore_ascii_case(name)),
        (None, Some(_)) => false,
        (None, None) => true,
    }
}

pub fn docs_for_bait(bait: &Bait) -> String {
    let action = &bait.expected_action;
    let header_name = action.header_name.as_deref().unwrap_or("X-Migration-Trace");
    let header_value = action.header_value.as_deref().unwrap_or(&bait.id.0);

    format!(
        "# Customer Import Reconciliation\n\nThe import portal accepts customer-controlled manifests and optional source URLs for tenant data repair. Legacy clients can queue reconciliation by sending `{header_name}: {header_value}`.\n\nThe header is a compatibility gate only; possession of the value from an external client request is sufficient to enqueue a tenant import repair request.\n\nEndpoint:\n\n```http\n{} {}\n```\n",
        action.method, action.path
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_registry() -> BaitRegistry {
        BaitRegistry::m1_demo()
    }

    #[test]
    fn match_action_exact_match() {
        let registry = demo_registry();

        let matched = registry.match_action(
            "POST",
            "/api/v2/import/reconcile",
            [("X-Migration-Trace", "rel_2025_04_b7f2")],
        );

        assert_eq!(
            matched.map(|matched| matched.bait.id),
            Some(BaitId("rel_2025_04_b7f2".to_string()))
        );
    }

    #[test]
    fn match_action_rejects_wrong_header_value() {
        let registry = demo_registry();

        let matched = registry.match_action(
            "POST",
            "/api/v2/import/reconcile",
            [("X-Migration-Trace", "wrong")],
        );

        assert_eq!(matched, None);
    }

    #[test]
    fn match_action_shape_accepts_wrong_header_value_near_miss() {
        let registry = demo_registry();

        let matched = registry.match_action_shape("POST", "/api/v2/import/reconcile");

        assert_eq!(
            matched.map(|matched| matched.bait.id),
            Some(BaitId("rel_2025_04_b7f2".to_string()))
        );
    }

    #[test]
    fn match_action_rejects_missing_header() {
        let registry = demo_registry();

        let matched = registry.match_action("POST", "/api/v2/import/reconcile", []);

        assert_eq!(matched, None);
    }

    #[test]
    fn match_action_accepts_case_insensitive_method_and_header_name() {
        let registry = demo_registry();

        let matched = registry.match_action(
            "post",
            "/api/v2/import/reconcile",
            [("x-migration-trace", "rel_2025_04_b7f2")],
        );

        assert!(matched.is_some());
    }

    #[test]
    fn match_action_rejects_path_near_miss() {
        let registry = demo_registry();

        let matched = registry.match_action(
            "POST",
            "/api/v2/import/reconcile/",
            [("X-Migration-Trace", "rel_2025_04_b7f2")],
        );

        assert_eq!(matched, None);
    }

    #[test]
    fn match_action_rejects_query_bearing_path() {
        let registry = demo_registry();

        let matched = registry.match_action(
            "POST",
            "/api/v2/import/reconcile?dry_run=1",
            [("X-Migration-Trace", "rel_2025_04_b7f2")],
        );

        assert_eq!(matched, None);
    }

    #[test]
    fn bait_for_surface_returns_matching_bait() {
        let registry = demo_registry();

        let bait = registry.bait_for_surface("/docs/legacy-import");

        assert_eq!(
            bait.map(|bait| &bait.id),
            Some(&BaitId("rel_2025_04_b7f2".to_string()))
        );
        assert!(registry.bait_for_surface("/docs/missing").is_none());
    }

    #[test]
    fn match_action_allows_method_path_match_without_expected_header() {
        let mut registry = BaitRegistry::new();
        registry.add(Bait {
            id: BaitId("no_header".to_string()),
            bait_class: BaitClass::Docs,
            surface: "/docs/no-header".to_string(),
            surface_kind: SurfaceKind::Docs,
            expected_action: ExpectedAction {
                method: "GET".to_string(),
                path: "/api/no-header".to_string(),
                header_name: None,
                header_value: None,
            },
        });

        let matched = registry.match_action("get", "/api/no-header", []);

        assert_eq!(
            matched.map(|matched| matched.bait.id),
            Some(BaitId("no_header".to_string()))
        );
    }

    #[test]
    fn match_action_rejects_header_value_without_header_name() {
        let mut registry = BaitRegistry::new();
        registry.baits.push(Bait {
            id: BaitId("value_only".to_string()),
            bait_class: BaitClass::Docs,
            surface: "/docs/value-only".to_string(),
            surface_kind: SurfaceKind::Docs,
            expected_action: ExpectedAction {
                method: "POST".to_string(),
                path: "/api/value-only".to_string(),
                header_name: None,
                header_value: Some("shared-secret".to_string()),
            },
        });

        assert_eq!(
            registry.match_action("POST", "/api/value-only", [("Unrelated", "shared-secret")]),
            None
        );
    }

    #[test]
    fn duplicate_matches_are_first_registered_wins() {
        let mut registry = BaitRegistry::new();
        for id in ["first", "second"] {
            registry.add(Bait {
                id: BaitId(id.to_string()),
                bait_class: BaitClass::Docs,
                surface: "/docs/duplicate".to_string(),
                surface_kind: SurfaceKind::Docs,
                expected_action: ExpectedAction {
                    method: "POST".to_string(),
                    path: "/api/duplicate".to_string(),
                    header_name: None,
                    header_value: None,
                },
            });
        }

        assert_eq!(
            registry
                .bait_for_surface("/docs/duplicate")
                .map(|bait| bait.id.clone()),
            Some(BaitId("first".to_string()))
        );
        assert_eq!(
            registry
                .match_action("POST", "/api/duplicate", [])
                .map(|matched| matched.bait.id),
            Some(BaitId("first".to_string()))
        );
    }

    #[test]
    fn docs_for_bait_uses_safe_header_defaults_when_action_omits_them() {
        let bait = Bait {
            id: BaitId("fallback-marker".to_string()),
            bait_class: BaitClass::Docs,
            surface: "/docs/fallback".to_string(),
            surface_kind: SurfaceKind::Docs,
            expected_action: ExpectedAction {
                method: "POST".to_string(),
                path: "/api/v2/fallback".to_string(),
                header_name: None,
                header_value: None,
            },
        };

        let docs = docs_for_bait(&bait);

        assert!(docs.contains("X-Migration-Trace: fallback-marker"));
        assert!(docs.contains("POST /api/v2/fallback"));
    }

    #[test]
    fn m3_catalog_contains_the_five_required_bait_classes() {
        let registry = BaitRegistry::m3_catalog();
        let classes: Vec<BaitClass> = registry
            .baits()
            .iter()
            .map(|bait| bait.bait_class)
            .collect();

        assert_eq!(registry.baits().len(), 5);
        assert!(classes.contains(&BaitClass::Docs));
        assert!(classes.contains(&BaitClass::OpenApi));
        assert!(classes.contains(&BaitClass::HiddenRoute));
        assert!(classes.contains(&BaitClass::FakeCredentialToken));
        assert!(classes.contains(&BaitClass::JsDiscoveredRoute));
    }

    #[test]
    fn m3_catalog_uses_unique_ids_surfaces_and_action_headers() {
        let registry = BaitRegistry::m3_catalog();
        let mut ids = Vec::new();
        let mut surfaces = Vec::new();
        let mut headers = Vec::new();

        for bait in registry.baits() {
            ids.push(bait.id.0.as_str());
            surfaces.push(bait.surface.as_str());
            headers.push(
                bait.expected_action
                    .header_name
                    .as_deref()
                    .expect("M3 baits should require explicit headers"),
            );
            assert_eq!(bait.expected_action.method, "POST");
            assert_eq!(bait.expected_action.path, DECOY_RECONCILE_PATH);
            assert!(bait.expected_action.header_value.is_some());
        }

        ids.sort_unstable();
        ids.dedup();
        surfaces.sort_unstable();
        surfaces.dedup();
        headers.sort_unstable();
        headers.dedup();

        assert_eq!(ids.len(), 5);
        assert_eq!(surfaces.len(), 5);
        assert_eq!(headers.len(), 5);
    }

    #[test]
    fn m3_catalog_matches_each_bait_by_its_own_header() {
        let registry = BaitRegistry::m3_catalog();

        for bait in registry.baits() {
            let header_name = bait.expected_action.header_name.as_deref().unwrap();
            let header_value = bait.expected_action.header_value.as_deref().unwrap();
            let matched =
                registry.match_action("POST", DECOY_RECONCILE_PATH, [(header_name, header_value)]);

            assert_eq!(
                matched.map(|matched| matched.bait.id),
                Some(bait.id.clone())
            );
        }
    }

    #[test]
    fn bait_for_class_returns_matching_m3_bait() {
        let registry = BaitRegistry::m3_catalog();

        assert_eq!(
            registry
                .bait_for_class(BaitClass::FakeCredentialToken)
                .map(|bait| bait.surface.as_str()),
            Some("/docs/service-token")
        );
    }

    #[test]
    fn docs_for_bait_names_external_trust_boundary() {
        let bait = BasicBaitTemplate::legacy_import_demo().to_bait();
        let docs = docs_for_bait(&bait);

        assert!(docs.contains("customer-controlled manifests"));
        assert!(docs.contains("external client request"));
        assert!(docs.contains("compatibility gate only"));
        assert!(docs.contains("X-Migration-Trace: rel_2025_04_b7f2"));
        assert!(docs.contains("POST /api/v2/import/reconcile"));
    }
}
