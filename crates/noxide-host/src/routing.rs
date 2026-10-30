use anyhow::{Result, ensure};
use noxide_protocol::*;

#[derive(Clone, Copy)]
enum PathSegment<'a> {
    Static(&'a str),
    Target,
}

fn canonical_id(value: &str) -> Option<u64> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|id| *id <= i64::MAX as u64)
}

fn path_segments(route: &Route) -> Result<Vec<PathSegment<'_>>> {
    ensure!(
        route.path.starts_with('/') && route.path.len() <= 128,
        "invalid route path"
    );
    let mut segments = Vec::new();
    let mut targets = 0;
    if route.path != "/" {
        for part in route.path[1..].split('/') {
            if let Some(name) = part
                .strip_prefix('{')
                .and_then(|name| name.strip_suffix('}'))
            {
                ensure!(crate::manifest::identifier(name), "invalid route parameter");
                targets += 1;
                segments.push(PathSegment::Target);
            } else {
                ensure!(crate::manifest::identifier(part), "invalid route segment");
                segments.push(PathSegment::Static(part));
            }
        }
    }
    ensure!(
        targets == usize::from(route.resource.is_some()),
        "route parameter mismatch"
    );
    ensure!(segments.len() <= 8, "route segment limit");
    Ok(segments)
}

/// Check the finite route grammar independently of guest-generated handles.
pub fn validate_path(route: &Route) -> Result<()> {
    path_segments(route)?;
    Ok(())
}

/// Whether two admitted patterns can name the same concrete request path.
pub fn paths_overlap(left: &Route, right: &Route) -> bool {
    let (Ok(left), Ok(right)) = (path_segments(left), path_segments(right)) else {
        return true;
    };
    left.len() == right.len()
        && left
            .iter()
            .zip(&right)
            .all(|(left, right)| match (left, right) {
                (PathSegment::Static(left), PathSegment::Static(right)) => left == right,
                (PathSegment::Target, PathSegment::Target) => true,
                (PathSegment::Static(value), PathSegment::Target)
                | (PathSegment::Target, PathSegment::Static(value)) => {
                    canonical_id(value).is_some()
                }
            })
}

/// Match only canonical decimal record IDs, with no alternate path encodings.
pub fn match_path(route: &Route, path: &str) -> Option<Option<u64>> {
    let segments = path_segments(route).ok()?;
    if !path.starts_with('/') {
        return None;
    }
    let parts: Vec<_> = if path == "/" {
        vec![]
    } else {
        path[1..].split('/').collect()
    };
    if segments.len() != parts.len() {
        return None;
    }
    let mut target = None;
    for (segment, part) in segments.iter().zip(parts) {
        match segment {
            PathSegment::Static(expected) if *expected == part => {}
            PathSegment::Target => target = Some(canonical_id(part)?),
            _ => return None,
        }
    }
    Some(target)
}

pub fn resolve(m: &Manifest, reference: &RouteRef) -> Result<String> {
    let route = crate::manifest::route(m, reference.route)?;
    let segments = path_segments(route)?;
    crate::manifest::validate_params(m, route, &reference.params)?;
    ensure!(
        route.resource.is_some() == reference.target.is_some(),
        "invalid route target"
    );
    if let Some(id) = reference.target {
        ensure!(id > 0 && id <= i64::MAX as u64, "invalid route target");
    }
    let mut path = String::new();
    for segment in segments {
        path.push('/');
        match segment {
            PathSegment::Static(value) => path.push_str(value),
            PathSegment::Target => path.push_str(
                &reference
                    .target
                    .ok_or_else(|| anyhow::anyhow!("missing route target"))?
                    .to_string(),
            ),
        }
    }
    if path.is_empty() {
        path.push('/');
    }
    if !reference.params.is_empty() {
        path.push('?');
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.extend_pairs(&reference.params);
        path.push_str(&query.finish());
    }
    Ok(path)
}
