//! Contains builtins that fetch paths from the Internet, or local filesystem.

use super::utils::select_string;
use crate::{
    fetchers::{Fetch, url_basename},
    snix_store_io::SnixStoreIO,
};
use nix_compat::nixhash::{HashAlgo, NixHash};
use snix_eval::builtin_macros::builtins;
use snix_eval::generators::Gen;
use snix_eval::generators::GenCo;
use snix_eval::{CatchableErrorKind, ErrorKind, EvalIO, NixAttrs, Value, try_cek};
use std::{rc::Rc, sync::Arc};
use url::Url;

// Used as a return type for extract_fetch_args, which is sharing some
// parsing code between the fetchurl and fetchTarball builtins.
struct NixFetchArgs {
    url: Url,
    name: Option<String>,
    sha256: Option<[u8; 32]>,
}

// `fetchurl` and `fetchTarball` accept a single argument, which can either be the URL (as string),
// or an attrset, where `url`, `sha256` and `name` keys are allowed.
async fn extract_fetch_args(
    co: &GenCo,
    args: Value,
) -> Result<Result<NixFetchArgs, CatchableErrorKind>, ErrorKind> {
    if let Ok(url_str) = args.to_str() {
        // Get the raw bytes, not the ToString repr.
        let url_str =
            String::from_utf8(url_str.as_bytes().to_vec()).map_err(|_| ErrorKind::Utf8)?;

        // Parse the URL.
        let url = Url::parse(&url_str).map_err(|e| ErrorKind::SnixError(Arc::from(e)))?;

        return Ok(Ok(NixFetchArgs {
            url,
            name: None,
            sha256: None,
        }));
    }

    let attrs = args.to_attrs().map_err(|_| ErrorKind::TypeError {
        expected: "attribute set or contextless string",
        actual: args.type_of(),
    })?;

    // Reject disallowed attrset keys, to match Nix' behaviour.
    // We complain about the first unexpected key we find in the list.
    const VALID_KEYS: [&[u8]; 3] = [b"url", b"name", b"sha256"];
    if let Some(first_invalid_key) = attrs.keys().find(|k| !&VALID_KEYS.contains(&k.as_bytes())) {
        return Err(ErrorKind::UnexpectedArgumentBuiltin(
            first_invalid_key.clone(),
        ));
    }

    let url_str = try_cek!(select_string(&co, &attrs, "url").await?)
        .ok_or_else(|| ErrorKind::AttributeNotFound { name: "url".into() })?;
    let name = try_cek!(select_string(&co, &attrs, "name").await?);
    let sha256_str = try_cek!(select_string(&co, &attrs, "sha256").await?);

    Ok(Ok(NixFetchArgs {
        url: Url::parse(&url_str).map_err(|e| ErrorKind::SnixError(Arc::from(e)))?,
        name,
        // parse the sha256 string into a digest, and bail out if it's not sha256.
        sha256: sha256_str
            .map(
                |sha256_str| match NixHash::from_str(&sha256_str, Some(HashAlgo::Sha256)) {
                    Ok(NixHash::Sha256(digest)) => Ok(digest),
                    _ => Err(ErrorKind::InvalidHash(sha256_str)),
                },
            )
            .transpose()?,
    }))
}

#[allow(unused_variables)] // for the `state` arg, for now
#[builtins(state = "Rc<SnixStoreIO>")]
pub(crate) mod fetcher_builtins {
    use bstr::ByteSlice;
    use nix_compat::nixhash::HashAlgo;
    use nix_compat::{flakeref, nixhash::NixHash};
    use snix_eval::generators;
    use snix_eval::{NixContext, NixString, try_cek_to_value};
    use std::collections::BTreeMap;

    use super::*;

    /// Consumes a fetch.
    /// If there is enough info to calculate the store path without fetching,
    /// queue the fetch to be fetched lazily, and return the store path.
    /// If there's not enough info to calculate it, do the fetch now, and then
    /// return the store path.
    /// Note the builtins.typeof of fetchurl and fetchTarball are *not* "path", but "string",
    /// to stay bug-compatible with Nix.
    fn fetch_lazy(state: Rc<SnixStoreIO>, name: String, fetch: Fetch) -> Result<Value, ErrorKind> {
        let store_path = match fetch
            .store_path(&name)
            .map_err(|e| ErrorKind::SnixError(Arc::from(e)))?
        {
            Some(store_path) => {
                // Move the fetch to KnownPaths, so it can be actually fetched later.
                let sp = state
                    .known_paths
                    .borrow_mut()
                    .add_fetch(fetch, &name)
                    .expect("Snix bug: should only fail if the store path cannot be calculated");

                debug_assert_eq!(
                    sp, store_path,
                    "calculated store path by KnownPaths should match"
                );
                sp
            }
            None => {
                // If we don't have enough info, do the fetch now.
                let (store_path, _path_info) = state
                    .tokio_handle
                    .block_on(async { state.fetcher.ingest_and_persist(&name, fetch).await })
                    .map_err(|e| ErrorKind::SnixError(Arc::from(e)))?;

                store_path
            }
        };

        let s = store_path.to_absolute_path();

        // Emit the calculated Store Path, which needs to have context.
        let context = NixContext::new().append(snix_eval::NixContextElement::Plain(s.clone()));
        Ok(Value::String(NixString::new_context_from(context, s)))
    }

    /// Parse a `narHash` attribute string into an optional SHA256 digest.
    /// Returns an error for non-SHA256 algorithms rather than silently
    /// skipping content verification.
    fn parse_nar_hash(nar_hash: Option<String>) -> Result<Option<[u8; 32]>, ErrorKind> {
        match nar_hash {
            Some(h) => {
                let nixhash = NixHash::from_str(&h, Some(HashAlgo::Sha256))
                    .map_err(|e| ErrorKind::InvalidHash(e.to_string()))?;
                match nixhash {
                    NixHash::Sha256(digest) => Ok(Some(digest)),
                    _ => Err(ErrorKind::InvalidHash(format!(
                        "narHash algorithm not supported: {h}"
                    ))),
                }
            }
            None => Ok(None),
        }
    }

    /// Default fetch name: basename of URL path, or "source" if empty.
    fn default_fetch_name(url: &Url) -> String {
        let basename = url_basename(url);
        if basename.is_empty() {
            "source".to_owned()
        } else {
            basename.to_owned()
        }
    }

    #[builtin("fetchurl")]
    async fn builtin_fetchurl(
        state: Rc<SnixStoreIO>,
        co: GenCo,
        args: Value,
    ) -> Result<Value, ErrorKind> {
        let args = try_cek_to_value!(extract_fetch_args(&co, args).await?);

        // Derive the name from the URL basename if not set explicitly.
        let name = args
            .name
            .unwrap_or_else(|| url_basename(&args.url).to_owned());

        fetch_lazy(
            state,
            name,
            Fetch::URL {
                url: args.url,
                exp_hash: args.sha256.map(NixHash::Sha256),
            },
        )
    }

    #[builtin("fetchTarball")]
    async fn builtin_fetch_tarball(
        state: Rc<SnixStoreIO>,
        co: GenCo,
        args: Value,
    ) -> Result<Value, ErrorKind> {
        let args = try_cek_to_value!(extract_fetch_args(&co, args).await?);

        // Name defaults to "source" if not set explicitly.
        const DEFAULT_NAME_FETCH_TARBALL: &str = "source";
        let name = args
            .name
            .unwrap_or_else(|| DEFAULT_NAME_FETCH_TARBALL.to_owned());

        fetch_lazy(
            state,
            name,
            Fetch::Tarball {
                url: args.url,
                exp_nar_sha256: args.sha256,
            },
        )
    }

    #[builtin("fetchGit")]
    async fn builtin_fetch_git(
        state: Rc<SnixStoreIO>,
        co: GenCo,
        args: Value,
    ) -> Result<Value, ErrorKind> {
        // Accept either a bare URL string or an attrset.
        let (url, r#ref, rev, name, all_refs, submodules) = if let Ok(url_str) = args.to_str() {
            // Bare URL: all other options default.
            let url_str = String::from_utf8(url_str.as_bytes().to_vec())
                .map_err(|_| ErrorKind::Utf8)?;
            let url =
                Url::parse(&url_str).map_err(|e| ErrorKind::SnixError(Arc::new(e)))?;
            (url, None, None, None, false, false)
        } else {
            let attrs = args.to_attrs().map_err(|_| ErrorKind::TypeError {
                expected: "attribute set or contextless string",
                actual: args.type_of(),
            })?;

            let url_str = try_cek_to_value!(select_string(&co, &attrs, "url").await?)
                .ok_or_else(|| ErrorKind::AttributeNotFound { name: "url".into() })?;
            let url =
                Url::parse(&url_str).map_err(|e| ErrorKind::SnixError(Arc::new(e)))?;
            let r#ref = try_cek_to_value!(select_string(&co, &attrs, "ref").await?);
            let rev = try_cek_to_value!(select_string(&co, &attrs, "rev").await?);
            let name = try_cek_to_value!(select_string(&co, &attrs, "name").await?);

            let all_refs = match attrs.select("allRefs") {
                Some(v) => generators::request_force(&co, v.clone())
                    .await
                    .as_bool()?,
                None => false,
            };
            let submodules = match attrs.select("submodules") {
                Some(v) => generators::request_force(&co, v.clone())
                    .await
                    .as_bool()?,
                None => false,
            };

            (url, r#ref, rev, name, all_refs, submodules)
        };

        // Default name: basename of the URL path, or "source" if empty.
        let name = name.unwrap_or_else(|| default_fetch_name(&url));

        // Use the shared Fetcher method for git clone + ingest + persist.
        // This keeps the code path unified with Fetcher::ingest(Fetch::Git)
        // and avoids duplicating the ingest/NAR/persist logic.
        let (store_path, path_info, resolved_rev) = state
            .tokio_handle
            .block_on(async {
                state.fetcher.ingest_git_and_persist(
                    &name,
                    &url,
                    r#ref.as_deref(),
                    rev.as_deref(),
                    all_refs,
                    submodules,
                )
                .await
            })
            .map_err(|e| ErrorKind::SnixError(Arc::new(e)))?;

        // Build the attrset matching CppNix's fetchGit return value.
        let out_path = store_path.to_absolute_path();
        let short_rev: String = resolved_rev.chars().take(7).collect();
        let nar_hash_str = format!(
            "sha256-{}",
            nix_compat::nixbase32::encode(&path_info.nar_sha256)
        );
        let mut attrs: BTreeMap<String, Value> = BTreeMap::new();
        attrs.insert(
            "outPath".into(),
            Value::Path(Box::new(out_path.into())),
        );
        attrs.insert("rev".into(), Value::from(resolved_rev));
        attrs.insert("shortRev".into(), Value::from(short_rev));
        attrs.insert("narHash".into(), Value::from(nar_hash_str));
        attrs.insert("revCount".into(), Value::Integer(0));
        attrs.insert("submodules".into(), Value::Bool(submodules));

        Ok(Value::Attrs(NixAttrs::from_iter(attrs)))
    }

    // FUTUREWORK: make it a feature flag once #64 is implemented
    #[builtin("parseFlakeRef")]
    async fn builtin_parse_flake_ref(
        state: Rc<SnixStoreIO>,
        co: GenCo,
        value: Value,
    ) -> Result<Value, ErrorKind> {
        let flake_ref = value.to_str()?;
        let flake_ref_str = flake_ref.to_str()?;

        let fetch_args: flakeref::FlakeRef = flake_ref_str
            .parse()
            .map_err(|err| ErrorKind::SnixError(Arc::new(err)))?;

        // Convert the FlakeRef to our Value format
        let mut attrs = BTreeMap::new();

        // Extract type and url based on the variant
        match fetch_args {
            flakeref::FlakeRef::Git { url, .. } => {
                attrs.insert("type".into(), Value::from("git"));
                attrs.insert("url".into(), Value::from(url.to_string()));
            }
            flakeref::FlakeRef::GitHub {
                owner, repo, r#ref, ..
            } => {
                attrs.insert("type".into(), Value::from("github"));
                attrs.insert("owner".into(), Value::from(owner));
                attrs.insert("repo".into(), Value::from(repo));
                if let Some(ref_name) = r#ref {
                    attrs.insert("ref".into(), Value::from(ref_name));
                }
            }
            flakeref::FlakeRef::GitLab { owner, repo, .. } => {
                attrs.insert("type".into(), Value::from("gitlab"));
                attrs.insert("owner".into(), Value::from(owner));
                attrs.insert("repo".into(), Value::from(repo));
            }
            flakeref::FlakeRef::File { url, .. } => {
                attrs.insert("type".into(), Value::from("file"));
                attrs.insert("url".into(), Value::from(url.to_string()));
            }
            flakeref::FlakeRef::Tarball { url, .. } => {
                attrs.insert("type".into(), Value::from("tarball"));
                attrs.insert("url".into(), Value::from(url.to_string()));
            }
            flakeref::FlakeRef::Path { path, .. } => {
                attrs.insert("type".into(), Value::from("path"));
                attrs.insert(
                    "path".into(),
                    Value::from(path.to_string_lossy().into_owned()),
                );
            }
            _ => {
                // For all other ref types, return a simple type/url attributes
                attrs.insert("type".into(), Value::from("indirect"));
                attrs.insert("url".into(), Value::from(flake_ref_str));
            }
        }

        Ok(Value::Attrs(attrs.into()))
    }

    /// `fetchTree` is the unified fetch primitive used by flakes.
    /// It dispatches based on the `type` attribute:
    ///
    /// - `"github"` → convert to tarball URL and fetch
    /// - `"git"` → delegate to fetchGit logic
    /// - `"tarball"` → delegate to fetchTarball logic
    /// - `"file"`, `"url"` → delegate to fetchurl logic
    /// - `"path"` → import the local path
    #[builtin("fetchTree")]
    async fn builtin_fetch_tree(
        state: Rc<SnixStoreIO>,
        co: GenCo,
        args: Value,
    ) -> Result<Value, ErrorKind> {
        let attrs = args.to_attrs().map_err(|_| ErrorKind::TypeError {
            expected: "attribute set",
            actual: args.type_of(),
        })?;

        let type_str = attrs
            .select("type")
            .map(|v| {
                let forced = generators::request_force(&co, v.clone());
                async move { forced.await.to_str() }
            });

        let type_str = match type_str {
            Some(fut) => fut.await?.to_str()?.to_string(),
            None => {
                return Err(ErrorKind::AttributeNotFound {
                    name: "type".into(),
                });
            }
        };

        match type_str.as_str() {
            "github" | "gitlab" | "sourcehut" => {
                // Convert to a tarball URL.
                let owner = try_cek_to_value!(select_string(&co, &attrs, "owner").await?)
                    .ok_or_else(|| ErrorKind::AttributeNotFound {
                        name: "owner".into(),
                    })?;
                let repo = try_cek_to_value!(select_string(&co, &attrs, "repo").await?)
                    .ok_or_else(|| ErrorKind::AttributeNotFound {
                        name: "repo".into(),
                    })?;
                let r#ref = try_cek_to_value!(select_string(&co, &attrs, "ref").await?);
                let rev = try_cek_to_value!(select_string(&co, &attrs, "rev").await?);
                let name = try_cek_to_value!(select_string(&co, &attrs, "name").await?);

                let tag_or_rev = r#ref
                    .as_deref()
                    .or(rev.as_deref())
                    .unwrap_or("HEAD");

                let host = match type_str.as_str() {
                    "gitlab" => "gitlab.com",
                    "sourcehut" => "git.sr.ht",
                    _ => "github.com",
                };

                // Percent-encode path components for the archive URL.
                // Git refs may contain {, }, |, ^, space, etc. — reject
                // them rather than producing a broken URL.
                let enc = |s: &str| -> Result<String, ErrorKind> {
                    for c in s.chars() {
                        if matches!(c, '{' | '}' | '|' | '^' | ' ' | '\\' | '<' | '>') {
                            return Err(ErrorKind::SnixError(Arc::new(
                                std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput,
                                    format!("unsupported character '{c}' in git ref '{s}'"),
                            ))));
                        }
                    }
                    Ok(s.replace('%', "%25")
                        .replace('/', "%2F")
                        .replace('#', "%23")
                        .replace('?', "%3F")
                        .replace('@', "%40"))
                };
                let tarball_url = if type_str == "gitlab" {
                    // GitLab archive format: /-/archive/ref/repo-ref.tar.gz
                    Url::parse(&format!(
                        "https://gitlab.com/{}/{}/-/archive/{}/{}-{}.tar.gz",
                        enc(&owner)?, enc(&repo)?, enc(&tag_or_rev)?, enc(&repo)?, enc(&tag_or_rev)?
                    ))
                } else {
                    Url::parse(&format!(
                        "https://{}/{}/{}/archive/{}.tar.gz",
                        host,
                        enc(&owner)?,
                        enc(&repo)?,
                        enc(&tag_or_rev)?
                    ))
                }
                .map_err(|e| ErrorKind::SnixError(Arc::new(e)))?;

                let name = name.unwrap_or_else(|| "source".to_owned());
                let nar_hash = try_cek_to_value!(select_string(&co, &attrs, "narHash").await?);
                let exp_nar_sha256 = parse_nar_hash(nar_hash)?;

                fetch_lazy(
                    state,
                    name,
                    Fetch::Tarball {
                        url: tarball_url,
                        exp_nar_sha256,
                    },
                )
            }

            "git" => {
                let url_str = try_cek_to_value!(select_string(&co, &attrs, "url").await?)
                    .ok_or_else(|| ErrorKind::AttributeNotFound {
                        name: "url".into(),
                    })?;
                let url = Url::parse(&url_str)
                    .map_err(|e| ErrorKind::SnixError(Arc::new(e)))?;
                let r#ref = try_cek_to_value!(select_string(&co, &attrs, "ref").await?);
                let rev = try_cek_to_value!(select_string(&co, &attrs, "rev").await?);
                let name = try_cek_to_value!(select_string(&co, &attrs, "name").await?);

                let name = name.unwrap_or_else(|| default_fetch_name(&url));

                let all_refs = match attrs.select("allRefs") {
                    Some(v) => generators::request_force(&co, v.clone())
                        .await
                        .as_bool()?,
                    None => false,
                };
                let submodules = match attrs.select("submodules") {
                    Some(v) => generators::request_force(&co, v.clone())
                        .await
                        .as_bool()?,
                    None => false,
                };

                // Use ingest_git_and_persist so we can return the full
                // attrset with rev/shortRev/narHash (matching
                // builtin_fetch_git and CppNix fetchTree for git).
                let (store_path, path_info, resolved_rev) = state
                    .tokio_handle
                    .block_on(async {
                        state.fetcher.ingest_git_and_persist(
                            &name, &url, r#ref.as_deref(), rev.as_deref(),
                            all_refs, submodules,
                        )
                        .await
                    })
                    .map_err(|e| ErrorKind::SnixError(Arc::new(e)))?;

                let out_path = store_path.to_absolute_path();
                let short_rev: String = resolved_rev.chars().take(7).collect();
                let nar_hash_str = format!(
                    "sha256-{}",
                    nix_compat::nixbase32::encode(&path_info.nar_sha256)
                );
                let mut result: BTreeMap<String, Value> = BTreeMap::new();
                result.insert("outPath".into(), Value::Path(Box::new(out_path.into())));
                result.insert("rev".into(), Value::from(resolved_rev));
                result.insert("shortRev".into(), Value::from(short_rev));
                result.insert("narHash".into(), Value::from(nar_hash_str));
                result.insert("revCount".into(), Value::Integer(0));
                result.insert("submodules".into(), Value::Bool(submodules));

                Ok(Value::Attrs(NixAttrs::from_iter(result)))
            }

            "tarball" => {
                let url_str = try_cek_to_value!(select_string(&co, &attrs, "url").await?)
                    .ok_or_else(|| ErrorKind::AttributeNotFound {
                        name: "url".into(),
                    })?;
                let url = Url::parse(&url_str)
                    .map_err(|e| ErrorKind::SnixError(Arc::new(e)))?;
                let name = try_cek_to_value!(select_string(&co, &attrs, "name").await?);
                let name = name.unwrap_or_else(|| "source".to_owned());
                let nar_hash_raw = try_cek_to_value!(select_string(&co, &attrs, "narHash").await?);
                let exp_nar_sha256 = parse_nar_hash(nar_hash_raw.clone())?;

                let result = fetch_lazy(
                    state,
                    name,
                    Fetch::Tarball {
                        url,
                        exp_nar_sha256,
                    },
                )?;
                let out_path = match &result {
                    Value::Path(p) => Value::Path(p.clone()),
                    other => other.clone(),
                };
                let mut attrs: BTreeMap<String, Value> = BTreeMap::new();
                attrs.insert("outPath".into(), out_path);
                if let Some(hash) = nar_hash_raw {
                    attrs.insert("narHash".into(), Value::from(hash));
                }
                Ok(Value::Attrs(NixAttrs::from_iter(attrs)))
            }

            "file" | "url" => {
                let url_str = try_cek_to_value!(select_string(&co, &attrs, "url").await?)
                    .ok_or_else(|| ErrorKind::AttributeNotFound {
                        name: "url".into(),
                    })?;
                let url = Url::parse(&url_str)
                    .map_err(|e| ErrorKind::SnixError(Arc::new(e)))?;
                let name = try_cek_to_value!(select_string(&co, &attrs, "name").await?);
                let name = name.unwrap_or_else(|| default_fetch_name(&url));
                let sha256_raw =
                    try_cek_to_value!(select_string(&co, &attrs, "narHash").await?);
                let exp_hash = sha256_raw
                    .clone()
                    .map(|h| {
                        NixHash::from_str(&h, Some(HashAlgo::Sha256))
                            .map_err(|e| ErrorKind::InvalidHash(e.to_string()))
                    })
                    .transpose()?;

                let result = fetch_lazy(
                    state,
                    name,
                    Fetch::URL { url, exp_hash },
                )?;
                let out_path = match &result {
                    Value::Path(p) => Value::Path(p.clone()),
                    other => other.clone(),
                };
                let mut attrs: BTreeMap<String, Value> = BTreeMap::new();
                attrs.insert("outPath".into(), out_path);
                if let Some(hash) = sha256_raw {
                    attrs.insert("narHash".into(), Value::from(hash));
                }
                Ok(Value::Attrs(NixAttrs::from_iter(attrs)))
            }

            "path" => {
                let path_str = try_cek_to_value!(select_string(&co, &attrs, "path").await?)
                    .ok_or_else(|| ErrorKind::AttributeNotFound {
                        name: "path".into(),
                    })?;
                let name = try_cek_to_value!(select_string(&co, &attrs, "name").await?);
                let nar_hash_str =
                    try_cek_to_value!(select_string(&co, &attrs, "narHash").await?);

                let p = std::path::Path::new(&path_str);
                let imported = state
                    .import_path(p)
                    .map_err(|e| ErrorKind::SnixError(Arc::new(e)))?;

                let mut attrs: BTreeMap<String, Value> = BTreeMap::new();
                attrs.insert(
                    "outPath".into(),
                    Value::Path(Box::new(imported)),
                );
                if let Some(n) = name {
                    // The name was provided but import_path derived its own
                    // name from the filesystem.  We store the caller's name
                    // for consumers that care about the original intent.
                    attrs.insert("name".into(), Value::from(n));
                }
                if let Some(h) = nar_hash_str {
                    attrs.insert("narHash".into(), Value::from(h));
                }
                Ok(Value::Attrs(NixAttrs::from_iter(attrs)))
            }

            _ => Err(ErrorKind::NotImplemented(
                "fetchTree type not supported",
            )),
        }
    }
}
