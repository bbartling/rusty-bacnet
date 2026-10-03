//! Public docs as the next release publishes them.
use super::*;

/// The contents of a public doc. `CHANGELOG.md` also gets the changelog.d/
/// fragments the next release assembles into it, since an unreleased entry
/// lives in a fragment until then.
pub(super) fn read_published_doc(path: &str) -> String {
    let mut text = read_repo_file(path);
    if path == "CHANGELOG.md" {
        let mut fragments: Vec<PathBuf> = fs::read_dir(repo_path("changelog.d"))
            .expect("changelog.d should be readable")
            .map(|entry| entry.expect("changelog.d entry should be readable").path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "md"))
            .filter(|p| p.file_name().is_some_and(|name| name != "README.md"))
            .collect();
        fragments.sort();
        for fragment in fragments {
            text.push_str(&fs::read_to_string(fragment).expect("fragment should be readable"));
        }
    }
    text
}
