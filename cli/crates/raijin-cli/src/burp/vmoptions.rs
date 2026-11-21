//! Burp's JVM options for a direct `java` launch, read the way install4j reads them.

use std::path::{Path, PathBuf};

const MAX_INCLUDE_DEPTH: usize = 8;

/// Options from `roots` (following `-include-options`), then `home_file` if it exists, with exact
/// duplicates dropped (first kept): the app and home `user.vmoptions` are often identical, and a
/// doubled `-javaagent` would load the agent twice.
pub fn collect(roots: &[PathBuf], home_file: Option<&Path>) -> Vec<String> {
    let mut out = Vec::new();
    for root in roots {
        read_into(root, &mut out, 0);
    }
    if let Some(home) = home_file {
        read_into(home, &mut out, 0);
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|line| seen.insert(line.clone()));
    out
}

fn read_into(path: &Path, out: &mut Vec<String>, depth: usize) {
    if depth > MAX_INCLUDE_DEPTH {
        return;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(include) = line.strip_prefix("-include-options") {
            let include = include.trim();
            if !include.is_empty() {
                let target = Path::new(include);
                let target = if target.is_absolute() {
                    target.to_path_buf()
                } else {
                    path.parent().unwrap_or(Path::new(".")).join(target)
                };
                read_into(&target, out, depth + 1);
            }
            continue;
        }
        // install4j-only class path edits (-classpath/a, -classpath/p) are not JVM options.
        if line.starts_with("-classpath") || !line.starts_with('-') {
            continue;
        }
        out.push(line.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn includes_recurse_missing_ones_skip_and_duplicates_collapse() {
        let dir = tempfile::tempdir().expect("temp dir");
        let app = dir.path().join("app");
        fs::create_dir_all(app.join("sub")).expect("dirs");
        fs::write(
            app.join("vmoptions.txt"),
            "# comment\n-XX:MaxRAMPercentage=50\n\n-include-options settings.vmoptions\n-include-options sub/user.vmoptions\n-classpath/a extra.jar\nnot-an-option\n",
        )
        .expect("root");
        fs::write(
            app.join("sub/user.vmoptions"),
            "  -javaagent:/x/loader.jar  \n-Dfoo=1\n-include-options ../more.vmoptions\n",
        )
        .expect("user");
        fs::write(app.join("more.vmoptions"), "-Dmore=1\n").expect("more");
        let home = dir.path().join("home.vmoptions");
        fs::write(&home, "-javaagent:/x/loader.jar\n-Dhome=1\n").expect("home");

        let options = collect(&[app.join("vmoptions.txt")], Some(&home));
        assert_eq!(
            options,
            [
                "-XX:MaxRAMPercentage=50",
                "-javaagent:/x/loader.jar",
                "-Dfoo=1",
                "-Dmore=1",
                "-Dhome=1"
            ]
        );
    }

    #[test]
    fn a_missing_home_file_is_fine() {
        assert_eq!(
            collect(&[], Some(Path::new("/nonexistent/user.vmoptions"))),
            [] as [std::string::String; 0]
        );
    }
}
