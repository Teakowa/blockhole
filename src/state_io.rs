use blockhole_core::{error::Result, models::State, state};
use std::{fs, io::Write, path::Path};

pub fn load(path: &Path) -> Result<State> {
    state::decode(&fs::read_to_string(path)?)
}

pub fn write(path: &Path, value: &State) -> Result<()> {
    let payload = state::encode(value)?;
    fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))?;
    let temporary = path.with_file_name(format!(
        ".{}.tmp",
        path.file_name().unwrap().to_string_lossy()
    ));
    {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(payload.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&temporary, path)?;
    Ok(())
}
