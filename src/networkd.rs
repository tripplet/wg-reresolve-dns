use std::{collections::HashMap, fs::read_dir};

use ini::Ini;

/// Get all network devices from the specified directory.
///
/// Returns a HashMap where the key is the device name and the value is the path to the netdev file.
pub fn get_networkd_devices(directory: &str) -> HashMap<String, String> {
    let mut devices = HashMap::new();

    // Find all files in the directory that end with .netdev
    let Ok(entries) = read_dir(directory) else {
        return devices;
    };

    for path in entries.flatten().map(|entry| entry.path()) {
        if path.extension().and_then(|s| s.to_str()) != Some("netdev") {
            continue;
        }

        // Parse the netdev file and get the name of the device
        let Ok(conf) = Ini::load_from_file(&path) else {
            continue;
        };

        // Find the NetDev section for the device name
        if let Some(device_name) = conf.get_from(Some("NetDev"), "Name") {
            devices.insert(device_name.into(), path.to_string_lossy().to_string());
        }
    }
    devices
}
