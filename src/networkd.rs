use std::{collections::HashMap, fs::read_dir};

use ini::Ini;

pub fn get_networkd_devices(directory: &str) -> HashMap<String, String> {
    let mut devices = HashMap::new();

    // Find all files in the directory that end with .netdev
    let entries = read_dir(directory).unwrap();

    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };

        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("netdev") {
            // Parse the netdev file and get the name of the device
            let Ok(conf) = Ini::load_from_file(&path) else {
                continue;
            };

            // Find the NetDev section for the device name
            if let Some(device_name) = conf.get_from(Some("NetDev"), "Name") {
                devices.insert(device_name.into(), path.to_string_lossy().to_string());
            }
        }
    }
    devices
}
