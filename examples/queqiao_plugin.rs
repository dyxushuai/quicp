//! Install the bounded Queqiao-inspired shared-path controller.

use quicp::{PluginRegistry, QueqiaoConfig, QueqiaoPlugin};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = QueqiaoPlugin::new(QueqiaoConfig {
        erasure_floor_ppm: 420_000,
        pacing_rate_bytes_per_second: Some(100_000_000),
        ..QueqiaoConfig::default()
    })?;
    let mut registry = PluginRegistry::new();
    registry.register(plugin)?;
    let options = registry.build_transport_options()?;
    println!("installed Queqiao transport policy: {options:?}");
    Ok(())
}
