//! HUP-S7.5 (D-27): the sidecar's machine sampler.
use super::*;

/// Trimmed from a real `ioreg -r -d 1 -c IOAccelerator` on an Apple M-series Mac.
const IOREG: &str = r#"+-o AGXAcceleratorG14X  <class AGXAcceleratorG14X, id 0x1000008a1, registered, matched, active, busy 0 (1 ms), retain 98>
    {
      "IOClass" = "AGXAcceleratorG14X"
      "PerformanceStatistics" = {"In use system memory (driver)"=0,"Alloc system memory"=1785217024,"Tiler Utilization %"=12,"recoveryCount"=0,"lastRecoveryTime"=0,"Renderer Utilization %"=37,"TiledSceneBytes"=1310720,"Device Utilization %"=41,"SplitSceneCount"=0,"Allocated PB Size"=2228224,"In use system memory"=626458624}
      "MetalPluginName" = "AGXMetalG14X"
    }
"#;

#[test]
fn the_macos_gpu_reading_is_device_utilization() {
    assert_eq!(parse_ioreg_gpu(IOREG), Some(4_100));
    let two = format!("{IOREG}{}", IOREG.replace("=41,", "=88,"));
    assert_eq!(
        parse_ioreg_gpu(&two),
        Some(8_800),
        "the busiest accelerator"
    );
    assert_eq!(
        parse_ioreg_gpu("\"Device Utilization %\"=250"),
        Some(10_000)
    );
    assert_eq!(parse_ioreg_gpu("no accelerator here"), None);
    assert_eq!(parse_ioreg_gpu("\"Device Utilization %\"=x"), None);
}

#[test]
fn the_nvidia_gpu_reading_is_the_busiest_gpu() {
    assert_eq!(parse_nvidia_smi_gpu("12\n 87 \n"), Some(8_700));
    assert_eq!(parse_nvidia_smi_gpu("[N/A]\n"), None);
    assert_eq!(parse_nvidia_smi_gpu(""), None);
}

#[test]
fn sampling_is_on_unless_switched_off() {
    assert!(sampling_from_value(None));
    assert!(sampling_from_value(Some("1")));
    for off in ["0", "false", " OFF "] {
        assert!(!sampling_from_value(Some(off)), "{off}");
    }
}

#[test]
fn the_energy_watts_override_needs_two_sane_numbers() {
    assert_eq!(
        energy_model_from_value(Some("25, 40")),
        EnergyModel {
            cpu_watts: 25,
            gpu_watts: 40
        }
    );
    for bad in [
        None,
        Some(""),
        Some("25"),
        Some("a,b"),
        Some("-1,3"),
        Some("9999,1"),
    ] {
        assert_eq!(
            energy_model_from_value(bad),
            DEFAULT_ENERGY_MODEL,
            "{bad:?}"
        );
    }
}

#[test]
fn cpu_percent_becomes_clamped_basis_points() {
    assert_eq!(pct_to_bps(37.456), 3_746);
    assert_eq!(pct_to_bps(140.0), BPS_WHOLE);
    assert_eq!(pct_to_bps(f32::NAN), 0);
    assert_eq!(pct_to_bps(-3.0), 0);
}

/// A real read of this machine: a turn that runs a few intervals gets real CPU and RAM samples,
/// and finishing does not wait on the sampling thread.
#[test]
fn a_turn_is_sampled_from_the_real_machine() {
    let s = SystemSampler::with_interval(Duration::from_millis(200));
    let sampling = s.begin();
    std::thread::sleep(Duration::from_millis(1_100));
    let t = Instant::now();
    let peaks = sampling.finish().expect("a 1.1 s turn has samples");
    assert!(t.elapsed() < Duration::from_millis(200), "finish waited");
    assert!(peaks.samples >= 2, "{peaks:?}");
    assert!(
        peaks.ram_total_bytes > 0 && peaks.ram_used_peak_bytes > 0,
        "{peaks:?}"
    );
    assert!(peaks.ram_used_peak_bytes <= peaks.ram_total_bytes);
    assert!(peaks.cpu_peak_bps <= BPS_WHOLE && peaks.cpu_mean_bps <= peaks.cpu_peak_bps);
}

#[test]
fn a_turn_shorter_than_one_interval_is_unknown_not_zero() {
    let s = SystemSampler::with_interval(Duration::from_secs(5));
    assert_eq!(s.begin().finish(), None);
}

/// Review fix (HUP-S7.5): a turn's sampling that is dropped without `finish` (its sink went away
/// with the turn still open) stops its thread instead of reading the machine for ever.
#[test]
fn dropping_an_unfinished_sampling_stops_its_thread() {
    let s = SystemSampler::with_interval(Duration::from_millis(50));
    let sampling = s.start();
    let samples = sampling.samples.clone();
    drop(sampling);
    let deadline = Instant::now() + Duration::from_secs(3);
    while Arc::strong_count(&samples) > 1 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        Arc::strong_count(&samples),
        1,
        "the sampling thread is still running"
    );
}
