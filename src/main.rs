use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;
use winreg::enums::*;
use winreg::RegKey;

// ============================================================================
// CONSTANTS
// ============================================================================
const OFFLINE_SYSTEM_KEY: &str = "OFFLINE_SYSTEM";
const OFFLINE_SOFTWARE_KEY: &str = "OFFLINE_SOFTWARE";

// ============================================================================
// DATA STRUCTURES
// ============================================================================

#[derive(Serialize, Debug, Default)]
pub struct HardwareInfo {
    pub computer_name: String,
    pub model_name: String,
    pub serial_number: String,
    pub serial_reliable: bool,
    pub uuid: String,
    pub tpm_available: bool,
    pub azure_joined: bool,
}

#[derive(Serialize, Debug, Default)]
pub struct IntuneInfo {
    pub registry_found: bool,
    pub mdm_certificate: bool,
    pub enrollment_found: bool,
    pub mdm_status: bool,
    pub genuinely_unregistered: bool,
}

#[derive(Serialize, Debug, Default)]
pub struct AutopilotInfo {
    pub registry_found: bool,
    pub json_xml_file_found: bool,
    pub csp_data_found: bool,
    pub residual_metadata: bool,
}

#[derive(Serialize, Debug, Default)]
pub struct GraphApiInfo {
    pub authenticated: bool,
    pub access_token_present: bool,
    pub device_found_in_tenant: bool,
    pub tenant_id: String,
    pub tenant_metadata: String,
    pub tenant_status: String,
}

#[derive(Serialize, Debug, Default)]
pub struct AssessmentResult {
    pub risk_level: String,
    pub status: String,
    pub recommendation: String,
}

#[derive(Serialize, Debug)]
pub struct FullScanReport {
    pub scan_time: String,
    pub hardware: HardwareInfo,
    pub intune: IntuneInfo,
    pub autopilot: AutopilotInfo,
    pub graph_api: GraphApiInfo,
    pub assessment: AssessmentResult,
}

#[derive(Debug)]
pub struct TenantConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub token_base: String,
    pub graph_base: String,
}

impl TenantConfig {
    pub fn from_stdin() -> Option<Self> {
        println!("\n--- Graph API / Tenant Configuration ---");
        println!("(Press Enter on Tenant ID to skip the Graph API check)\n");

        let tenant_id = prompt("Tenant ID      : ");
        if tenant_id.is_empty() {
            println!("Skipping Graph API check.\n");
            return None;
        }

        let client_id     = prompt("Client ID      : ");
        let client_secret = prompt("Client Secret  : ");

        println!("\n(Mock server URL -- leave blank to use real Microsoft endpoints)");
        let raw_token = prompt("Token Base URL : ");
        let raw_graph = prompt("Graph Base URL : ");

        Some(TenantConfig {
            tenant_id,
            client_id,
            client_secret,
            token_base: if raw_token.is_empty() {
                "https://login.microsoftonline.com".to_string()
            } else {
                raw_token
            },
            graph_base: if raw_graph.is_empty() {
                "https://graph.microsoft.com".to_string()
            } else {
                raw_graph
            },
        })
    }
}

fn prompt(label: &str) -> String {
    print!("{}", label);
    let _ = io::stdout().flush();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap_or(0);
    buf.trim().to_string()
}

// ============================================================================
// BOOT MEDIA DETECTION
// ============================================================================
pub mod boot_media {
    pub fn drive() -> String {
        if let Ok(exe_path) = std::env::current_exe() {
            let s = exe_path.to_string_lossy().to_string();
            if s.len() >= 2 && s.as_bytes()[1] == b':' {
                return s[..2].to_string();
            }
        }
        "X:".to_string()
    }
}

// ============================================================================
// OFFLINE HIVE MOUNTING
// ============================================================================
pub mod offline_hive {
    use super::*;

    pub struct OfflineHives;

    impl OfflineHives {
        pub fn mount(os_drive: &str) -> Result<Self, String> {
            let system_hive  = format!(r"{}\Windows\System32\config\SYSTEM",   os_drive);
            let software_hive = format!(r"{}\Windows\System32\config\SOFTWARE", os_drive);

            if !Path::new(&system_hive).exists() || !Path::new(&software_hive).exists() {
                return Err(format!("Hive files not found under {}", os_drive));
            }

            run_reg(&["load", &format!(r"HKLM\{}", OFFLINE_SYSTEM_KEY),   &system_hive])?;
            if let Err(e) = run_reg(&["load", &format!(r"HKLM\{}", OFFLINE_SOFTWARE_KEY), &software_hive]) {
                let _ = run_reg(&["unload", &format!(r"HKLM\{}", OFFLINE_SYSTEM_KEY)]);
                return Err(e);
            }
            Ok(OfflineHives)
        }
    }

    impl Drop for OfflineHives {
        fn drop(&mut self) {
            let _ = run_reg(&["unload", &format!(r"HKLM\{}", OFFLINE_SOFTWARE_KEY)]);
            let _ = run_reg(&["unload", &format!(r"HKLM\{}", OFFLINE_SYSTEM_KEY)]);
        }
    }

    fn run_reg(args: &[&str]) -> Result<(), String> {
        let output = Command::new("reg.exe")
            .args(args)
            .output()
            .map_err(|e| format!("failed to run reg.exe: {}", e))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "reg.exe {:?} failed: {}",
                args,
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    pub fn find_target_os_drive() -> Result<String, String> {
        let boot_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "X:".to_string());
        for letter in b'C'..=b'Z' {
            let drive = format!("{}:", letter as char);
            let candidate = format!(r"{}\Windows\System32\config\SYSTEM", drive);
            if Path::new(&candidate).exists() && !drive.eq_ignore_ascii_case(&boot_drive) {
                return Ok(drive);
            }
        }
        Err("Could not locate an offline target OS drive".to_string())
    }

    pub fn resolve_control_set() -> Result<String, String> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let select = hklm
            .open_subkey(format!(r"{}\Select", OFFLINE_SYSTEM_KEY))
            .map_err(|e| format!("cannot open Select key: {}", e))?;
        let current: u32 = select
            .get_value("Current")
            .map_err(|e| format!("cannot read Select\\Current: {}", e))?;
        Ok(format!("ControlSet{:03}", current))
    }
}

// ============================================================================
// 1. HARDWARE MODULE
// ============================================================================
pub mod hardware_module {
    use super::*;

    pub fn scan(control_set: &str) -> HardwareInfo {
        let uuid = get_uuid();
        let (serial_number, serial_reliable) = get_serial_number();
        let model_name = get_model_name();

        HardwareInfo {
            computer_name: get_offline_computer_name(control_set)
                .unwrap_or_else(|_| "Unknown".to_string()),
            model_name,
            serial_number,
            serial_reliable,
            uuid,
            tpm_available: check_tpm_live(),
            azure_joined: check_azure_joined_offline(control_set),
        }
    }

    fn get_uuid() -> String {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey(r"SYSTEM\HardwareConfig") {
            if let Ok(uuid) = key.get_value::<String, _>("LastConfig") {
                let trimmed = uuid.trim().to_string();
                if !trimmed.is_empty() {
                    return trimmed;
                }
            }
        }
        "UNKNOWN-UUID".to_string()
    }

    fn get_serial_number() -> (String, bool) {
        if let Some(serial) = query_wmic("bios", "serialnumber") {
            return (serial, true);
        }
        ("NOT_AVAILABLE".to_string(), false)
    }

    /// Laptop/desktop model name read from wmic computersystem.
    /// Examples: "HP EliteBook 840 G8", "Dell Latitude 5520".
    fn get_model_name() -> String {
        query_wmic("computersystem", "model")
            .unwrap_or_else(|| "UNKNOWN-MODEL".to_string())
    }

    /// Generic wmic helper: runs `wmic <class> get <field>` and returns
    /// the first non-header line. Used for both serial and model.
    fn query_wmic(class: &str, field: &str) -> Option<String> {
        let output = Command::new("wmic")
            .args([class, "get", field])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let value = text
            .lines()
            .map(|l| l.trim())
            .find(|l| !l.is_empty() && !l.eq_ignore_ascii_case(field))?
            .to_string();
        if value.is_empty()
            || value.eq_ignore_ascii_case("To be filled by O.E.M.")
            || value.eq_ignore_ascii_case("System Product Name")
        {
            None
        } else {
            Some(value)
        }
    }

    fn check_tpm_live() -> bool {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        hklm.open_subkey(r"SYSTEM\CurrentControlSet\Services\TPM\Wmi").is_ok()
    }

    fn check_azure_joined_offline(control_set: &str) -> bool {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let path = format!(
            r"{}\{}\Control\CloudDomainJoin\JoinInfo",
            OFFLINE_SYSTEM_KEY, control_set
        );
        hklm.open_subkey(&path)
            .map(|k| k.enum_keys().count() > 0)
            .unwrap_or(false)
    }

    fn get_offline_computer_name(control_set: &str) -> Result<String, String> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let path = format!(
            r"{}\{}\Control\ComputerName\ComputerName",
            OFFLINE_SYSTEM_KEY, control_set
        );
        let key = hklm.open_subkey(&path).map_err(|e| e.to_string())?;
        key.get_value::<String, _>("ComputerName").map_err(|e| e.to_string())
    }
}

// ============================================================================
// 2. INTUNE SCANNER MODULE
// ============================================================================
pub mod intune_scanner {
    use super::*;

    pub fn scan() -> IntuneInfo {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let enrollments_path = format!(r"{}\Microsoft\Enrollments", OFFLINE_SOFTWARE_KEY);
        let certs_path = format!(
            r"{}\Microsoft\SystemCertificates\My\Certificates",
            OFFLINE_SOFTWARE_KEY
        );

        let registry_found = hklm.open_subkey(&enrollments_path).is_ok();
        let mdm_certificate = hklm
            .open_subkey(&certs_path)
            .map(|key| key.enum_keys().count() > 0)
            .unwrap_or(false);

        let mut enrollment_found = false;
        let mut mdm_status = false;

        if let Ok(enrollments) = hklm.open_subkey(&enrollments_path) {
            for subkey_name in enrollments.enum_keys().filter_map(Result::ok) {
                if let Ok(subkey) = enrollments.open_subkey(&subkey_name) {
                    if let Ok(url) = subkey.get_value::<String, _>("DiscoveryServiceServerUrl") {
                        if url.to_lowercase().contains("manage.microsoft.com") {
                            enrollment_found = true;
                            mdm_status = true;
                            break;
                        }
                    }
                }
            }
        }

        let genuinely_unregistered =
            !(registry_found || mdm_certificate || enrollment_found || mdm_status);

        IntuneInfo {
            registry_found,
            mdm_certificate,
            enrollment_found,
            mdm_status,
            genuinely_unregistered,
        }
    }
}

// ============================================================================
// 3. AUTOPILOT SCANNER MODULE
// ============================================================================
pub mod autopilot_scanner {
    use super::*;

    pub fn scan(os_drive: &str) -> AutopilotInfo {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

        let registry_found = hklm
            .open_subkey(format!(
                r"{}\Microsoft\Provisioning\Diagnostics\Autopilot",
                OFFLINE_SOFTWARE_KEY
            ))
            .is_ok();

        let json_path = format!(
            r"{}\Windows\Provisioning\Autopilot\AutoPilotConfigurationFile.json",
            os_drive
        );
        let json_xml_file_found = Path::new(&json_path).exists();

        let csp_data_found = hklm
            .open_subkey(format!(
                r"{}\Microsoft\PolicyManager\current\device\Autopilot",
                OFFLINE_SOFTWARE_KEY
            ))
            .is_ok();

        let residual_metadata = hklm
            .open_subkey(format!(r"{}\Microsoft\Windows\Autopilot", OFFLINE_SOFTWARE_KEY))
            .is_ok();

        AutopilotInfo {
            registry_found,
            json_xml_file_found,
            csp_data_found,
            residual_metadata,
        }
    }
}

// ============================================================================
// 4. GRAPH API MODULE
// ============================================================================
pub mod graph_api_module {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
    }

    #[derive(Deserialize)]
    struct AutopilotDeviceList {
        value: Vec<AutopilotDeviceEntry>,
    }

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct AutopilotDeviceEntry {
        id: String,
        #[serde(rename = "groupTag")]
        group_tag: Option<String>,
    }

    pub fn scan(
        serial: &str,
        serial_reliable: bool,
        has_autopilot_trace: bool,
        tenant: Option<&TenantConfig>,
    ) -> GraphApiInfo {
        if !has_autopilot_trace {
            return GraphApiInfo {
                authenticated: false,
                access_token_present: false,
                device_found_in_tenant: false,
                tenant_id: "N/A".to_string(),
                tenant_metadata: "Skipped -- no local Autopilot trace found".to_string(),
                tenant_status: "Not Checked (Clean Locally)".to_string(),
            };
        }

        let Some(tenant) = tenant else {
            return GraphApiInfo {
                authenticated: false,
                access_token_present: false,
                device_found_in_tenant: false,
                tenant_id: "N/A".to_string(),
                tenant_metadata: "No tenant credentials configured".to_string(),
                tenant_status: "Cannot Verify -- Missing Config".to_string(),
            };
        };

        if !serial_reliable {
            return GraphApiInfo {
                authenticated: false,
                access_token_present: false,
                device_found_in_tenant: false,
                tenant_id: tenant.tenant_id.clone(),
                tenant_metadata: "Serial number unreliable -- cannot query Graph API safely"
                    .to_string(),
                tenant_status: "Cannot Verify -- Unreliable Serial".to_string(),
            };
        }

        match query_graph(serial, tenant) {
            Ok(found) => GraphApiInfo {
                authenticated: true,
                access_token_present: true,
                device_found_in_tenant: found,
                tenant_id: tenant.tenant_id.clone(),
                tenant_metadata: if found {
                    "Serial matches an active Autopilot registration in this tenant".to_string()
                } else {
                    "Serial not found in tenant Autopilot registrations".to_string()
                },
                tenant_status: if found {
                    "Still Registered".to_string()
                } else {
                    "Not Registered".to_string()
                },
            },
            Err(e) => GraphApiInfo {
                authenticated: false,
                access_token_present: false,
                device_found_in_tenant: false,
                tenant_id: tenant.tenant_id.clone(),
                tenant_metadata: format!("Graph API check failed: {}", e),
                tenant_status: "Error / Unverified".to_string(),
            },
        }
    }

    fn query_graph(serial: &str, tenant: &TenantConfig) -> Result<bool, String> {
        let client = reqwest::blocking::Client::new();

        let token_url = format!(
            "{}/{}/oauth2/v2.0/token",
            tenant.token_base, tenant.tenant_id
        );
        let params = [
            ("client_id",     tenant.client_id.as_str()),
            ("client_secret", tenant.client_secret.as_str()),
            ("scope",         "https://graph.microsoft.com/.default"),
            ("grant_type",    "client_credentials"),
        ];

        let token_resp: TokenResponse = client
            .post(&token_url)
            .form(&params)
            .send()
            .map_err(|e| format!("token request failed: {}", e))?
            .error_for_status()
            .map_err(|e| format!("token request rejected: {}", e))?
            .json()
            .map_err(|e| format!("token response parse failed: {}", e))?;

        let filter = format!("contains(serialNumber,'{}')", serial.replace('\'', ""));
        let url = format!(
            "{}/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities?$filter={}",
            tenant.graph_base,
            urlencode(&filter)
        );

        let devices: AutopilotDeviceList = client
            .get(&url)
            .bearer_auth(&token_resp.access_token)
            .send()
            .map_err(|e| format!("graph query failed: {}", e))?
            .error_for_status()
            .map_err(|e| format!("graph query rejected: {}", e))?
            .json()
            .map_err(|e| format!("graph response parse failed: {}", e))?;

        Ok(!devices.value.is_empty())
    }

    fn urlencode(s: &str) -> String {
        s.replace(' ',  "%20")
         .replace('\'', "%27")
         .replace(',',  "%2C")
         .replace('(',  "%28")
         .replace(')',  "%29")
    }
}

// ============================================================================
// 5. ASSESSMENT MODULE
// ============================================================================
pub mod assessment_module {
    use super::*;

    pub fn evaluate(
        intune: &IntuneInfo,
        autopilot: &AutopilotInfo,
        graph: &GraphApiInfo,
    ) -> AssessmentResult {
        let has_autopilot_trace =
            autopilot.registry_found || autopilot.json_xml_file_found || autopilot.residual_metadata;
        let has_intune_trace  = !intune.genuinely_unregistered;
        let confirmed_in_tenant = graph.device_found_in_tenant;

        let (risk_level, status, recommendation) = if !has_autopilot_trace && !has_intune_trace {
            (
                "CLEAN".to_string(),
                "READY FOR RENTAL / RESALE".to_string(),
                "No Autopilot or Intune traces found. Device is genuinely unregistered. Safe for deployment or sale.".to_string(),
            )
        } else {
            let mut rec = String::from("Action required before deployment/sale:\n");
            if has_intune_trace {
                rec.push_str("- Delete device profile from Intune portal (device is NOT genuinely unregistered).\n");
            }
            if has_autopilot_trace {
                rec.push_str("- Deregister device serial number from Tenant Autopilot deployment.\n");
            }
            if confirmed_in_tenant {
                rec.push_str(&format!(
                    "- CONFIRMED via Graph API: device is still actively registered to tenant {}.\n",
                    graph.tenant_id
                ));
            }
            (
                "RISK".to_string(),
                "NOT READY FOR RENTAL / RESALE".to_string(),
                rec,
            )
        };

        AssessmentResult {
            risk_level,
            status,
            recommendation,
        }
    }
}

// ============================================================================
// 6. REPORT MODULE
// ============================================================================
pub mod report_module {
    use super::*;

    fn sanitize_for_filename(s: &str) -> String {
        let cleaned: String = s
            .chars()
            .map(|c| match c {
                '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
                c if c.is_whitespace() => '_',
                c => c,
            })
            .collect();
        if cleaned.is_empty() { "UNKNOWN".to_string() } else { cleaned }
    }

    pub fn generate_reports(report: &FullScanReport, output_dir: &str) {
        print_console(report);
        let _ = fs::create_dir_all(output_dir);

        let file_timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
        let serial_part = sanitize_for_filename(&report.hardware.serial_number);
        let base_name   = format!("report_{}_{}", serial_part, file_timestamp);

        if let Ok(json) = serde_json::to_string_pretty(report) {
            let path = format!(r"{}\{}.json", output_dir, base_name);
            match fs::write(&path, json) {
                Ok(_)  => println!("JSON Report Saved -> {}", path),
                Err(e) => eprintln!("Could not save JSON report: {}", e),
            }
        }

        save_html(report, output_dir, &base_name);
        save_csv(report, output_dir, &base_name);
    }

    fn print_console(report: &FullScanReport) {
        println!("\n==============================================");
        println!("           AUTOPILOT SCANNER REPORT           ");
        println!("==============================================");
        println!("Computer Name   : {}", report.hardware.computer_name);
        println!("Model           : {}", report.hardware.model_name);
        println!(
            "Serial Number   : {} (reliable: {})",
            report.hardware.serial_number, report.hardware.serial_reliable
        );
        println!("UUID            : {}", report.hardware.uuid);
        println!("TPM Available   : {}", report.hardware.tpm_available);
        println!("Azure Joined    : {}", report.hardware.azure_joined);
        println!(
            "Intune Status   : {}",
            if report.intune.genuinely_unregistered {
                "Genuinely Unregistered"
            } else {
                "NOT Genuinely Unregistered (traces found)"
            }
        );
        println!("Tenant Status   : {}", report.graph_api.tenant_status);
        println!("Risk Level      : {}", report.assessment.risk_level);
        println!("Status          : {}", report.assessment.status);
        println!("Recommendation  : {}", report.assessment.recommendation);
        println!("==============================================\n");
    }

    fn html_escape(s: &str) -> String {
        s.replace('&', "&amp;")
         .replace('<', "&lt;")
         .replace('>', "&gt;")
         .replace('"', "&quot;")
    }

    fn save_html(report: &FullScanReport, output_dir: &str, base_name: &str) {
        let intune_status_text = if report.intune.genuinely_unregistered {
            "Genuinely Unregistered"
        } else {
            "NOT Genuinely Unregistered (traces found)"
        };

        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Enterprise Scan Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 30px; background: #f8f9fa; }}
        h1 {{ color: #1a73e8; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #dee2e6; padding: 12px; text-align: left; }}
        th {{ background: #e9ecef; }}
    </style>
</head>
<body>
    <h1>Diagnostic Report</h1>
    <div class="card">
        <h2>Summary</h2>
        <p><strong>Scan Time:</strong> {}</p>
        <p><strong>Risk Level:</strong> {}</p>
        <p><strong>Status:</strong> {}</p>
        <p><strong>Recommendation:</strong><br>{}</p>
    </div>
    <div class="card">
        <h2>Hardware Details</h2>
        <table>
            <tr><th>Computer Name</th><td>{}</td></tr>
            <tr><th>Model</th><td>{}</td></tr>
            <tr><th>Serial Number</th><td>{} (reliable: {})</td></tr>
            <tr><th>UUID</th><td>{}</td></tr>
            <tr><th>TPM Available</th><td>{}</td></tr>
            <tr><th>Azure AD Joined</th><td>{}</td></tr>
        </table>
    </div>
    <div class="card">
        <h2>Intune & Autopilot Status</h2>
        <table>
            <tr><th>Intune Status Check</th><td><strong>{}</strong></td></tr>
            <tr><th>Autopilot Registry</th><td>{}</td></tr>
            <tr><th>Enrollment Registry</th><td>{}</td></tr>
            <tr><th>Intune Enrolled</th><td>{}</td></tr>
            <tr><th>MDM Certificate</th><td>{}</td></tr>
        </table>
    </div>
    <div class="card">
        <h2>Graph API / Tenant Information</h2>
        <table>
            <tr><th>Tenant ID</th><td>{}</td></tr>
            <tr><th>Tenant Metadata</th><td>{}</td></tr>
            <tr><th>Tenant Status</th><td>{}</td></tr>
            <tr><th>Authenticated</th><td>{}</td></tr>
        </table>
    </div>
</body>
</html>"#,
            html_escape(&report.scan_time),
            html_escape(&report.assessment.risk_level),
            html_escape(&report.assessment.status),
            html_escape(&report.assessment.recommendation).replace('\n', "<br>"),
            html_escape(&report.hardware.computer_name),
            html_escape(&report.hardware.model_name),
            html_escape(&report.hardware.serial_number),
            report.hardware.serial_reliable,
            html_escape(&report.hardware.uuid),
            report.hardware.tpm_available,
            report.hardware.azure_joined,
            intune_status_text,
            report.autopilot.registry_found,
            report.intune.registry_found,
            report.intune.mdm_status,
            report.intune.mdm_certificate,
            html_escape(&report.graph_api.tenant_id),
            html_escape(&report.graph_api.tenant_metadata),
            html_escape(&report.graph_api.tenant_status),
            report.graph_api.authenticated
        );

        let path = format!(r"{}\{}.html", output_dir, base_name);
        match fs::write(&path, html) {
            Ok(_)  => println!("HTML Report Saved -> {}", path),
            Err(e) => eprintln!("Could not save HTML report: {}", e),
        }
    }

    fn csv_field(s: &str) -> String {
        format!("\"{}\"", s.replace('"', "\"\""))
    }

    fn save_csv(report: &FullScanReport, output_dir: &str, base_name: &str) {
        let intune_status_text = if report.intune.genuinely_unregistered {
            "Genuinely Unregistered"
        } else {
            "NOT Genuinely Unregistered (traces found)"
        };

        let csv_data = format!(
            "Property,Value\n\
             Computer Name,{}\n\
             Model,{}\n\
             Serial Number,{}\n\
             Serial Reliable,{}\n\
             UUID,{}\n\
             TPM Available,{}\n\
             Azure AD Joined,{}\n\
             Intune Status Check,{}\n\
             Tenant ID,{}\n\
             Tenant Metadata,{}\n\
             Tenant Status,{}\n\
             Risk Level,{}\n\
             Status,{}\n\
             Scan Time,{}\n",
            csv_field(&report.hardware.computer_name),
            csv_field(&report.hardware.model_name),
            csv_field(&report.hardware.serial_number),
            report.hardware.serial_reliable,
            csv_field(&report.hardware.uuid),
            report.hardware.tpm_available,
            report.hardware.azure_joined,
            csv_field(intune_status_text),
            csv_field(&report.graph_api.tenant_id),
            csv_field(&report.graph_api.tenant_metadata),
            csv_field(&report.graph_api.tenant_status),
            csv_field(&report.assessment.risk_level),
            csv_field(&report.assessment.status),
            csv_field(&report.scan_time),
        );

        let path = format!(r"{}\{}.csv", output_dir, base_name);
        match fs::write(&path, csv_data) {
            Ok(_)  => println!("CSV Report Saved  -> {}", path),
            Err(e) => eprintln!("Could not save CSV report: {}", e),
        }
    }
}

// ============================================================================
// MAIN PIPELINE
// ============================================================================
fn main() {
    println!("Starting Enterprise Diagnostics Pipeline...\n");

    let own_drive = boot_media::drive();
    println!("Boot media drive detected: {}", own_drive);

    let os_drive = match offline_hive::find_target_os_drive() {
        Ok(drive) => drive,
        Err(e) => { eprintln!("FATAL: {}", e); std::process::exit(1); }
    };
    println!("Target OS drive detected: {}", os_drive);

    let _hives = match offline_hive::OfflineHives::mount(&os_drive) {
        Ok(h)  => h,
        Err(e) => { eprintln!("FATAL: could not mount offline hives: {}", e); std::process::exit(1); }
    };

    let control_set = match offline_hive::resolve_control_set() {
        Ok(cs) => cs,
        Err(e) => { eprintln!("FATAL: could not resolve ControlSet: {}", e); std::process::exit(1); }
    };

    let hardware  = hardware_module::scan(&control_set);
    let intune    = intune_scanner::scan();
    let autopilot = autopilot_scanner::scan(&os_drive);

    let has_autopilot_trace =
        autopilot.registry_found || autopilot.json_xml_file_found || autopilot.residual_metadata;

    // TEST-ONLY: set FORCE_GRAPH_CHECK=1 to test against a mock server.
    // Remove before production shipping.
    let has_autopilot_trace = has_autopilot_trace
        || std::env::var("FORCE_GRAPH_CHECK").map(|v| v == "1").unwrap_or(false);

    let tenant_config = if has_autopilot_trace {
        TenantConfig::from_stdin()
    } else {
        None
    };

    let graph_api = graph_api_module::scan(
        &hardware.serial_number,
        hardware.serial_reliable,
        has_autopilot_trace,
        tenant_config.as_ref(),
    );

    let assessment = assessment_module::evaluate(&intune, &autopilot, &graph_api);

    let report = FullScanReport {
        scan_time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        hardware,
        intune,
        autopilot,
        graph_api,
        assessment,
    };

    let output_dir = format!(r"{}\Diagnostics\Results", own_drive);
    report_module::generate_reports(&report, &output_dir);
    // `_hives` unloads the offline hives on drop.
}