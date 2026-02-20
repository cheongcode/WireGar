use anyhow::Result;
use serde::Deserialize;

use crate::models::*;

pub struct ThreatIntelClient {
    http: reqwest::Client,
    vt_key: Option<String>,
    abuse_key: Option<String>,
    shodan_key: Option<String>,
}

impl ThreatIntelClient {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            vt_key: std::env::var("VIRUSTOTAL_API_KEY").ok().filter(|s| !s.is_empty()),
            abuse_key: std::env::var("ABUSEIPDB_API_KEY").ok().filter(|s| !s.is_empty()),
            shodan_key: std::env::var("SHODAN_API_KEY").ok().filter(|s| !s.is_empty()),
        }
    }

    pub fn has_any_key(&self) -> bool {
        self.vt_key.is_some() || self.abuse_key.is_some() || self.shodan_key.is_some()
    }

    pub async fn enrich_iocs(&self, iocs: &[Ioc]) -> Vec<IocEnrichment> {
        let mut results = Vec::new();

        for ioc in iocs {
            let enrichment = match ioc.kind {
                IocKind::IpAddress => self.enrich_ip(&ioc.id, &ioc.value).await,
                IocKind::Domain => self.enrich_domain(&ioc.id, &ioc.value).await,
                IocKind::FileHash => self.enrich_hash(&ioc.id, &ioc.value).await,
                _ => Ok(IocEnrichment {
                    ioc_id: ioc.id.clone(),
                    ioc_value: ioc.value.clone(),
                    reputation_score: None,
                    is_malicious: None,
                    tags: vec![],
                    geo: None,
                    whois: None,
                    sources: vec![],
                }),
            };

            if let Ok(e) = enrichment {
                results.push(e);
            }
        }

        results
    }

    async fn enrich_ip(&self, ioc_id: &str, ip: &str) -> Result<IocEnrichment> {
        let mut sources = Vec::new();
        let mut tags = Vec::new();
        let mut max_score: Option<i32> = None;
        let mut malicious = false;

        let geo = self.geoip_lookup(ip).await.ok();

        let whois = self.whois_lookup(ip).await.ok();

        if let Some(ref key) = self.abuse_key {
            if let Ok(abuse) = self.query_abuseipdb(ip, key).await {
                let score = abuse.confidence_score;
                if score > 50 { malicious = true; }
                if score > 0 { tags.push("reported".into()); }
                sources.push(EnrichmentSource {
                    provider: "abuseipdb".into(),
                    score: Some(score),
                    details: format!("Abuse confidence: {}%, {} reports, ISP: {}",
                        score, abuse.total_reports, abuse.isp.as_deref().unwrap_or("-")),
                    link: Some(format!("https://www.abuseipdb.com/check/{}", ip)),
                });
                max_score = Some(score);
            }
        }

        if let Some(ref key) = self.vt_key {
            if let Ok(vt) = self.query_virustotal_ip(ip, key).await {
                let m = vt.malicious;
                let total = vt.malicious + vt.harmless + vt.suspicious + vt.undetected;
                if m > 3 { malicious = true; tags.push("malware".into()); }
                let vt_score = if total > 0 { (m as f64 / total as f64 * 100.0) as i32 } else { 0 };
                sources.push(EnrichmentSource {
                    provider: "virustotal".into(),
                    score: Some(vt_score),
                    details: format!("{}/{} engines flagged malicious", m, total),
                    link: Some(format!("https://www.virustotal.com/gui/ip-address/{}", ip)),
                });
                max_score = Some(max_score.map_or(vt_score, |s: i32| s.max(vt_score)));
            }
        }

        if let Some(ref key) = self.shodan_key {
            if let Ok(shodan) = self.query_shodan(ip, key).await {
                let port_str = shodan.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
                if !shodan.vulns.is_empty() { tags.push("vulnerable".into()); }
                sources.push(EnrichmentSource {
                    provider: "shodan".into(),
                    score: None,
                    details: format!("Ports: [{}], OS: {}, Vulns: {}",
                        port_str,
                        shodan.os.as_deref().unwrap_or("-"),
                        if shodan.vulns.is_empty() { "none".into() } else { shodan.vulns.join(", ") }),
                    link: Some(format!("https://www.shodan.io/host/{}", ip)),
                });
            }
        }

        if let Ok(otx) = self.query_otx_ip(ip).await {
            if otx.pulse_count > 0 {
                tags.push("otx_flagged".into());
                if otx.pulse_count > 5 { malicious = true; }
            }
            sources.push(EnrichmentSource {
                provider: "otx".into(),
                score: Some(std::cmp::min(otx.pulse_count as i32 * 10, 100)),
                details: format!("{} OTX pulses, reputation: {}", otx.pulse_count, otx.reputation),
                link: Some(format!("https://otx.alienvault.com/indicator/ip/{}", ip)),
            });
        }

        Ok(IocEnrichment {
            ioc_id: ioc_id.to_string(),
            ioc_value: ip.to_string(),
            reputation_score: max_score,
            is_malicious: Some(malicious),
            tags,
            geo,
            whois,
            sources,
        })
    }

    async fn enrich_domain(&self, ioc_id: &str, domain: &str) -> Result<IocEnrichment> {
        let mut sources = Vec::new();
        let mut tags = Vec::new();
        let mut malicious = false;

        if let Some(ref key) = self.vt_key {
            if let Ok(vt) = self.query_virustotal_domain(domain, key).await {
                let m = vt.malicious;
                let total = vt.malicious + vt.harmless + vt.suspicious + vt.undetected;
                if m > 3 { malicious = true; tags.push("malware".into()); }
                sources.push(EnrichmentSource {
                    provider: "virustotal".into(),
                    score: Some(if total > 0 { (m as f64 / total as f64 * 100.0) as i32 } else { 0 }),
                    details: format!("{}/{} engines flagged malicious", m, total),
                    link: Some(format!("https://www.virustotal.com/gui/domain/{}", domain)),
                });
            }
        }

        if let Ok(otx) = self.query_otx_domain(domain).await {
            if otx.pulse_count > 0 { tags.push("otx_flagged".into()); }
            sources.push(EnrichmentSource {
                provider: "otx".into(),
                score: Some(std::cmp::min(otx.pulse_count as i32 * 10, 100)),
                details: format!("{} OTX pulses", otx.pulse_count),
                link: Some(format!("https://otx.alienvault.com/indicator/domain/{}", domain)),
            });
        }

        Ok(IocEnrichment {
            ioc_id: ioc_id.to_string(),
            ioc_value: domain.to_string(),
            reputation_score: None,
            is_malicious: Some(malicious),
            tags,
            geo: None,
            whois: None,
            sources,
        })
    }

    async fn enrich_hash(&self, ioc_id: &str, hash: &str) -> Result<IocEnrichment> {
        let mut sources = Vec::new();
        let mut tags = Vec::new();
        let mut malicious = false;

        if let Some(ref key) = self.vt_key {
            if let Ok(vt) = self.query_virustotal_hash(hash, key).await {
                let m = vt.malicious;
                let total = vt.malicious + vt.harmless + vt.suspicious + vt.undetected;
                if m > 0 { malicious = true; tags.push("malware".into()); }
                sources.push(EnrichmentSource {
                    provider: "virustotal".into(),
                    score: Some(if total > 0 { (m as f64 / total as f64 * 100.0) as i32 } else { 0 }),
                    details: format!("{}/{} detections", m, total),
                    link: Some(format!("https://www.virustotal.com/gui/file/{}", hash)),
                });
            }
        }

        Ok(IocEnrichment {
            ioc_id: ioc_id.to_string(),
            ioc_value: hash.to_string(),
            reputation_score: None,
            is_malicious: Some(malicious),
            tags,
            geo: None,
            whois: None,
            sources,
        })
    }

    pub async fn geoip_lookup(&self, ip: &str) -> Result<GeoInfo> {
        let url = format!("http://ip-api.com/json/{}?fields=status,country,countryCode,regionName,city,as,org,lat,lon", ip);
        let resp: serde_json::Value = self.http.get(&url).send().await?.json().await?;

        if resp["status"].as_str() != Some("success") {
            anyhow::bail!("geoip lookup failed for {}", ip);
        }

        Ok(GeoInfo {
            country: resp["country"].as_str().map(String::from),
            country_code: resp["countryCode"].as_str().map(|s| s.to_lowercase()),
            city: resp["city"].as_str().map(String::from),
            region: resp["regionName"].as_str().map(String::from),
            asn: resp["as"].as_str().map(String::from),
            org: resp["org"].as_str().map(String::from),
            lat: resp["lat"].as_f64(),
            lon: resp["lon"].as_f64(),
        })
    }

    async fn whois_lookup(&self, ip: &str) -> Result<WhoisInfo> {
        let url = format!("https://rdap.org/ip/{}", ip);
        let resp: serde_json::Value = self.http.get(&url).send().await?.json().await?;

        Ok(WhoisInfo {
            name: resp["name"].as_str().map(String::from),
            org: resp["entities"].as_array()
                .and_then(|e| e.first())
                .and_then(|e| e["vcardArray"].as_array())
                .and_then(|v| v.get(1))
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.iter().find(|e| e[0].as_str() == Some("org")))
                .and_then(|e| e[3].as_str())
                .map(String::from),
            country: resp["country"].as_str().map(String::from),
            range: resp["handle"].as_str().map(String::from),
        })
    }

    async fn query_abuseipdb(&self, ip: &str, key: &str) -> Result<AbuseIpDbResult> {
        let resp: serde_json::Value = self.http
            .get("https://api.abuseipdb.com/api/v2/check")
            .header("Key", key)
            .header("Accept", "application/json")
            .query(&[("ipAddress", ip), ("maxAgeInDays", "90")])
            .send().await?.json().await?;

        let data = &resp["data"];
        Ok(AbuseIpDbResult {
            confidence_score: data["abuseConfidenceScore"].as_i64().unwrap_or(0) as i32,
            total_reports: data["totalReports"].as_i64().unwrap_or(0) as i32,
            isp: data["isp"].as_str().map(String::from),
        })
    }

    async fn query_virustotal_ip(&self, ip: &str, key: &str) -> Result<VtAnalysisStats> {
        let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ip);
        let resp: serde_json::Value = self.http.get(&url)
            .header("x-apikey", key).send().await?.json().await?;
        parse_vt_stats(&resp["data"]["attributes"]["last_analysis_stats"])
    }

    async fn query_virustotal_domain(&self, domain: &str, key: &str) -> Result<VtAnalysisStats> {
        let url = format!("https://www.virustotal.com/api/v3/domains/{}", domain);
        let resp: serde_json::Value = self.http.get(&url)
            .header("x-apikey", key).send().await?.json().await?;
        parse_vt_stats(&resp["data"]["attributes"]["last_analysis_stats"])
    }

    async fn query_virustotal_hash(&self, hash: &str, key: &str) -> Result<VtAnalysisStats> {
        let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);
        let resp: serde_json::Value = self.http.get(&url)
            .header("x-apikey", key).send().await?.json().await?;
        parse_vt_stats(&resp["data"]["attributes"]["last_analysis_stats"])
    }

    async fn query_shodan(&self, ip: &str, key: &str) -> Result<ShodanResult> {
        let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, key);
        let resp: serde_json::Value = self.http.get(&url).send().await?.json().await?;

        Ok(ShodanResult {
            ports: resp["ports"].as_array().map(|a| a.iter().filter_map(|v| v.as_u64().map(|n| n as u16)).collect()).unwrap_or_default(),
            os: resp["os"].as_str().map(String::from),
            vulns: resp["vulns"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(),
        })
    }

    async fn query_otx_ip(&self, ip: &str) -> Result<OtxResult> {
        let url = format!("https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general", ip);
        let resp: serde_json::Value = self.http.get(&url).send().await?.json().await?;
        Ok(OtxResult {
            pulse_count: resp["pulse_info"]["count"].as_u64().unwrap_or(0) as usize,
            reputation: resp["reputation"].as_i64().unwrap_or(0) as i32,
        })
    }

    async fn query_otx_domain(&self, domain: &str) -> Result<OtxResult> {
        let url = format!("https://otx.alienvault.com/api/v1/indicators/domain/{}/general", domain);
        let resp: serde_json::Value = self.http.get(&url).send().await?.json().await?;
        Ok(OtxResult {
            pulse_count: resp["pulse_info"]["count"].as_u64().unwrap_or(0) as usize,
            reputation: resp["reputation"].as_i64().unwrap_or(0) as i32,
        })
    }
}

fn parse_vt_stats(stats: &serde_json::Value) -> Result<VtAnalysisStats> {
    Ok(VtAnalysisStats {
        malicious: stats["malicious"].as_u64().unwrap_or(0) as u32,
        suspicious: stats["suspicious"].as_u64().unwrap_or(0) as u32,
        harmless: stats["harmless"].as_u64().unwrap_or(0) as u32,
        undetected: stats["undetected"].as_u64().unwrap_or(0) as u32,
    })
}

#[derive(Deserialize)]
struct AbuseIpDbResult { confidence_score: i32, total_reports: i32, isp: Option<String> }
struct VtAnalysisStats { malicious: u32, suspicious: u32, harmless: u32, undetected: u32 }
struct ShodanResult { ports: Vec<u16>, os: Option<String>, vulns: Vec<String> }
struct OtxResult { pulse_count: usize, reputation: i32 }
