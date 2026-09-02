use anyhow::{Context, bail};
use ipnet::Ipv4Net;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SubnetMapping {
    pub mapped: Ipv4Net,
    pub actual: Ipv4Net,
}

impl FromStr for SubnetMapping {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parts = value.split(',').map(str::trim).collect::<Vec<_>>();
        if parts.len() != 2 {
            bail!("invalid subnet mapping '{value}', expected mapped_cidr,actual_cidr");
        }
        let mapped = parts[0]
            .parse::<Ipv4Net>()
            .with_context(|| format!("invalid mapped CIDR '{}'", parts[0]))?
            .trunc();
        let actual = parts[1]
            .parse::<Ipv4Net>()
            .with_context(|| format!("invalid actual CIDR '{}'", parts[1]))?
            .trunc();
        if mapped.prefix_len() != actual.prefix_len() {
            bail!("subnet mapping masks must match: {} and {}", mapped, actual);
        }
        if mapped.network() == actual.network() {
            bail!("mapped and actual networks must differ: {mapped}");
        }
        Ok(Self { mapped, actual })
    }
}

impl Display for SubnetMapping {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{},{}", self.mapped, self.actual)
    }
}

impl Serialize for SubnetMapping {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SubnetMapping {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Default)]
pub struct SubnetMappingTable {
    rules: Arc<Vec<SubnetMapping>>,
}

impl SubnetMappingTable {
    pub fn new(mut rules: Vec<SubnetMapping>) -> Self {
        rules.sort_by_key(|rule| std::cmp::Reverse(rule.mapped.prefix_len()));
        Self {
            rules: Arc::new(rules),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn forward(&self, mapped: Ipv4Addr) -> Option<Ipv4Addr> {
        self.rules
            .iter()
            .find(|rule| rule.mapped.contains(&mapped))
            .map(|rule| translate(mapped, rule.mapped, rule.actual))
    }

    pub fn reverse(&self, actual: Ipv4Addr) -> Option<Ipv4Addr> {
        self.rules
            .iter()
            .filter(|rule| rule.actual.contains(&actual))
            .max_by_key(|rule| rule.actual.prefix_len())
            .map(|rule| translate(actual, rule.actual, rule.mapped))
    }

    pub fn rules(&self) -> &[SubnetMapping] {
        &self.rules
    }
}

/// Build the canonical address space that other nodes can use to reach this exit.
/// Output ranges are interpreted in the real address space and translated through
/// the reverse (actual -> mapped) mapping before being collapsed back to CIDRs.
pub fn advertised_subnets(outputs: &[Ipv4Net], rules: &[SubnetMapping]) -> Vec<Ipv4Net> {
    let output_intervals = merged_intervals(outputs.iter().copied());
    if output_intervals.is_empty() {
        return Vec::new();
    }

    let table = SubnetMappingTable::new(rules.to_vec());
    let mut translated = Vec::new();
    for (start, end) in output_intervals {
        let mut boundaries = vec![start, end];
        for rule in rules {
            let rule_start = u32::from(rule.actual.network()) as u64;
            let rule_end = u32::from(rule.actual.broadcast()) as u64 + 1;
            if rule_start < end && rule_end > start {
                boundaries.push(rule_start.max(start));
                boundaries.push(rule_end.min(end));
            }
        }
        boundaries.sort_unstable();
        boundaries.dedup();

        for range in boundaries.windows(2) {
            let part_start = range[0];
            let part_end = range[1];
            if part_start == part_end {
                continue;
            }
            let actual = Ipv4Addr::from(part_start as u32);
            if let Some(mapped) = table.reverse(actual) {
                let mapped_start = u32::from(mapped) as u64;
                translated.push((mapped_start, mapped_start + (part_end - part_start)));
            } else {
                translated.push((part_start, part_end));
            }
        }
    }

    intervals_to_cidrs(merge_interval_list(translated))
}

fn merged_intervals(nets: impl IntoIterator<Item = Ipv4Net>) -> Vec<(u64, u64)> {
    merge_interval_list(
        nets.into_iter()
            .map(|net| {
                let net = net.trunc();
                (
                    u32::from(net.network()) as u64,
                    u32::from(net.broadcast()) as u64 + 1,
                )
            })
            .collect(),
    )
}

fn merge_interval_list(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
}

fn intervals_to_cidrs(ranges: Vec<(u64, u64)>) -> Vec<Ipv4Net> {
    let mut result = Vec::new();
    for (mut start, end) in ranges {
        while start < end {
            let alignment_bits = if start == 0 {
                32
            } else {
                (start as u32).trailing_zeros()
            };
            let remaining = end - start;
            let remaining_bits = 63 - remaining.leading_zeros();
            let host_bits = alignment_bits.min(remaining_bits).min(32);
            let prefix_len = (32 - host_bits) as u8;
            result.push(Ipv4Net::new_assert(
                Ipv4Addr::from(start as u32),
                prefix_len,
            ));
            start += 1u64 << host_bits;
        }
    }
    result
}

fn translate(ip: Ipv4Addr, from: Ipv4Net, to: Ipv4Net) -> Ipv4Addr {
    let offset = u32::from(ip) - u32::from(from.network());
    Ipv4Addr::from(u32::from(to.network()) + offset)
}

pub(crate) fn normalize_and_validate(
    rules: &mut Vec<SubnetMapping>,
    outputs: &[Ipv4Net],
) -> anyhow::Result<()> {
    for rule in rules.iter_mut() {
        if rule.mapped.prefix_len() != rule.actual.prefix_len() {
            bail!(
                "subnet mapping masks must match: {} and {}",
                rule.mapped,
                rule.actual
            );
        }
        rule.mapped = rule.mapped.trunc();
        rule.actual = rule.actual.trunc();
        if rule.mapped == rule.actual {
            bail!("mapped and actual networks must differ: {}", rule.mapped);
        }
    }
    let mut seen = HashSet::new();
    rules.retain(|rule| seen.insert(rule.clone()));

    validate_equal_prefix_conflicts(rules)?;
    validate_output_coverage(rules, outputs)?;

    let table = SubnetMappingTable::new(rules.clone());
    validate_inverse(&table, true)?;
    validate_inverse(&table, false)?;
    Ok(())
}

fn validate_equal_prefix_conflicts(rules: &[SubnetMapping]) -> anyhow::Result<()> {
    for (index, rule) in rules.iter().enumerate() {
        for other in &rules[index + 1..] {
            if rule.mapped == other.mapped && rule.actual != other.actual {
                bail!(
                    "conflicting subnet mappings for {}: {} and {}",
                    rule.mapped,
                    rule.actual,
                    other.actual
                );
            }
            if rule.actual == other.actual && rule.mapped != other.mapped {
                bail!(
                    "conflicting reverse subnet mappings for {}: {} and {}",
                    rule.actual,
                    rule.mapped,
                    other.mapped
                );
            }
        }
    }
    Ok(())
}

fn validate_output_coverage(rules: &[SubnetMapping], outputs: &[Ipv4Net]) -> anyhow::Result<()> {
    for rule in rules {
        let start = u32::from(rule.actual.network()) as u64;
        let end = u32::from(rule.actual.broadcast()) as u64;
        let mut boundaries = vec![start, end + 1];
        for output in outputs {
            let output_start = u32::from(output.network()) as u64;
            let output_end = u32::from(output.broadcast()) as u64 + 1;
            if output_start < end + 1 && output_end > start {
                boundaries.push(output_start.max(start));
                boundaries.push(output_end.min(end + 1));
            }
        }
        boundaries.sort_unstable();
        boundaries.dedup();
        for range in boundaries.windows(2) {
            if range[0] == range[1] {
                continue;
            }
            let address = Ipv4Addr::from(range[0] as u32);
            if !outputs.iter().any(|output| output.contains(&address)) {
                bail!(
                    "actual range {} is not fully covered by output routes (first uncovered address: {})",
                    rule.actual,
                    address
                );
            }
        }
    }
    Ok(())
}

fn validate_inverse(table: &SubnetMappingTable, forward: bool) -> anyhow::Result<()> {
    let mut boundaries = Vec::<u64>::new();
    for rule in table.rules() {
        let net = if forward { rule.mapped } else { rule.actual };
        boundaries.push(u32::from(net.network()) as u64);
        boundaries.push(u32::from(net.broadcast()) as u64 + 1);
    }
    boundaries.sort_unstable();
    boundaries.dedup();

    for outer in boundaries.windows(2) {
        if outer[0] == outer[1] {
            continue;
        }
        let first = Ipv4Addr::from(outer[0] as u32);
        let Some(translated_first) = (if forward {
            table.forward(first)
        } else {
            table.reverse(first)
        }) else {
            continue;
        };
        let delta = i64::from(u32::from(translated_first)) - outer[0] as i64;
        let translated_start = (outer[0] as i64 + delta) as u64;
        let translated_end = (outer[1] as i64 + delta) as u64;
        let mut inner_boundaries = vec![outer[0], outer[1]];
        for rule in table.rules() {
            let net = if forward { rule.actual } else { rule.mapped };
            for boundary in [
                u32::from(net.network()) as u64,
                u32::from(net.broadcast()) as u64 + 1,
            ] {
                if boundary > translated_start && boundary < translated_end {
                    inner_boundaries.push((boundary as i64 - delta) as u64);
                }
            }
        }
        inner_boundaries.sort_unstable();
        inner_boundaries.dedup();
        for range in inner_boundaries.windows(2) {
            let original = Ipv4Addr::from(range[0] as u32);
            let mapped = if forward {
                table.forward(original)
            } else {
                table.reverse(original)
            };
            let round_trip = mapped.and_then(|ip| {
                if forward {
                    table.reverse(ip)
                } else {
                    table.forward(ip)
                }
            });
            if round_trip != Some(original) {
                bail!(
                    "subnet mappings are not a stable bijection near {} (maps to {:?}, round trip {:?})",
                    original,
                    mapped,
                    round_trip
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_translates_subnets_and_hosts() {
        let canonical = "192.168.2.99/24,192.168.1.88/24"
            .parse::<SubnetMapping>()
            .unwrap();
        assert_eq!(canonical.to_string(), "192.168.2.0/24,192.168.1.0/24");
        let host = "192.168.2.2/32,192.168.1.3/32"
            .parse::<SubnetMapping>()
            .unwrap();
        assert_eq!(host.to_string(), "192.168.2.2/32,192.168.1.3/32");
        let table =
            SubnetMappingTable::new(vec!["192.168.2.0/24,192.168.1.0/24".parse().unwrap(), host]);
        assert_eq!(
            table.forward(Ipv4Addr::new(192, 168, 2, 2)),
            Some(Ipv4Addr::new(192, 168, 1, 3))
        );
        assert_eq!(
            table.forward(Ipv4Addr::new(192, 168, 2, 8)),
            Some(Ipv4Addr::new(192, 168, 1, 8))
        );
    }

    #[test]
    fn rejects_bad_masks_and_uncovered_ranges() {
        assert!(
            "192.168.2.0/24,192.168.1.0/25"
                .parse::<SubnetMapping>()
                .is_err()
        );
        let mut rules = vec!["192.168.2.0/24,192.168.1.0/24".parse().unwrap()];
        assert!(normalize_and_validate(&mut rules, &[]).is_err());
        normalize_and_validate(
            &mut rules,
            &[
                "192.168.1.0/25".parse().unwrap(),
                "192.168.1.128/25".parse().unwrap(),
            ],
        )
        .unwrap();
    }

    #[test]
    fn accepts_stable_longest_prefix_exception_and_rejects_ambiguous_one() {
        let outputs = ["192.168.1.0/24".parse().unwrap()];
        let mut stable = vec![
            "192.168.2.0/24,192.168.1.0/24".parse().unwrap(),
            "192.168.2.2/32,192.168.1.3/32".parse().unwrap(),
            "192.168.2.3/32,192.168.1.2/32".parse().unwrap(),
        ];
        normalize_and_validate(&mut stable, &outputs).unwrap();

        let mut unstable = vec![
            "192.168.2.0/24,192.168.1.0/24".parse().unwrap(),
            "192.168.2.2/32,192.168.1.3/32".parse().unwrap(),
        ];
        assert!(normalize_and_validate(&mut unstable, &outputs).is_err());
    }

    #[test]
    fn rejects_equal_priority_forward_and_reverse_conflicts() {
        let outputs = ["192.168.0.0/16".parse().unwrap()];
        let mut forward_conflict = vec![
            "192.168.2.0/24,192.168.1.0/24".parse().unwrap(),
            "192.168.2.0/24,192.168.3.0/24".parse().unwrap(),
        ];
        assert!(normalize_and_validate(&mut forward_conflict, &outputs).is_err());

        let mut reverse_conflict = vec![
            "192.168.2.0/24,192.168.1.0/24".parse().unwrap(),
            "192.168.3.0/24,192.168.1.0/24".parse().unwrap(),
        ];
        assert!(normalize_and_validate(&mut reverse_conflict, &outputs).is_err());
    }

    #[test]
    fn advertised_subnets_merge_outputs_and_translate_mapped_ranges() {
        let outputs = vec![
            "192.168.1.0/25".parse().unwrap(),
            "192.168.1.128/25".parse().unwrap(),
            "192.168.1.0/24".parse().unwrap(),
        ];
        assert_eq!(
            advertised_subnets(&outputs, &[]),
            vec!["192.168.1.0/24".parse().unwrap()]
        );

        let rules = vec!["192.168.2.0/25,192.168.1.0/25".parse().unwrap()];
        assert_eq!(
            advertised_subnets(&outputs, &rules),
            vec![
                "192.168.1.128/25".parse().unwrap(),
                "192.168.2.0/25".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn advertised_subnets_honor_longest_reverse_mapping_and_recollapse() {
        let outputs = vec!["192.168.1.0/24".parse().unwrap()];
        let rules = vec![
            "192.168.2.0/24,192.168.1.0/24".parse().unwrap(),
            "192.168.2.2/32,192.168.1.3/32".parse().unwrap(),
            "192.168.2.3/32,192.168.1.2/32".parse().unwrap(),
        ];
        assert_eq!(
            advertised_subnets(&outputs, &rules),
            vec!["192.168.2.0/24".parse().unwrap()]
        );
    }
}
