// Match Rust's Ipv4Addr parser: four decimal octets, with no leading zeroes.
export const isValidIpv4 = (value) => {
  if (typeof value !== "string") return false;
  const parts = value.trim().split(".");
  return parts.length === 4 && parts.every(
    (part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255,
  );
};
