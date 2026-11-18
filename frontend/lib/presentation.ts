export function verdictLabel(verdict: string) {
  switch (verdict) {
    case "phishing":
      return "Likely a scam";
    case "suspicious":
      return "Needs a closer look";
    case "benign":
      return "No clear warning signs";
    default:
      return verdict.replaceAll("_", " ");
  }
}

export function connectionReasonLabel(reason: string) {
  const labels: Record<string, string> = {
    "Domain infrastructure is present": "Websites are part of this group.",
    "IP infrastructure relationship is present":
      "Websites share a server address.",
    "TLS certificate relationship is present":
      "The websites share a security certificate.",
    "ASN/hosting relationship is present":
      "The websites may use the same hosting provider.",
    "Payment identity relationship is present":
      "A payment ID is linked to this group.",
    "Shared kit/fingerprint relationship is present":
      "The websites share a technical identifier.",
    "Brand association is present":
      "The same brand name is linked to this group.",
  };
  return labels[reason] ?? reason;
}
