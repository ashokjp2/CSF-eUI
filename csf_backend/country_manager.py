from csf_backend import csf_wrapper as csf

COUNTRIES = {
    "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AD": "Andorra",
    "AO": "Angola", "AR": "Argentina", "AM": "Armenia", "AU": "Australia",
    "AT": "Austria", "AZ": "Azerbaijan", "BD": "Bangladesh", "BY": "Belarus",
    "BE": "Belgium", "BJ": "Benin", "BO": "Bolivia", "BA": "Bosnia",
    "BR": "Brazil", "BG": "Bulgaria", "KH": "Cambodia", "CM": "Cameroon",
    "CA": "Canada", "CL": "Chile", "CN": "China", "CO": "Colombia",
    "CR": "Costa Rica", "HR": "Croatia", "CU": "Cuba", "CY": "Cyprus",
    "CZ": "Czech Republic", "DK": "Denmark", "DO": "Dominican Republic",
    "EC": "Ecuador", "EG": "Egypt", "SV": "El Salvador", "EE": "Estonia",
    "ET": "Ethiopia", "FI": "Finland", "FR": "France", "GE": "Georgia",
    "DE": "Germany", "GH": "Ghana", "GR": "Greece", "GT": "Guatemala",
    "HN": "Honduras", "HK": "Hong Kong", "HU": "Hungary", "IS": "Iceland",
    "IN": "India", "ID": "Indonesia", "IR": "Iran", "IQ": "Iraq",
    "IE": "Ireland", "IL": "Israel", "IT": "Italy", "JM": "Jamaica",
    "JP": "Japan", "JO": "Jordan", "KZ": "Kazakhstan", "KE": "Kenya",
    "KP": "North Korea", "KR": "South Korea", "KW": "Kuwait", "KG": "Kyrgyzstan",
    "LA": "Laos", "LV": "Latvia", "LB": "Lebanon", "LY": "Libya",
    "LT": "Lithuania", "LU": "Luxembourg", "MO": "Macau", "MK": "North Macedonia",
    "MG": "Madagascar", "MY": "Malaysia", "MX": "Mexico", "MD": "Moldova",
    "MN": "Mongolia", "ME": "Montenegro", "MA": "Morocco", "MZ": "Mozambique",
    "MM": "Myanmar", "NP": "Nepal", "NL": "Netherlands", "NZ": "New Zealand",
    "NI": "Nicaragua", "NG": "Nigeria", "NO": "Norway", "OM": "Oman",
    "PK": "Pakistan", "PA": "Panama", "PY": "Paraguay", "PE": "Peru",
    "PH": "Philippines", "PL": "Poland", "PT": "Portugal", "QA": "Qatar",
    "RO": "Romania", "RU": "Russia", "SA": "Saudi Arabia", "SN": "Senegal",
    "RS": "Serbia", "SG": "Singapore", "SK": "Slovakia", "SI": "Slovenia",
    "ZA": "South Africa", "ES": "Spain", "LK": "Sri Lanka", "SD": "Sudan",
    "SE": "Sweden", "CH": "Switzerland", "SY": "Syria", "TW": "Taiwan",
    "TJ": "Tajikistan", "TZ": "Tanzania", "TH": "Thailand", "TN": "Tunisia",
    "TR": "Turkey", "TM": "Turkmenistan", "UG": "Uganda", "UA": "Ukraine",
    "AE": "UAE", "GB": "United Kingdom", "US": "United States",
    "UY": "Uruguay", "UZ": "Uzbekistan", "VE": "Venezuela", "VN": "Vietnam",
    "YE": "Yemen", "ZM": "Zambia", "ZW": "Zimbabwe",
}


def get_country_config():
    conf = csf.load_csf_conf()
    deny_raw = conf.get("CC_DENY", "")
    allow_raw = conf.get("CC_ALLOW", "")
    allow_smtpauth = conf.get("CC_ALLOW_SMTPAUTH", "")
    deny_ports = conf.get("CC_DENY_PORTS", "")
    allow_ports = conf.get("CC_ALLOW_PORTS", "")
    cc_lookups = conf.get("CC_LOOKUPS", "1")

    denied = [c.strip() for c in deny_raw.split(",") if c.strip()]
    allowed = [c.strip() for c in allow_raw.split(",") if c.strip()]

    denied_list = [{"code": c, "name": COUNTRIES.get(c, c)} for c in denied]
    allowed_list = [{"code": c, "name": COUNTRIES.get(c, c)} for c in allowed]

    all_countries = sorted(COUNTRIES.items(), key=lambda x: x[1])

    return {
        "denied": denied_list,
        "allowed": allowed_list,
        "deny_raw": deny_raw,
        "allow_raw": allow_raw,
        "deny_ports": deny_ports,
        "allow_ports": allow_ports,
        "cc_lookups": cc_lookups,
        "all_countries": [{"code": c, "name": n} for c, n in all_countries],
    }


def update_country_list(list_type, codes):
    """Update CC_DENY or CC_ALLOW with given country codes."""
    if list_type not in ("deny", "allow"):
        return {"success": False, "error": "Invalid list type"}

    valid_codes = [c.strip().upper() for c in codes if c.strip().upper() in COUNTRIES]
    setting = "CC_DENY" if list_type == "deny" else "CC_ALLOW"
    csf.save_csf_conf({setting: ",".join(valid_codes)})

    return {
        "success": True,
        "message": f"{setting} updated with {len(valid_codes)} countries. Restart CSF to apply.",
        "codes": valid_codes,
    }


def add_country(list_type, code):
    code = code.strip().upper()
    if code not in COUNTRIES:
        return {"success": False, "error": f"Unknown country code: {code}"}

    conf = csf.load_csf_conf()
    setting = "CC_DENY" if list_type == "deny" else "CC_ALLOW"
    current = conf.get(setting, "")
    codes = [c.strip() for c in current.split(",") if c.strip()]
    if code in codes:
        return {"success": False, "error": f"{code} is already in {setting}"}
    codes.append(code)
    csf.save_csf_conf({setting: ",".join(codes)})
    return {"success": True, "message": f"{COUNTRIES[code]} ({code}) added to {setting}. Restart CSF to apply."}


def remove_country(list_type, code):
    code = code.strip().upper()
    conf = csf.load_csf_conf()
    setting = "CC_DENY" if list_type == "deny" else "CC_ALLOW"
    current = conf.get(setting, "")
    codes = [c.strip() for c in current.split(",") if c.strip()]
    if code not in codes:
        return {"success": False, "error": f"{code} is not in {setting}"}
    codes.remove(code)
    csf.save_csf_conf({setting: ",".join(codes)})
    return {"success": True, "message": f"{COUNTRIES.get(code, code)} removed from {setting}. Restart CSF to apply."}
