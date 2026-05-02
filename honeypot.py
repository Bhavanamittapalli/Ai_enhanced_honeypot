import re

# Common malicious signatures (case-insensitive matching applied at search time)
SQLI_SIGNATURES = [
    r"\bUNION\b\s+ALL\b\s+SELECT\b",
    r"\bSELECT\b\s+.*?\s+FROM\b",
    r"\bOR\b\s+1\s*=\s*1",
    r"['\"]\s*OR\s*['\"]",
    r"\bDROP\b\s+TABLE\b"
]

XSS_SIGNATURES = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*="
]

def check_signatures(payload):
    """Check if the payload matches any known malicious signatures."""
    if not payload:
        return False, []
    
    payload_str = str(payload)
    matched_sigs = []
    
    for sig in SQLI_SIGNATURES:
        if re.search(sig, payload_str, re.IGNORECASE):
            matched_sigs.append("SQLi")
            break
            
    for sig in XSS_SIGNATURES:
        if re.search(sig, payload_str, re.IGNORECASE):
            matched_sigs.append("XSS")
            break
            
    return len(matched_sigs) > 0, matched_sigs

def analyze_request(ip, headers, form_data=None, query_args=None):
    """
    Hybrid Detection Engine:
    Converts request data into numeric features and checks for signatures.
    Returns: (feature_vector, has_signature, matched_sigs)
    """
    # 1. Signature Checker
    has_sig_form, sigs_form = check_signatures(form_data)
    has_sig_args, sigs_args = check_signatures(query_args)
    has_sig_headers, sigs_headers = check_signatures(headers)
    
    all_sigs = list(set(sigs_form + sigs_args + sigs_headers))
    has_signature = has_sig_form or has_sig_args or has_sig_headers
    
    # 2. Behavioral Features for AI Model
    # We build a basic feature vector: [num_headers, has_user_agent, has_curl, payload_length]
    headers_str = str(headers).lower()
    payload_len = len(str(form_data)) + len(str(query_args)) if form_data or query_args else 0
    
    feature_vector = [
        len(headers),
        1 if "user-agent" in headers_str else 0,
        1 if "curl" in headers_str or "postman" in headers_str else 0,
        payload_len
    ]
    
    return feature_vector, has_signature, all_sigs
