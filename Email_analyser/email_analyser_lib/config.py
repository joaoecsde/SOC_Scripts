"""Tunable detection lists and scoring settings.

Everything an analyst may want to adjust lives here, so detection can be
tuned without touching the logic. All values are lowercase.

Assumption: these lists are a practical starting point, not complete
threat intelligence. Extend them with brands, providers and TLDs relevant
to your organisation.
"""

# Brands and their genuine sending domains
# Brands most often impersonated in phishing (incl. Portuguese banks), mapped
# to the registrable domains they really use. A sender on one of these
# domains is treated as genuine for that brand. Country versions of the
# brand's own name (e.g. amazon.de, paypal.pt) are also accepted by
# utils.is_legit_brand_domain(), so they do not need listing here.
BRAND_DOMAINS = {
    "paypal":        {"paypal.com", "paypal.me", "paypalobjects.com"},
    "microsoft":     {"microsoft.com", "microsoftonline.com", "microsoft365.com", "office.com",
                      "office365.com", "outlook.com", "live.com", "sharepoint.com", "azure.com"},
    "office365":     {"microsoft.com", "microsoftonline.com", "office.com", "office365.com"},
    "outlook":       {"outlook.com", "microsoft.com", "office.com", "office365.com", "live.com"},
    "apple":         {"apple.com", "icloud.com", "me.com", "mac.com"},
    "icloud":        {"icloud.com", "apple.com", "me.com"},
    "amazon":        {"amazon.com", "amazon.co.uk", "amazon.es", "amazon.de", "amazon.fr", "amazon.it"},
    "google":        {"google.com", "gmail.com", "googlemail.com", "youtube.com"},
    "netflix":       {"netflix.com"},
    "dhl":           {"dhl.com"},
    "fedex":         {"fedex.com"},
    "ups":           {"ups.com"},
    "docusign":      {"docusign.com", "docusign.net"},
    "dropbox":       {"dropbox.com", "dropboxmail.com"},
    "linkedin":      {"linkedin.com"},
    "facebook":      {"facebook.com", "facebookmail.com", "fb.com", "meta.com"},
    "instagram":     {"instagram.com", "facebookmail.com"},
    "santander":     {"santander.com"},
    "caixa":         {"cgd.pt", "caixabank.com", "caixabank.es"},
    "millennium":    {"millenniumbcp.pt"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "wellsfargo":    {"wellsfargo.com"},
    "chase":         {"chase.com", "jpmorgan.com"},
    "hsbc":          {"hsbc.com"},
    "binance":       {"binance.com"},
    "coinbase":      {"coinbase.com"},
}
BRANDS = list(BRAND_DOMAINS)

# Brands shorter than this must appear as a whole word (see utils.brand_in()).
# Short names hide inside everyday words ("ups" in "groups", "chase" in
# "purchase", "apple" in "pineapple"); longer ones rarely do.
SHORT_BRAND_LEN = 6

# Digit-for-letter swaps used in lookalike domains ("paypa1", "micr0soft",
# "amazon5hop"). "1" can stand for "l" or "i", so two maps are tried.
LEET_MAPS = (str.maketrans("013458", "oleasb"),   # paypa1    -> paypal
             str.maketrans("013458", "oieasb"))   # m1crosoft -> microsoft

# Sender context
# A brand name in the display name sent from one of these is a classic lure,
# since real companies do not send from free webmail.
FREE_MAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
             "yahoo.com", "aol.com", "proton.me", "protonmail.com", "gmx.com",
             "mail.com", "icloud.com", "me.com", "mac.com", "sapo.pt"}

# Mail platforms whose Message-IDs never match the customer's own domain
# (Google Workspace uses @mail.gmail.com, Microsoft 365 @*.prod.outlook.com).
# A Message-ID on one of these root domains is not suspicious by itself.
MAIL_PROVIDER_DOMAINS = {"gmail.com", "google.com", "outlook.com", "exchangelabs.com",
                         "yahoo.com", "icloud.com", "apple.com", "zoho.com", "protonmail.com",
                         "proton.me"}

# Mail providers whose own servers use several root domains in one Received
# chain (Microsoft 365 hops are named *.outlook.com and *.office365.com).
# Used to tell where the recipient's side of the chain ends; the first
# domain of each group is the name the others are treated as.
RELAY_ORG_GROUPS = [
    ("outlook.com", "office365.com", "exchangelabs.com", "microsoft.com"),
    ("yahoo.com", "yahoodns.net"),
]

# Email service providers (newsletters, helpdesks, transactional mail). Mail
# sent through them legitimately has Return-Path / Message-ID / SPF domains
# of the provider. Only used to name the provider in the report.
ESP_DOMAINS = {
    "mcsv.net": "Mailchimp", "mailchimp.com": "Mailchimp", "mandrillapp.com": "Mailchimp Transactional",
    "rsgsv.net": "Mailchimp", "sendgrid.net": "SendGrid", "amazonses.com": "Amazon SES",
    "sparkpostmail.com": "SparkPost", "mailgun.org": "Mailgun", "mailgun.net": "Mailgun",
    "mktomail.com": "Marketo", "hubspotemail.net": "HubSpot", "exacttarget.com": "Salesforce MC",
    "salesforce.com": "Salesforce", "constantcontact.com": "Constant Contact",
    "sendinblue.com": "Brevo", "brevo.com": "Brevo", "mailjet.com": "Mailjet",
    "postmarkapp.com": "Postmark", "zendesk.com": "Zendesk", "freshdesk.com": "Freshdesk",
}

# Cheap or newly released TLDs that are over-represented in phishing feeds.
# ".zip" and ".mov" are also confusable with file names.
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml",
                   "cf", "ga", "work", "support", "rest", "monster", "icu", "buzz",
                   "cam", "cyou", "sbs", "lol", "quest", "live"}

# X-Mailer / User-Agent substrings typical of scripts and mass-mailing kits
# rather than normal mail clients.
BULK_MAILERS = ["phpmailer", "swiftmailer", "the bat", "mass mail", "sendblaster",
                "mailer", "smtp client", "leaf pgp", "python", "php/"]

# Links
# Shorteners hide the real destination, so the analyst cannot judge the link.
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
                  "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id",
                  "lnkd.in", "qrco.de"}

# Namespace / schema URLs that appear in HTML and Office markup but are never
# real links. Dropped so they do not pollute the IOC list.
IGNORED_URL_HOSTS = {"www.w3.org", "w3.org", "schemas.microsoft.com",
                     "schemas.openxmlformats.org", "purl.org", "ns.adobe.com"}

# Attachments
# Extensions that can run code or smuggle a payload. Archives, disk images
# (.iso/.img/.vhd), HTML/SVG (HTML smuggling, credential pages), OneNote,
# Excel add-ins (.xll) and web queries (.iqy/.slk) are included because they
# are common ways to get past mail filters. The "-ms" ones are Windows shell
# files (settings shortcuts, libraries, saved searches) that can run commands.
RISKY_EXT = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".bat", ".cmd",
             ".ps1", ".com", ".pif", ".jar", ".msi", ".msix", ".appx", ".dll", ".lnk",
             ".iso", ".img", ".vhd", ".vhdx", ".hta", ".cpl", ".reg", ".chm", ".msc",
             ".docm", ".dotm", ".xlsm", ".xlsb", ".xltm", ".pptm", ".ppam", ".xlam", ".xll",
             ".iqy", ".slk", ".one", ".html", ".htm", ".shtml", ".svg",
             ".zip", ".rar", ".7z", ".ace", ".gz", ".tar", ".cab", ".arj", ".xz",
             ".settingcontent-ms", ".library-ms", ".appref-ms", ".search-ms", ".searchconnector-ms"}

# "Harmless-looking" extensions. Seeing one right before a risky one
# ("invoice.pdf.exe") indicates a double-extension disguise.
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
           ".jpg", ".jpeg", ".png", ".gif", ".rtf", ".csv", ".odt", ".ods"}

# Scoring
# Points are defined next to each rule in rules.py / links.py. Each category
# is capped so one problem (e.g. five bad links) cannot max out the score on
# its own; the total is capped at 100.
CATEGORY_CAPS = {
    "authentication": 45,
    "sender":         40,   # From / Reply-To / Return-Path / Message-ID consistency
    "impersonation":  50,   # display name, brand and lookalike domains
    "relay":          20,   # Received chain oddities
    "mailer":         10,
    "links":          40,
    "attachments":    60,
    "reputation":     50,   # online AbuseIPDB / VirusTotal results
}
MAX_SCORE = 100

# Verdict thresholds (score >= value).
HIGH_THRESHOLD = 60
MEDIUM_THRESHOLD = 30

# Online lookups
ABUSE_HIGH = 75      # AbuseIPDB confidence treated as malicious
ABUSE_MEDIUM = 25    # AbuseIPDB confidence treated as suspicious
