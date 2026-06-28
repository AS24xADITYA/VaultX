from urllib.parse import urlparse

CATEGORY_MAP = {
    'instagram': 'Social', 'twitter': 'Social', 'x.com': 'Social',
    'facebook': 'Social', 'linkedin': 'Social', 'snapchat': 'Social',
    'tiktok': 'Social', 'reddit': 'Social', 'pinterest': 'Social',
    'discord': 'Social', 'telegram': 'Social', 'whatsapp': 'Social',
    
    'bank': 'Banking', 'credit': 'Banking', 'chase': 'Banking',
    'paypal': 'Banking', 'razorpay': 'Banking', 'paytm': 'Banking',
    'gpay': 'Banking', 'phonepay': 'Banking', 'zerodha': 'Banking',
    'sbi': 'Banking', 'hdfc': 'Banking', 'icici': 'Banking',
    'stripe': 'Banking', 'revolut': 'Banking', 'wise': 'Banking',
    
    'github': 'Work', 'gitlab': 'Work', 'bitbucket': 'Work',
    'jira': 'Work', 'slack': 'Work', 'notion': 'Work',
    'confluence': 'Work', 'trello': 'Work', 'asana': 'Work',
    'figma': 'Work', 'vercel': 'Work', 'netlify': 'Work',
    'aws': 'Work', 'azure': 'Work', 'google.com/business': 'Work',
    'office': 'Work', 'microsoft': 'Work',
    
    'amazon': 'Shopping', 'flipkart': 'Shopping', 'myntra': 'Shopping',
    'ebay': 'Shopping', 'etsy': 'Shopping', 'shopify': 'Shopping',
    'meesho': 'Shopping', 'ajio': 'Shopping', 'nykaa': 'Shopping',
    
    'netflix': 'Entertainment', 'spotify': 'Entertainment',
    'youtube': 'Entertainment', 'hotstar': 'Entertainment',
    'primevideo': 'Entertainment', 'hulu': 'Entertainment',
    'twitch': 'Entertainment', 'steam': 'Entertainment',
    'epicgames': 'Entertainment', 'playstation': 'Entertainment',
    'crunchyroll': 'Entertainment', 'jiocinema': 'Entertainment',
    
    'coursera': 'Education', 'udemy': 'Education', 'edx': 'Education',
    'nptel': 'Education', 'khan': 'Education', 'duolingo': 'Education',
    'leetcode': 'Education', 'hackerrank': 'Education',
    
    'gmail': 'Social', 'outlook': 'Work', 'yahoo': 'Social',
    'protonmail': 'Work', 'tutanota': 'Work',
}

def suggest_category(site: str) -> str:
    if '://' in site:
        domain = urlparse(site).netloc.lower().replace('www.', '')
    else:
        domain = site.lower().replace('www.', '')
        
    for keyword, category in CATEGORY_MAP.items():
        if keyword in domain:
            return category
            
    return 'Other'

def auto_categorize_all(vault_instance) -> dict:
    entries = vault_instance.list_all()
    updated = {}
    for entry in entries:
        if entry['category'] == 'Other':
            suggestion = suggest_category(entry['site'])
            if suggestion != 'Other':
                vault_instance.update_category(entry['id'], suggestion)
                updated[entry['id']] = suggestion
    return updated
