from collections import Counter, defaultdict
import re
from urllib.parse import urldefrag, urlparse, urljoin
from lxml import html as lh
import hashlib
from simhash import Simhash
import threading

# GLOBAL VARIABLES
# question 1
UNIQUE_PAGES = set()
NUM_PAGES = 0
# question 2
LONGEST_PAGE_URL = ""
LONGEST_PAGE_WORDCOUNT = 0
# question 3
WORD_COUNTER = Counter()
# question 4
SUBDOMAIN_COUNTER = defaultdict(int)

# duplicate detection
CHECKSUMS = set() # for MD5
SIMHASHES = [] # for near duplicate detection

DATE_PATTERN = re.compile(r"\d{4}-\d{2}(-\d{2})?")
EXTENSION_PATTERN = re.compile(
    r".*.(css|js|bmp|gif|jpe?g|ico|png|tiff?|mid|mp2|mp3|mp4|"
    r"wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|ps|eps|tex|ppt|"
    r"pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|"
    r"bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1|thmx|mso|arff|png|jpeg|"
    r"rtf|jar|csv|rm|smil|wmv|swf|wma|zip|rar|gz|ipynb|war|apk)$", re.IGNORECASE)
BLOCKED_KEYWORDS = {"doku.php", "swiki", "events", "~eppstein", "wics", "wiki", "grape", "nanda"}
BLOCKED_QUERY_PARAMS = {"tribe-bar-date", "ical", "tribe_events_display"}
VALID_DOMAINS = (
    ".ics.uci.edu",
    ".cs.uci.edu",
    ".informatics.uci.edu",
    ".stat.uci.edu"
)

#Lock
unique_pages_lock = threading.RLock()
word_counter_lock = threading.RLock()
subdomain_counter_lock = threading.RLock()
checksum_lock = threading.RLock()
simhash_lock = threading.RLock()

# create set of stop words
stopwords = set()
with open('stopwords.txt', 'r') as f:
    for line in f:
        stopwords.add(line.strip().lower())

def tokenize(content: str) -> list:
    # disregard non‑ASCII bytes
    # split content into alphanumeric sequences, ignoring punctuation
    ascii_text = content.encode("ascii", "ignore").decode()
    # find runs of 2+ ASCII letters/digits
    return re.findall(r"\b[A-Za-z0-9]{2,}\b", ascii_text)

def remove_html_tags(html):
    # remove <script> and <style>
    html = re.sub(r'(?is)<script.*?>.*?</script>', '', html)
    html = re.sub(r'(?is)<style.*?>.*?</style>', '', html)

    # remove tags such as <html>, <head>, <title>, <body>, <h1>, <p>, etc.
    text = re.sub(r'<[^>]+>', ' ', html)
    # remove one or more whitespace characters
    text = re.sub(r'\s+', ' ', text)

    return text

def scraper(url, resp):
    links = extract_next_links(url, resp)
    next_links = []
    for link in links:
        with unique_pages_lock:
            if is_valid(link) and link not in UNIQUE_PAGES:
                UNIQUE_PAGES.add(link)
                if len(link) < 370:
                    next_links.append(link)
    return next_links

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    global LONGEST_PAGE_URL, LONGEST_PAGE_WORDCOUNT, NUM_PAGES
    
    next_links = []
    # Status OK
    if resp.status == 200:
        try:
            content = resp.raw_response.content
            # checksum
            checksum = hashlib.md5(content).hexdigest()

            
            with checksum_lock:
                if checksum in CHECKSUMS:
                    return []
                else:
                    if len(CHECKSUMS) < 8000:
                        CHECKSUMS.add(checksum)

            html = content.decode('utf-8', errors='ignore')
            # remove html tags so they do not get counted
            text = remove_html_tags(html)

            # simhash
            simhash_value = Simhash(tokenize(text))
            with simhash_lock:
                for existing in SIMHASHES:
                    if simhash_value.distance(existing) <= 3:
                        return []
                if len(SIMHASHES) < 8000:
                     SIMHASHES.append(simhash_value)

            # decode response into HTML
            doc = lh.fromstring(content)
            doc.make_links_absolute(url, resolve_base_href=True)
            for _, href, l, _ in doc.iterlinks():
                if not href and not l:
                    continue
                # strip fragment
                clean_href, _ = urldefrag(l)
                parsed = urlparse(clean_href)

                # normalise: remove trailing '/' unless root
                path = parsed.path.rstrip("/") if parsed.path and parsed.path != "/" else parsed.path
                normalised = parsed._replace(path=path).geturl()

                if normalised not in UNIQUE_PAGES:
                    if len(normalised) < 370:
                        next_links.append(normalised)

            # deduplicate list while preserving order
            next_links = list(dict.fromkeys(next_links))
            # retrieve base url 

            base_url, _ = urldefrag(url)
            parsed_base = urlparse(base_url)
            base_path = parsed_base.path.rstrip('/') if parsed_base.path != '/' else parsed_base.path
            base_url = parsed_base._replace(path=base_path).geturl()
            with unique_pages_lock:
                if len(UNIQUE_PAGES) < 8000:
                    UNIQUE_PAGES.add(base_url)
                NUM_PAGES += 1


            # tokenize the text and update word counts
            tokens = tokenize(text)
            cleaned_tokens = [token.lower() for token in tokens if token.lower() not in stopwords and not token.isdigit()]
            with word_counter_lock:
                if len(WORD_COUNTER) < 4000 and len(cleaned_tokens) > 100:
                    WORD_COUNTER.update(cleaned_tokens)
                else:
                    for token in cleaned_tokens:
                        if(token in WORD_COUNTER):
                            WORD_COUNTER.update([token])
    
                # check if current url text is longer than the max so far
                if len(cleaned_tokens) > LONGEST_PAGE_WORDCOUNT:
                    LONGEST_PAGE_WORDCOUNT = len(cleaned_tokens)
                    LONGEST_PAGE_URL = base_url

            # update number of subdomains
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()
            with subdomain_counter_lock:
                if netloc.endswith(".uci.edu"):
                    SUBDOMAIN_COUNTER[netloc] += 1

        except Exception as e:
            print(f"Error processing {url}: {e}")
    # Status NOT OK !!
    else:
        print(f"Skipping {url}, bad status {resp.status}")

    return next_links


def is_valid(url):
    try:
        url, _ = urldefrag(url)
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False

        path_lower = parsed.path.lower()
        netloc_lower = parsed.netloc.lower()
        query_lower = parsed.query.lower()

        if any(keyword in path_lower for keyword in BLOCKED_KEYWORDS):
            return False
        if any(keyword in netloc_lower for keyword in BLOCKED_KEYWORDS):
            return False
        if any(keyword in query_lower for keyword in BLOCKED_KEYWORDS):
            return False

        if DATE_PATTERN.search(path_lower) or DATE_PATTERN.search(query_lower):
            return False

        if any(param in query_lower for param in BLOCKED_QUERY_PARAMS):
            return False

        if EXTENSION_PATTERN.search(path_lower):
            return False

        if any(netloc_lower.endswith(domain) for domain in VALID_DOMAINS):
            return True
        if netloc_lower.endswith("today.uci.edu") and path_lower.startswith("/department/information_computer_sciences/"):
            return True

        return False

    except TypeError:
        print("TypeError for URL:", url)
        raise


def create_report():
    with open('report.txt', 'w', encoding='utf-8') as f:
        # 1. unique pages
        f.write(f"Unique pages: {NUM_PAGES}\n")

        # 2. longest page
        f.write(f"Longest page: {LONGEST_PAGE_URL} ({LONGEST_PAGE_WORDCOUNT} words)\n\n")

        # 3. top 50 words
        f.write("Top 50 most common words:\n")
        for word, count in WORD_COUNTER.most_common(50):
            f.write(f"{word}: {count}\n")

        # 4. subdomains found
        f.write("\nSubdomains:\n")
        for subdomain in sorted(SUBDOMAIN_COUNTER.keys()):
            f.write(f"{subdomain}, {SUBDOMAIN_COUNTER[subdomain]}\n")
