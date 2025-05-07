from collections import Counter, defaultdict
import re
from urllib.parse import urldefrag, urlparse, urljoin
from lxml import html as lh

# GLOBAL VARIABLES
# question 1
unique_pages = set()
num_pages = 0
# question 2
longest_page_url = ""
longest_page_wordcount = 0
# question 3
word_counter = Counter()
# question 4
subdomain_counter = defaultdict(int)

DATE_PATTERN = re.compile(r"\d{4}-\d{2}(-\d{2})?")
EXTENSION_PATTERN = re.compile(
    r".*\.(css|js|bmp|gif|jpe?g|ico|png|tiff?|mid|mp2|mp3|mp4|"
    r"wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|ps|eps|tex|ppt|"
    r"pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|"
    r"bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1|thmx|mso|arff|"
    r"rtf|jar|csv|rm|smil|wmv|swf|wma|zip|rar|gz)$", re.IGNORECASE)
BLOCKED_KEYWORDS = {"doku.php", "swiki", "events", "~eppstein", "wics", "wiki", "grape"}
BLOCKED_QUERY_PARAMS = {"tribe-bar-date", "ical", "tribe_events_display"}
VALID_DOMAINS = (
    ".ics.uci.edu",
    ".cs.uci.edu",
    ".informatics.uci.edu",
    ".stat.uci.edu"
)

# create set of stop words
stopwords = set()
with open('stopwords.txt', 'r') as f:
    for line in f:
        stopwords.add(line.strip().lower())

def tokenize(content: str) -> list:
    # split content into alphanumeric sequences, ignoring punctuation
    return re.findall(r'\b\w+\b', content)

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
    return [link for link in links if is_valid(link) and link not in unique_pages]

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
    global longest_page_url, longest_page_wordcount, num_pages
    next_links = []
    # Status OK
    if resp.status == 200:
        content = resp.raw_response.content
        try:
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

                if normalised not in unique_pages:
                    next_links.append(normalised)

            # deduplicate list while preserving order
            next_links = list(dict.fromkeys(next_links))
            # retrieve base url 

            base_url, _ = urldefrag(url)
            parsed_base = urlparse(base_url)
            base_path = parsed_base.path.rstrip('/') if parsed_base.path != '/' else parsed_base.path
            base_url = parsed_base._replace(path=base_path).geturl()
            if len(unique_pages) < 5000:
                unique_pages.add(base_url)
            num_pages += 1

            html = content.decode('utf-8', errors='ignore')
            # remove html tags so they do not get counted
            text = remove_html_tags(html)

            # tokenize the text and update word counts
            tokens = tokenize(text)
            cleaned_tokens = [token.lower() for token in tokens if token.isalpha() and token.lower() not in stopwords]
            if (len(word_counter) < 5000):
                word_counter.update(cleaned_tokens)
            else:
                for token in cleaned_tokens:
                    if(token in word_counter):
                        word_counter.update([token])

            # check if current url text is longer than the max so far
            if len(cleaned_tokens) > longest_page_wordcount:
                longest_page_wordcount = len(cleaned_tokens)
                longest_page_url = base_url

            # update number of subdomains
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()
            if netloc.endswith(".uci.edu"):
                subdomain_counter[netloc] += 1

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
        f.write(f"Unique pages: {num_pages}\n")

        # 2. longest page
        f.write(f"Longest page: {longest_page_url} ({longest_page_wordcount} words)\n\n")

        # 3. top 50 words
        f.write("Top 50 most common words:\n")
        for word, count in word_counter.most_common(50):
            f.write(f"{word}: {count}\n")

        # 4. subdomains found
        f.write("\nSubdomains:\n")
        for subdomain in sorted(subdomain_counter.keys()):
            f.write(f"{subdomain}, {subdomain_counter[subdomain]}\n")
