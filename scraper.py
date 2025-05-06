from collections import Counter, defaultdict
import re
from urllib.parse import urldefrag, urlparse, urljoin
from bs4 import BeautifulSoup

# GLOBAL VARIABLES
# question 1
unique_pages = set()
# question 2
longest_page_url = ""
longest_page_wordcount = 0
# question 3
word_counter = Counter()
# question 4
subdomain_counter = defaultdict(int)

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
    global longest_page_url, longest_page_wordcount
    next_links = []
    # Status OK
    if resp.status == 200:
        content = resp.raw_response.content
        try:
            # decode response into HTML
            html = content.decode('utf-8', errors='ignore')
            soup = BeautifulSoup(html, 'html.parser')

            for link in soup.find_all('a', href=True):
                full_link = urljoin(url, link['href'])

                # strip fragment
                defragged_link, _ = urldefrag(full_link)

                # remove trailing slash
                parsed = urlparse(defragged_link)
                netloc = parsed.netloc
                path = parsed.path.rstrip('/') if parsed.path != '/' else parsed.path

                # reconstruct normalized URL
                normalized_url = parsed._replace(netloc=netloc, path=path).geturl()
                if normalized_url not in unique_pages:
                    next_links.append(normalized_url)

            # retrieve base url 
            base_url, _ = urldefrag(url)
            parsed_base = urlparse(base_url)
            base_path = parsed_base.path.rstrip('/') if parsed_base.path != '/' else parsed_base.path
            base_url = parsed_base._replace(path=base_path).geturl()
            unique_pages.add(base_url)

            # remove html tags so they do not get counted
            text = remove_html_tags(html)

            # tokenize the text and update word counts
            tokens = tokenize(text)
            cleaned_tokens = [token.lower() for token in tokens if token.isalpha() and token.lower() not in stopwords]
            word_counter.update(cleaned_tokens)

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
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        url, _ = urldefrag(url)
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        if "doku.php" in parsed.path.lower() or "swiki" in parsed.path.lower() or "events" in parsed.path.lower() or "~eppstein" in parsed.path.lower() or "wics" in parsed.path.lower() or "wiki" in parsed.path.lower() or "grape" in parsed.path.lower():
            return False
        if "doku.php" in parsed.query.lower() or "swiki" in parsed.query.lower() or "events" in parsed.query.lower() or "~eppstein" in parsed.query.lower() or "wics" in parsed.query.lower() or "wiki" in parsed.query.lower() or "grape" in parsed.query.lower():
            return False
        if "doku.php" in parsed.netloc.lower() or "swiki" in parsed.netloc.lower() or "events" in parsed.netloc.lower() or "~eppstein" in parsed.netloc.lower() or "wics" in parsed.netloc.lower() or "wiki" in parsed.netloc.lower() or "grape" in parsed.netloc.lower():
            return False
        if re.search(r"\d{4}-\d{2}-\d{2}", parsed.path.lower()) or re.search(r"\d{4}-\d{2}-\d{2}", parsed.query.lower()) or re.search(r"\d{4}-\d{2}", parsed.path.lower()) or re.search(r"\d{4}-\d{2}", parsed.query.lower()):
            return False
        if "tribe-bar-date" in parsed.path.lower() or "ical" in parsed.path.lower() or "tribe_events_display" in parsed.path.lower() or "tribe-bar-date" in parsed.query.lower() or "ical" in parsed.query.lower() or "tribe_events_display" in parsed.query.lower():
            return False
        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower() ):
            return False
        
        valid_domains = (
                ".ics.uci.edu",
                ".cs.uci.edu",
                ".informatics.uci.edu",
                ".stat.uci.edu"
            )
        if parsed.netloc.endswith(valid_domains):
            return True
        if parsed.netloc.endswith("today.uci.edu"):
            if parsed.path.startswith("/department/information_computer_sciences/"):
                return True   
        return False

    except TypeError:
        print ("TypeError for ", parsed)
        raise


def create_report():
    with open('report.txt', 'w', encoding='utf-8') as f:
        # 1. unique pages
        f.write(f"Unique pages: {len(unique_pages)}\n")

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
