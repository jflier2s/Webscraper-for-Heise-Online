import requests
import re
import pandas as pd
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone
import json

# constants
BASE_URL = "https://www.heise.de"
DAYS_IN_SCOPE = 91
KNOWN_FALSE_POSITIVE = ['/security/news/archiv/', '/security/news/7_tage_news/', '/security/news/']
CVE_PATTERN = r"\bcve-\d{4}-\d{4,7}\b"
POSTING_PATTERN = r"posting-(\d+)"
results = []


# Überprüft das Veröffentlichungsdatum
def is_recent(date_str):
    try:

        current_time = datetime.now()
        timestamp = datetime.fromisoformat(date_str)
        time_difference = current_time - timestamp

        return time_difference <= timedelta(days=DAYS_IN_SCOPE)

    except ValueError:
        return False


# Fragt den Inhalt einer Website an und formatiert ihn
def get_webcontent(url):
    response = requests.get(url)
    if response.status_code != 200:
        print("Fehler beim Abrufen der Seite:", response.status_code)
        return
    return BeautifulSoup(response.content, 'html.parser')


# Ermittelt den vom NIST bereitgestellten CVSS
def get_cvss(cve):
    full_nist_link = f"https://nvd.nist.gov/vuln/detail/{cve}"
    nist_soup = get_webcontent(full_nist_link)

    try:
        return nist_soup.find('a', id="Cvss3CnaCalculatorAnchor").get_text(), datetime.strptime(
            nist_soup.find('span', attrs={'data-testid': 'vuln-published-on'}).get_text(), "%m/%d/%Y").isoformat()
    except AttributeError:
        return None, None


# Speichert die erhobenen Informationen in einer JSON-File
def save_in_file(analysis_results):
    # df = pd.DataFrame(results)
    # df.to_excel('Heise_Analyse.xlsx', index=False)
    json_object = json.dumps(analysis_results, indent=7)

    with open("heise_analysis2.json", "w") as outfile:
        outfile.write(json_object)


# Funktion zum Extrahieren von Artikeln und Kommentaren
def scrape_heise_security_alerts():
    print(f"-- Ermittle die News Artikel der letzten {DAYS_IN_SCOPE} Tage --")

    page_count = 1
    recent_flag = True
    while (recent_flag):

        # Ermittelt alle News von der Heise Security Alerts Landing Page
        news_articles = get_webcontent(f"{BASE_URL}/security/alerts/seite-{page_count}")
        articles = [link.get('href') for link in news_articles.find_all('a') if "/news/" in link.get('href')]

        # False Positive entfernen
        articles = [article for article in articles if article not in KNOWN_FALSE_POSITIVE]

        print(f"-- {len(articles)} auf Seite {page_count} gefunden --")

        print("-- Beginne mit der Informationsermittlung --")

        for article in articles:
            print("-" * 80)

            article_title = article.split("-")
            del article_title[-1]
            article_title = " ".join(article_title).replace("/news/", "")

            print(f"-- {article_title} --")

            # Inhalt des Artikels holen
            full_article_link = f"{BASE_URL}/security/alerts{article}"

            if any(result['url'] == full_article_link for result in results):
                print(f"-- Artikel {article_title} bereits betrachtet --")
                continue

            article_soup = get_webcontent(full_article_link)

            # Veröffentlichungsdatum (an den HTML-Aufbau der Seite anpassen)
            date_tag = article_soup.find('time')
            date_text = date_tag.get('datetime', '') if date_tag else ''

            article_author = article_soup.find('div', attrs={'class': 'creator'}).get_text().strip().split("\n")[-1]
            print(f"-- Author: {article_author} --")
            updated = True

            if is_recent(date_text):

                print(f"-- Zeitlich relevant -- ")

                article_text = article_soup.get_text()

                article_content = "\n".join(line.strip() for line in article_text.splitlines() if line.strip())

                # CVEs aus Artikel ermitteln
                cve_data = []

                cves = re.findall(CVE_PATTERN, article_text, re.IGNORECASE)
                cves = list(dict.fromkeys(cves))  # Duplikate entfernen

                # CVE-Informationen aus der National Vulnerability Database des NIST holen
                for cve in cves:
                    CVSS, pub_date = get_cvss(cve)

                    cve_data.append({
                        "cve": cve,
                        "cvss": CVSS,
                        "published": pub_date
                    })

                print(cve_data)

                # Überprüfen, ob der Artikel ein Update-Tag hat
                # Author extrahieren
                try:
                    article_soup.find('span', attrs={'class': 'a-publish-info__update'}).get_text()

                except AttributeError:
                    updated = False

                print(f"-- Updated: {updated} --")

                # Kommentar-Link ermitteln - Es gibt nur einen, den aber doppelt
                article_comment_link = [link.get('href') for link in article_soup.find_all('a') if
                                        "/comment/" in link.get('href')]
                if len(article_comment_link) > 0:
                    article_comment_link = article_comment_link[0]

                    full_comment_link = f"{BASE_URL}/forum/heise-online/Kommentare{article_comment_link}"

                    # Einzelne Kommentare ermitteln
                    article_comment_soup = get_webcontent(full_comment_link)
                    comments = [link.get('href') for link in article_comment_soup.find_all('a') if
                                f"/Kommentare/{article_title.replace(' ', '-')}" in link.get(
                                    'href') and not "/chronological/" in link.get('href')]

                    # Inhalt jedes Kommentars erhalten
                    content_of_comments = []
                    for comment in comments:
                        comment_soup = get_webcontent(comment)
                        comment_id = re.findall(POSTING_PATTERN, comment, re.IGNORECASE)[0]
                        comment_content = comment_soup.find('div', id=f"posting_{comment_id}").get_text()

                        cleaned_comment_content = "\n".join(
                            line.strip() for line in comment_content.splitlines() if line.strip())
                        cleaned_comment_content = cleaned_comment_content.split("Melden")[1]
                        content_of_comments.append(cleaned_comment_content)

                print(f"-- {len(content_of_comments)} Kommentare ermittelt --")

                results.append({
                    "url": full_article_link,
                    "author": article_author,
                    "title": article_title,
                    "time": date_text,
                    "cves": cve_data,
                    "comments": content_of_comments,
                    "updated": updated
                })
            else:
                recent_flag = False
                print("-- Nicht zeitlich Relevant --")
                break

        page_count = page_count + 1

    print(f"-- Ergebnisse von {len(results)} Artikel in JSON gespeichert --")
    save_in_file(results)


# Hauptfunktion aufrufen
scrape_heise_security_alerts()
