#!/usr/bin/env python3
"""Generate README.md from YAML data files in companies/ and honorable_mentions/."""

import os
import sys
import yaml

COMPANIES_DIR = os.path.join(os.path.dirname(__file__), "companies")
MENTIONS_DIR = os.path.join(os.path.dirname(__file__), "honorable_mentions")
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "README.md")

PROVIDERS = {
    "github": {
        "repo_url": "https://github.com/{repo}",
        "stars_badge": "https://img.shields.io/github/stars/{repo}",
    },
}


def load_yaml_dir(directory):
    items = []
    if not os.path.isdir(directory):
        return items
    for filename in os.listdir(directory):
        if not filename.endswith(".yaml"):
            continue
        filepath = os.path.join(directory, filename)
        with open(filepath, "r") as f:
            data = yaml.safe_load(f)
        if data:
            data["_filename"] = filename
            items.append(data)
    return items


def render_company_row(company):
    name = company["name"]
    website = company["website"]

    company_cell = f"[{name}]({website})"
    if company.get("acquired_by"):
        company_cell += f" <br> Acquired by {company['acquired_by']}"

    projects_parts = []
    for proj in company.get("projects", []):
        provider = proj.get("provider", "github")
        if "url" in proj:
            projects_parts.append(f"[{proj['name']}]({proj['url']})")
        elif provider in PROVIDERS:
            cfg = PROVIDERS[provider]
            repo = proj["repo"]
            badge_url = cfg["stars_badge"].format(repo=repo)
            repo_url = cfg["repo_url"].format(repo=repo)
            projects_parts.append(
                f"![Stars]({badge_url}) [{proj['name']}]({repo_url})"
            )
        else:
            projects_parts.append(proj["name"])
    projects_cell = " <br> ".join(projects_parts)

    founders_parts = []
    for founder in company.get("founders", []):
        if founder.get("linkedin"):
            founders_parts.append(f"[{founder['name']}]({founder['linkedin']})")
        else:
            founders_parts.append(founder["name"])
    founders_cell = ", ".join(founders_parts)

    return f"| {company_cell} | {projects_cell} | {founders_cell} |"


def render_mention(mention):
    repo = mention.get("repo", "")
    url = mention.get("url", "")
    if repo:
        badge = f"![Stars](https://img.shields.io/github/stars/{repo})"
        link = f"[{mention['name']}](https://github.com/{repo})"
    elif url:
        badge = ""
        link = f"[{mention['name']}]({url})"
    else:
        return ""

    authors = mention.get("authors", [])
    author_strs = []
    for a in authors:
        if a.get("github"):
            author_strs.append(f"[{a['name']}]({a['github']})")
        else:
            author_strs.append(a["name"])
    authors_text = " and ".join(author_strs)

    parts = [p for p in [badge, link] if p]
    return f"{' '.join(parts)} by {authors_text}"


def main():
    companies = load_yaml_dir(COMPANIES_DIR)
    mentions = load_yaml_dir(MENTIONS_DIR)

    active = [c for c in companies if c.get("status") != "inactive"]
    inactive = [c for c in companies if c.get("status") == "inactive"]

    active.sort(key=lambda c: c["name"].upper())
    inactive.sort(key=lambda c: c["name"].upper())
    mentions.sort(key=lambda m: m["name"].upper())

    lines = []

    lines.append(
        'As an Israeli Open Source consulting company, we are proud to present the eco system of Israeli companies which create Open Source projects. The list is curated under <a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-sa/4.0/80x15.png" /></a>'
    )
    lines.append("")
    lines.append("## Israeli Open Source Companies")
    lines.append("")
    lines.append(
        "Companies are sorted by name. Contributors are welcomed, open a pull request to add new companies / projects or update the existing information."
    )
    lines.append("")
    lines.append("| Company | Projects | Founders |")
    lines.append("|---|---|---|")

    for company in active:
        lines.append(render_company_row(company))

    if inactive:
        lines.append("")
        lines.append("## Inactive Companies")
        lines.append("")
        lines.append("| Company | Projects | Founders |")
        lines.append("|---|---|---|")
        for company in inactive:
            lines.append(render_company_row(company))

    if mentions:
        lines.append("")
        lines.append("## Honorable mentions of top Israeli lead Open Source projects")
        mention_lines = []
        for mention in mentions:
            rendered = render_mention(mention)
            if rendered:
                mention_lines.append(rendered)
        lines.append(" <br>\n".join(mention_lines))

    lines.append("")
    lines.append("## Media refenreces")
    lines.append(
        "2023-06-25 Tech12 [בלי סודות: מה עומד מאחורי השגשוג של הקוד הפתוח](https://www.tech12.co.il/index-investments/Article-b49a7ca76d7d881027.htm)"
    )
    lines.append("")
    lines.append("---")
    lines.append("Made with :heart: by Kaplan Open Source")

    output = "\n".join(lines) + "\n"

    with open(OUTPUT_FILE, "w") as f:
        f.write(output)

    print(f"Generated {OUTPUT_FILE} with {len(active)} active companies", end="")
    if inactive:
        print(f", {len(inactive)} inactive", end="")
    print(f", {len(mentions)} honorable mentions")


if __name__ == "__main__":
    main()
