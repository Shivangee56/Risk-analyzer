
from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import json
import re
import os
from datetime import datetime, timezone
import requests

app = Flask(__name__)
CORS(app)

DB_PATH = os.path.join(os.path.dirname(__file__), "rospl_history.db")
OSV_API = "https://api.osv.dev/v1/query"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_name TEXT,
            scanned_at TEXT,
            score INTEGER,
            dependency_count INTEGER,
            vulnerable_count INTEGER,
            result_json TEXT
        )
    """)
    conn.commit()
    return conn


def parse_manifest(filename, content):
    filename = filename.lower()
    dependencies = []
    project_name = "My Project"

    if filename.endswith(".json"):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            raise ValueError("Invalid package.json. Check its JSON syntax.")

        if not isinstance(data, dict):
            raise ValueError("package.json must contain a JSON object.")

        project_name = data.get("name", project_name)

        for section in (
            "dependencies",
            "devDependencies",
            "optionalDependencies"
        ):
            values = data.get(section, {})
            if isinstance(values, dict):
                for name, version in values.items():
                    dependencies.append({
                        "name": name,
                        "version": str(version).strip(),
                        "ecosystem": "npm"
                    })

    elif filename.endswith(".txt"):
        project_name = "Python Project"

        for line in content.splitlines():
            line = line.strip()

            if not line or line.startswith("#") or line.startswith("-"):
                continue

            match = re.match(
                r"^([A-Za-z0-9_.-]+)\s*(?:==|===)\s*([A-Za-z0-9_.+!-]+)",
                line
            )

            if match:
                name, version = match.groups()
            else:
                match = re.match(r"^([A-Za-z0-9_.-]+)", line)
                if not match:
                    continue
                name = match.group(1)
                version = "unspecified"

            dependencies.append({
                "name": name,
                "version": version,
                "ecosystem": "PyPI"
            })
    else:
        raise ValueError(
            "Supported files are package.json and requirements.txt."
        )

    unique = {}
    for dep in dependencies:
        unique[(dep["ecosystem"], dep["name"].lower())] = dep

    return project_name, list(unique.values())


def check_osv(dep):
    version = dep["version"]

    if version == "unspecified" or any(
        char in version for char in ["^", "~", ">", "<", "*", " "]
    ):
        return {
            "checked": False,
            "vulnerabilities": [],
            "message": "Exact version unavailable; review required."
        }

    try:
        response = requests.post(
            OSV_API,
            json={
                "package": {
                    "name": dep["name"],
                    "ecosystem": dep["ecosystem"]
                },
                "version": version
            },
            timeout=8
        )
        response.raise_for_status()

        records = response.json().get("vulns", [])
        vulnerabilities = []

        for item in records:
            vulnerabilities.append({
                "id": item.get("id", "Unknown"),
                "summary": (
                    item.get("summary")
                    or item.get("details")
                    or "No summary provided by advisory."
                )[:300],
                "references": [
                    ref.get("url")
                    for ref in item.get("references", [])[:3]
                    if ref.get("url")
                ]
            })

        return {
            "checked": True,
            "vulnerabilities": vulnerabilities,
            "message": ""
        }

    except requests.RequestException:
        return {
            "checked": False,
            "vulnerabilities": [],
            "message": "OSV API unavailable. This package is unverified."
        }


def run_analysis(project_name, dependencies):
    results = []
    vulnerable_packages = 0
    vulnerability_count = 0
    unverified_count = 0
    unpinned_count = 0

    for dep in dependencies:
        osv = check_osv(dep)
        vulnerabilities = osv["vulnerabilities"]

        if vulnerabilities:
            vulnerable_packages += 1
            vulnerability_count += len(vulnerabilities)

        if not osv["checked"]:
            unverified_count += 1

        version = dep["version"]
        is_unpinned = version == "unspecified" or any(
            char in version for char in ["^", "~", ">", "<", "*"]
        )

        if is_unpinned:
            unpinned_count += 1

        flags = []

        if vulnerabilities:
            flags.append("Known vulnerability records found")

        if is_unpinned:
            flags.append("Version is not pinned to an exact release")

        if not osv["checked"]:
            flags.append(osv["message"])

        if vulnerabilities:
            status = "Vulnerable"
        elif not osv["checked"] or is_unpinned:
            status = "Needs review"
        else:
            status = "No OSV findings"

        results.append({
            **dep,
            "status": status,
            "osv_checked": osv["checked"],
            "vulnerabilities": vulnerabilities,
            "flags": flags
        })

    # Heuristic indicator, not a formal security certification.
    score = max(
        0,
        min(
            100,
            100
            - min(65, vulnerable_packages * 20
                  + max(0, vulnerability_count - vulnerable_packages) * 5)
            - min(20, unpinned_count * 3)
        )
    )

    recommendations = []

    for dep in results:
        if dep["vulnerabilities"]:
            recommendations.append({
                "priority": "HIGH",
                "package": dep["name"],
                "action": (
                    "Review the linked advisories and upgrade to a "
                    "patched version recommended by the advisory."
                )
            })
        elif "Version is not pinned to an exact release" in dep["flags"]:
            recommendations.append({
                "priority": "MEDIUM",
                "package": dep["name"],
                "action": "Pin the resolved package version and rerun the scan."
            })
        elif not dep["osv_checked"]:
            recommendations.append({
                "priority": "CHECK",
                "package": dep["name"],
                "action": "Repeat the vulnerability check when OSV is reachable."
            })

    return {
        "project_name": project_name,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "score_description": (
            "Heuristic score based on known OSV findings and version pinning; "
            "not a formal security certification."
        ),
        "dependency_count": len(results),
        "vulnerable_packages": vulnerable_packages,
        "vulnerability_count": vulnerability_count,
        "osv_checked_count": sum(
            1 for dep in results if dep["osv_checked"]
        ),
        "unverified_count": unverified_count,
        "dependencies": results,
        "recommendations": recommendations
    }


@app.get("/")
def home():
    return jsonify({
        "name": "ROSPL Dependency Health & Risk Analyzer",
        "status": "running",
        "health_endpoint": "/api/health"
    })


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "service": "ROSPL API"})


@app.post("/api/scan")
def scan():
    payload = request.get_json(silent=True) or {}
    content = payload.get("content", "")
    filename = payload.get("filename", "package.json")

    if not isinstance(content, str) or not content.strip():
        return jsonify({"error": "Manifest content is required."}), 400

    try:
        project, dependencies = parse_manifest(filename, content)

        if not dependencies:
            return jsonify({
                "error": "No supported dependencies were found."
            }), 400

        project = payload.get("project_name") or project
        report = run_analysis(project, dependencies)

        conn = get_db()
        conn.execute(
            """INSERT INTO scans
            (project_name, scanned_at, score, dependency_count,
             vulnerable_count, result_json)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (
                report["project_name"],
                report["scanned_at"],
                report["score"],
                report["dependency_count"],
                report["vulnerable_packages"],
                json.dumps(report)
            )
        )
        conn.commit()
        conn.close()

        return jsonify(report)

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        app.logger.exception("Scan failed")
        return jsonify({"error": "Unexpected scan error. Check terminal logs."}), 500


@app.get("/api/history")
def history():
    conn = get_db()
    rows = conn.execute(
        """SELECT id, project_name, scanned_at, score,
        dependency_count, vulnerable_count
        FROM scans ORDER BY id DESC LIMIT 50"""
    ).fetchall()
    conn.close()

    return jsonify([dict(row) for row in rows])


@app.get("/api/history/<int:scan_id>")
def history_detail(scan_id):
    conn = get_db()
    row = conn.execute(
        "SELECT result_json FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    conn.close()

    if row is None:
        return jsonify({"error": "Scan not found."}), 404

    return jsonify(json.loads(row["result_json"]))


if __name__ == "__main__":
    get_db().close()
    app.run(host="127.0.0.1", port=5000, debug=False)
