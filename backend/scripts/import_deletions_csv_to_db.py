#!/usr/bin/env python3
import csv, os, pymysql
CSV = os.path.join(os.path.dirname(__file__), "deletions_log.csv")
DB = dict(host="localhost", user="shieldpatch_user", password="ajaykumar@040702", db="ShieldPatch", port=3306, charset="utf8mb4")

if not os.path.exists(CSV):
    print("no csv:", CSV); raise SystemExit(1)

conn = pymysql.connect(host=DB['host'], user=DB['user'], password=DB['password'], db=DB['db'], port=DB['port'], charset='utf8mb4')
cur = conn.cursor()
with open(CSV, newline="", encoding="utf-8") as fh:
    reader = csv.DictReader(fh)
    for row in reader:
        image_id = row.get("image_id") or None
        image_tag = row.get("image_tag") or None
        removed_stdout = row.get("removed_stdout") or None
        removed_stderr = row.get("removed_stderr") or None
        removed_succeeded = int(row.get("removed_succeeded") or 0)
        host_path = row.get("host_path") or None
        note = row.get("note") or None
        sql = """
        INSERT INTO job_image_deletions (job_image_id, image_id, image_tag, container_name, job_name, user_id,
            removed_stdout, removed_stderr, removed_succeeded, host_path, note)
        VALUES (NULL, %s, %s, NULL, NULL, NULL, %s, %s, %s, %s, %s)
        """
        cur.execute(sql, (image_id, image_tag, removed_stdout, removed_stderr, removed_succeeded, host_path, note))
conn.commit()
print("import finished")
cur.close()
conn.close()