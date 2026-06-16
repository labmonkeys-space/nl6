# worldcities filter policy

This vendored simplemaps "World Cities" dataset has **Russia removed** by
project policy. Rows whose ISO country code is `RU` (iso2, column 6) / `RUS`
(iso3, column 7) are excluded, along with the `"Moscow, Russia"` fallback in
`../cities.go`.

ISO codes are matched rather than the country *name* string so the filter is
spelling-proof (and won't accidentally drop a city/admin named "Russia", e.g.
Russia, OH).

If the dataset is ever re-vendored, re-apply with a CSV-aware pass (the files
are CRLF, fully quoted, and contain embedded commas inside quoted fields, so a
naive comma split is unsafe):

```python
import csv, glob
for fp in glob.glob("[0-9]*.csv"):
    with open(fp, newline='', encoding='utf-8') as fh:
        rows = [r for r in csv.reader(fh)
                if not (len(r) > 6 and (r[5] == "RU" or r[6] == "RUS"))]
    with open(fp, "w", newline='', encoding='utf-8') as fh:
        csv.writer(fh, quoting=csv.QUOTE_ALL, lineterminator='\r\n').writerows(rows)
```
