---
type: map
aliases:
  - Knowledge Atlas
cssclasses:
  - dashboard
tags:
  - system/map
---

# Atlas

This is the live map of the vault. Folder maps update automatically through Waypoint; these views update automatically through Dataview.

> [!nav] Main spaces
> [[00 Inbox/00 Inbox|Inbox]] · [[01 Daily/01 Daily|Daily]] · [[02 Projects/02 Projects|Projects]] · [[03 Areas/03 Areas|Areas]] · [[Hacking/Hacking|Hacking]] · [[99 System/Second Brain Guide|System]]

## Top-level map

```dataview
TABLE WITHOUT ID key AS Space, length(rows) AS Notes, dateformat(max(rows.file.mtime), "MMM d, yyyy") AS Latest
FROM ""
FLATTEN split(file.folder, "/")[0] AS key
WHERE key != "99 System" AND key != ".trash"
GROUP BY key
SORT length(rows) DESC
```

## Tags

```dataview
TABLE WITHOUT ID tag AS Tag, length(rows) AS Notes
FROM ""
FLATTEN file.tags AS tag
WHERE tag
GROUP BY tag
SORT length(rows) DESC
LIMIT 30
```

## Orphaned notes

```dataview
TABLE WITHOUT ID file.link AS Note, file.folder AS Folder
FROM ""
WHERE length(file.inlinks) = 0 AND length(file.outlinks) = 0
  AND !startswith(file.path, "99 System")
  AND file.name != this.file.name
SORT file.mtime DESC
```
