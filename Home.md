---
type: dashboard
aliases:
  - Second Brain
cssclasses:
  - dashboard
tags:
  - system/home
---

# Second Brain

Your calm starting point. Capture first, organize later.

> [!capture] Quick capture
> Create a new note from anywhere. It automatically lands in [[00 Inbox/00 Inbox|Inbox]]. Use today's note for logs, thoughts, and decisions: [[01 Daily/01 Daily|Daily notes]].

> [!nav] Navigate
> [[Atlas|Atlas]] · [[Hacking/Hacking|Hacking]] · [[02 Projects/02 Projects|Projects]] · [[03 Areas/03 Areas|Areas]] · [[99 System/Second Brain Guide|How this works]]

## Open tasks

```tasks
not done
sort by due
sort by priority
limit 12
```

## Recently changed

```dataview
TABLE WITHOUT ID file.link AS Note, dateformat(file.mtime, "MMM d, HH:mm") AS Updated
FROM ""
WHERE file.name != this.file.name
  AND !startswith(file.path, "99 System/Templates")
SORT file.mtime DESC
LIMIT 12
```

## Inbox

```dataview
LIST
FROM "00 Inbox"
WHERE file.name != "00 Inbox"
SORT file.ctime DESC
```

## Active projects

```dataview
TABLE WITHOUT ID file.link AS Project, status AS Status, due AS Due
FROM "02 Projects"
WHERE type = "project" AND status != "done" AND file.name != "02 Projects"
SORT due ASC
```

## Notes needing connections

```dataview
LIST
FROM ""
WHERE length(file.inlinks) = 0
  AND !contains(file.tags, "#system/home")
  AND !startswith(file.path, "99 System")
  AND file.name != this.file.name
SORT file.mtime DESC
LIMIT 10
```
