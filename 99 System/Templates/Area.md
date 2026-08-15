---
type: area
status: active
created: {{DATE:YYYY-MM-DD}}
tags:
  - area
---

# {{VALUE}}

## Standard

What does healthy look like in this area?

## Current focus


## Projects

```dataview
LIST
FROM "02 Projects"
WHERE area = this.file.link AND status != "done"
SORT file.mtime DESC
```

## Notes
