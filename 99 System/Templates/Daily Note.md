---
type: daily
date: {{date:YYYY-MM-DD}}
tags:
  - daily
---

# {{date:dddd, MMMM D, YYYY}}

## Focus

- [ ] 

## Log

- {{time:HH:mm}} — 

## Notes created today

```dataview
LIST
FROM ""
WHERE file.cday = date(this.date)
  AND file.path != this.file.path
SORT file.ctime ASC
```

## End-of-day review

- What moved forward?
- What did I learn?
- What is the next action?
