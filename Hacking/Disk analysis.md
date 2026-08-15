 🧩 Step 1: Identify Disk Structure

Command:

mmls disk.img

Purpose:

- Shows partition layout

Output Example:

DOS Partition Table  
Offset Sector: 0  
  
Slot    Start        End          Length       Description  
00:00   0000000000   0000002047   2048         Primary Table  
00:01   0000002048   0001026047   ...          NTFS

👉 You need the **start sector** (offset)



📂 Step 2: Analyze File System

 Command:

fsstat -o <offset> disk.img

Example:

fsstat -o 2048 disk.img

Purpose:

- Shows file system details (NTFS, FAT, EXT)
- Volume info, cluster size, etc.

📁 Step 3: List Files (Like `ls`)

 Command:

fls -o <offset> disk.img

 Recursive listing:

fls -r -o 2048 disk.img

Output Example:

r/r 5:  file.txt  
d/d 6:  Documents

👉 Important:

- `r/r` = regular file
- `d/d` = directory
- Numbers = **inode**

---

🔍 Step 4: View File Contents

Command:

icat -o <offset> disk.img <inode>

Example:

icat -o 2048 disk.img 5

👉 Extracts file content even if deleted!

---

🗑️ Step 5: Recover Deleted Files

List deleted files:

fls -r -d -o 2048 disk.img

Recover:

icat -o 2048 disk.img <inode> > recovered.txt

---

📊 Step 6: Timeline Analysis

 Create body file:

fls -r -o 2048 disk.img > body.txt

Convert to timeline:

mactime -b body.txt > timeline.txt

👉 Shows:

- Modified
- Accessed
- Changed
- Created times

---

🧬 Step 7: Metadata Analysis

Command:

istat -o 2048 disk.img <inode>

Output:

- File timestamps
- Size
- Allocation status
- Owner info

---

🔎 Step 8: Find Specific Files

Search by name:

fls -r disk.img | grep "password"

 Search by inode:

ffind -o 2048 disk.img <inode>

---

💾 Step 9: Recover Entire File System

tsk_recover -o 2048 disk.img output_folder/

👉 Recovers all files (including deleted)

---

# ⚡ Important Tools Summary

|Tool|Purpose|
|---|---|
|`mmls`|Partition layout|
|`fsstat`|File system info|
|`fls`|List files|
|`icat`|Extract file|
|`istat`|File metadata|
|`ffind`|Find file by inode|
|`tsk_recover`|Bulk recovery|
|`mactime`|Timeline|

---

 🧪 Real Investigation Example

Let’s say:  
👉 You suspect a deleted password file.

Steps:

1. Find partitions:

mmls disk.img

2. List deleted files:

fls -r -d -o 2048 disk.img

3. Find suspicious file:

r/r * 45: passwords.txt

4. Extract:

icat -o 2048 disk.img 45 > passwords.txt

5. Check metadata:

istat -o 2048 disk.img 45

---

 ⚠️ Important Forensic Tips

 🔒 1. Always Use Read-Only

Never modify original evidence.

 🧾 2. Work on Copies

Use `.dd` or `.img`

 🧮 3. Note Offsets Carefully

Wrong offset = wrong data

⏱️ 4. Correlate Timeline

Use `mactime` to detect:

- Data exfiltration
- Suspicious access

🧠 5. Combine Tools

TSK + Autopsy = powerful combo

---

# 🧑‍💻 Pro Tips (Advanced)

🔹 Extract Slack Space

blkls disk.img > slack.raw

🔹 Analyze Unallocated Space

blkls -o 2048 disk.img

🔹 Keyword Search

strings disk.img | grep "password"

