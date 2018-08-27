# PE File Infection
Infects *only* 32bit PE files (*I'm working on a solution to make it works also with 64bit PE*)
<br/>
<br/>
## Features
●High ratio of success
<br/>
●Stealthly
<br/>
●Clean code
<br/>
### How is it works
The virus will create in **memory** a *map* of the host (PE), after that he will start to analyze it.
If he finds that the host is *already infected*, he will stop the infection.
<br/>
Will abort the infection also if he finds that the host has **ASLR**/**DEP** *enabled* and **can't** disable **one** of it, if is a **.NET** PE, if is a **DLL** PE, if the host has a **TLS** callback active, if has a **Digital Signature** and if is *packed* with [*UPX*](https://upx.github.io/).
<br/>
<br/>
After all of this checks he start to iterate all the sections in the PE, and when he find a code cave (in this context a code cave is a sequence of null bytes (0x00)) large as the **shellcode + 2 bytes** he will place the shellcode in the codecave.
<br/>
If everything is fine, he will *update* the **OEP** (*Original Entry Point*) of the host to redirect the "starting code" to the **offset** where the *shellcode was placed*.
<br/>
When the shellcode has finished, the virus will redirect the "program code" to the **real OEP** of the host, so the user will think that everything is ok.
## A little demonstration
The virus will infect the [**AES Protect**](https://www.directorandgeneral.com/aes-protect/) PE with the [WinExec_Calc_x86.asm](https://github.com/Xxshark888xX/PE-File-Infection/blob/master/src/WinExec_calc_x86.asm) shellcode, who when launched will first execute **calc.exe**
<br/>
[**GIFV Demonstration**](https://i.imgur.com/ub4d94H.gifv)
## Special thanks to
I want to say *thanks* to those people who have written *detailed* articles about the PE file structure and about PE infection technique.
<br/>
<br/>
**Matt Pietrek** for the ***super detailed*** '[Peering Inside the PE: A Tour of the Win32 Portable Executable File Format](https://msdn.microsoft.com/en-us/library/ms809762.aspx)' article.
<br/>
**KOrUPt** for the *beautiful* '[Detailed Guide To Pe Infection](http://www.rohitab.com/discuss/topic/33006-detailed-guide-to-pe-infection/)' article.
<br>
**dtm** for this *clear* PoC '[PE File Infection](https://0x00sec.org/t/pe-file-infection/401)' article
## If you can help me to fix the 64bit infection part, feel free to contact me.<br/>(*mutu.adi.marian@gmail.com*)
## License
See the [LICENSE](LICENSE) file for details
<br/><br/>
:warning: **This code was written only as a personal challenge. I don't assume any responsibility about how you will use.** :warning:
