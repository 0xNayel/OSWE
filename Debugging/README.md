# Debugging

## .NET 
We will use the freely-available dnSpy decompiler and debugger for this purpose, as it provides all we need. Specifically, dnSpy uses the ILSpy decompiler engine to extract the source code from a .NET compiled module.

### Manipulation of Assembly Attributes for Debugging
Debugging .NET web applications is often complicated by runtime optimizations that prevent setting breakpoints or inspecting local variables. This is because most assemblies are compiled in Release mode, with attributes like:

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
To improve the debugging experience, this can be changed to:

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default | DebuggableAttribute.DebuggingModes.DisableOptimizations | DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints | DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Via right clicking the module name and then choosing `Edit Assembly Attributes (C#)` and click `Compile`

This modification can be done using dnSpy. It's crucial to edit the correct assembly — in this case, `DotNetNuke.dll` located at:

```
C:\inetpub\wwwroot\dotnetnuke\bin\DotNetNuke.dll
```
However, IIS loads assemblies from a temporary location:

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\dotnetnuke\
```
It's important to note that once the IIS worker process starts, it does not load assemblies directly from the DotNetNuke directory under the inetpub path. Instead, it copies the necessary modules to a temporary directory and loads them from there. To ensure IIS loads the edited module, simply restart the IIS service.
```
C:\Inetpub\wwwroot\dotnetnuke\bin> iisreset /noforce
```

## Remote Debugging 
Some debuggers also support debugging a process running on a remote system. This is known as *remote debugging*.

Remote debugging allows us to debug a process running on a different system as long as we have access to the source code and the debugger port on the remote system.

### Java

#### `lunch.json` File for Remote Debugging

Example `lunch.json` file should look like this:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "type": "java",
            "name": "Attach to Remote Program",
            "request": "attach",
            "hostName": "127.0.0.1", // the host name or IP address
            "port": 9898 // debugging port for the remote host
        },
        {
            "type": "java",
            "name": "Launch Current File",
            "request": "launch",
            "mainClass": "${file}"
        },
        {
            "type": "java",
            "name": "Launch NumberGameApplication",
            "request": "launch",
            "mainClass": "com.offsec.awae.NumberGameApplication",
            "projectName": "NumberGame"
        }
    ]
}
```

#### Visual Studio Code Extensions
- **Language Support for Java(TM) by Red Hat:** https://marketplace.visualstudio.com/items?itemName=redhat.java
- **Microsoft Debugger for Java:** https://marketplace.visualstudio.com/items?itemName=vscjava.vscode-java-debug


### Python
