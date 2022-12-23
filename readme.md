# MpClientTracer

## Introduction

This repository contains a test harness of [Windows Defender](https://learn.microsoft.com/en-us/windows/win32/lwef/windows-defender-bumper). It can be concatenated with the fuzzers.


```
Usage: Mpclient.exe <Scheme: file/folder> <Path>
```

> Noted: Type "file" or "folder" for your scheme (scanning type).

## Build

These files are built by Visual Studio 2019. No additional settings are required.

## MpClient.h

Microsoft provides the API document but it doesn't contain all of the stuff like enums, structures. Some structures and enums of the header file are reversed by myself. I also reversed the Callback Handler of the MsScanStart function.

Target module version: 4.18.2210.6 (2022/11/09)

## Screenshot

![](https://i.imgur.com/wJfmlCw.png)

![](https://i.imgur.com/JZ0WCqW.png)
