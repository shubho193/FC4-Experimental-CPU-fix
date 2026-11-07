@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
cl /nologo /LD /O2 /MT /W3 /GS- fc4corefix.c /Fe:dinput8.dll /link /DEF:dinput8.def /NOLOGO
